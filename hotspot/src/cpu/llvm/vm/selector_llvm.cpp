#include "opto/cfgnode.hpp"
#include "opto/rootnode.hpp"
#include "adfiles/ad_llvm.hpp"
#include "code_gen/node_bw_iterator.hpp"
#include "code_gen/scopeDescriptor.hpp"

#include "selector_llvm.hpp"

Selector::Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name) :
  Phase(Phase::BlockLayout), 
  C(comp), _ctx(ctx), _builder(ctx), _mod(mod), 
  _blocks(comp->cfg()->number_of_blocks()), _relocator(this), _scope_descriptor(this),
  _pointer_size(mod->getDataLayout().getPointerSize() * 8),
  _monitors_num(count_monitors()), _max_stack(count_max_stack()), _name(name),
  _is_fast_compression(Universe::narrow_oop_base() == NULL && Universe::narrow_oop_shift() == 0) {
  create_func();
  prolog();
  select();
  complete_phi_nodes();
}

void Selector::prolog() {
  llvm::Type* retType = llvm::PointerType::getUnqual(llvm::Type::getInt8PtrTy(ctx()));
  std::vector<llvm::Type*> paramTypes { type(T_INT) };
  std::vector<llvm::Value*> args { builder().getInt32(ThreadLocalStorage::thread_index()) };                                                                                            
  _thread = call_external((void*)os::thread_local_storage_at, retType, args);
  _thread = builder().CreatePointerCast(_thread, type(T_ADDRESS));
  uint slots = OptoReg::reg2stack(C->matcher()->_old_SP);
  llvm::AllocaInst* alloc = builder().CreateAlloca(type(T_BYTE), builder().getInt32(slots * BytesPerInt + max_stack() * wordSize + monitors_num() * monitor_size()));
  _SP = builder().CreatePointerCast(alloc, type(T_ADDRESS));
  uint64_t alloc_size = (*alloc->getAllocationSizeInBits(mod()->getDataLayout()) >> 3);
  _frame_size = alloc_size;
  _last_Java_fp = gep(thread(), in_bytes(JavaThread::last_Java_fp_offset()));
  _FP = call_intrinsic("llvm.frameaddress.p0i8", llvm::Type::getInt8PtrTy(ctx()), { builder().getInt32(0) });
  store(_FP, _last_Java_fp);

  Block* block = C->cfg()->get_root_block();
  builder().CreateBr(basic_block(block));
}

llvm::Value* Selector::tlab_top() {
  if (!_tlab_top) {
    llvm::Value* tto = builder().getInt32(in_bytes(JavaThread::tlab_top_offset()));
    _tlab_top = gep(thread(), tto);
  }
  return _tlab_top;
}

llvm::Value* Selector::tlab_end() {
  if (!_tlab_end) {
    llvm::Value* teo = builder().getInt32(in_bytes(JavaThread::tlab_end_offset()));
    _tlab_end = gep(thread(), teo);
  }
  return _tlab_end;
}

llvm::Value* Selector::null() {
  if (!_null) {
    _null = builder().getInt32(0);
  }
  return _null;
}

llvm::Value* Selector::gep(llvm::Value* base, int offset) {
  return gep(base, builder().getInt64(offset));
}

llvm::Value* Selector::gep(llvm::Value* base, llvm::Value* offset) {
  llvm::Type* ty = base->getType();
  base = builder().CreatePointerCast(base, llvm::Type::getInt8PtrTy(ctx()));
  base = builder().CreateGEP(base, offset);
  return builder().CreatePointerCast(base, ty);
}

llvm::Type* Selector::type(BasicType ty) const {
  switch (ty) {
    case T_BYTE: return llvm::Type::getInt8Ty(_ctx);
    case T_SHORT: return llvm::Type::getInt16Ty(_ctx);
    case T_INT: 
    case T_NARROWOOP:
    case T_NARROWKLASS: return llvm::Type::getInt32Ty(_ctx);
    case T_LONG: return llvm::Type::getInt64Ty(_ctx);
    case T_FLOAT: return llvm::Type::getFloatTy(_ctx);
    case T_DOUBLE: return llvm::Type::getDoubleTy(_ctx);
    case T_BOOLEAN: return llvm::Type::getInt1Ty(_ctx);
    case T_CHAR: return llvm::Type::getInt32Ty(_ctx);
    case T_VOID: return llvm::Type::getVoidTy(_ctx);
    case T_OBJECT:
    case T_METADATA:
    case T_ADDRESS: return llvm::PointerType::getUnqual(llvm::Type::getInt8PtrTy(_ctx));
    default: 
      assert(false, "unable to convert type");
      Unimplemented();
  }
}

void Selector::create_func() {
  llvm::Type *retType = type(C->tf()->return_type());
  const TypeTuple* domain = C->tf()->domain();
  std::vector<llvm::Type*> paramTypes;

  unsigned nf_cnt = 0;
  for (uint i = TypeFunc::Parms; i < domain->cnt(); ++i) {
    BasicType btype = domain->field_at(i)->basic_type();
    if (btype != T_VOID) {
      if (btype != T_FLOAT && btype != T_DOUBLE && nf_cnt < NF_REGS) {
        nf_cnt++;
        _nf_pos.push_back(i);
      }
      llvm::Type* ty = type(btype);
      if (nf_cnt == NF_REGS) {
        paramTypes.insert(paramTypes.begin(), ty);
        nf_cnt++;
      } else {
        paramTypes.push_back(ty);
      }
    }
  }
  if (nf_cnt != 0 && nf_cnt < 6) {
    paramTypes.insert(paramTypes.begin(), type(T_LONG));
  }

  llvm::FunctionType *ftype = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage;
  _func = llvm::Function::Create(ftype, linkage, 0, _name, _mod);
  func()->setGC("statepoint-example");
  create_blocks();
}

void Selector::callconv_adjust(std::vector<llvm::Value*>& args) {
  unsigned nf_cnt = 0;
  for (auto i = args.begin(); i != args.end(); ++i) {
    if ((*i)->getType()->isFloatingPointTy()) continue;
    nf_cnt++;
    if (nf_cnt == NF_REGS) {
      llvm::Value* tmp = *i;
      args.erase(i);
      args.insert(args.begin(), tmp);
      return;
    }
  }
  if (nf_cnt != 0) {
    args.insert(args.begin(), builder().getInt64(0));
  }
}

int Selector::param_to_arg(int param_num) {
  int arg_num = (_nf_pos.size() > 0 && _nf_pos.size() < NF_REGS) ? 1 : 0;
  auto it = std::find(_nf_pos.begin(), _nf_pos.end(), param_num);
  if (it != _nf_pos.end()) {
    if (_nf_pos.size() == NF_REGS && it + 1 == _nf_pos.end()) {
       arg_num = *_nf_pos.begin(); 
    }
    else arg_num += *it;
  } else {
    const TypeTuple* domain = C->tf()->domain();
    for (uint i = TypeFunc::Parms; i < param_num; ++i) {
      const Type* at = domain->field_at(i);
      if (at->base() == Type::Half) continue;
      arg_num++;
    }
  }
  return arg_num - TypeFunc::Parms;
}

void Selector::create_blocks() {
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(ctx(), "B0", func());
  builder().SetInsertPoint(entry_block);
  std::string b_str = "B";
  for (size_t i = 0; i < C->cfg()->number_of_blocks(); ++i) {
    _blocks.append(llvm::BasicBlock::Create(ctx(), b_str + std::to_string(i + 1), func()));
  }
}

void Selector::select() {
  for (size_t i = 0; i < C->unique(); ++i) {
    _cache.push_back(std::make_unique<CacheEntry>());
  }
  select_root_block();
  for (size_t i = 1; i < _blocks.length(); ++i) {
    select_block(C->cfg()->get_block(i));
  }
}

void Selector::select_block(Block* block) {
  _block = block;
  builder().SetInsertPoint(basic_block(_block));
    for (uint i = 0; i < _block->number_of_nodes(); ++i) {
      Node* node = _block->get_node(i);
      select_node(node);
    }
  }

llvm::Value* Selector::select_node(Node* node) {
  CacheEntry* entry = _cache[node->_idx].get();
  if (!entry->hit) {
    entry->val = node->select(this);
    entry->hit = true;
  }
  return entry->val;

}

void Selector::select_root_block() {
  RootNode* node = C->cfg()->get_root_node();
  Node* start_node;
  for (uint i = 0; i < node->outcnt(); ++i) {
    if (node->raw_out(i)->is_Start()) {
      start_node = node->raw_out(i);
      break;
    }
  }
  Block* block = C->cfg()->get_block_for_node(start_node)->non_connector();
  builder().SetInsertPoint(basic_block(C->cfg()->get_root_block()));
  builder().CreateBr(basic_block(block));
}

llvm::Value* Selector::select_address(MachNode *mem_node) {
  int op_index;
  return select_address(mem_node, op_index);
}

llvm::Value* Selector::select_address(MachNode *mem_node, int& op_index) {
  const MachOper* mop = mem_node->memory_operand();
  op_index = MemNode::Address;
  llvm::Value *base, *offset;
  switch (mop->opcode()) {
    case INDIRECT: {
      Node* addr_node = mem_node->in(op_index++);
      assert(addr_node != NULL, "check");
      uint addr_rule = addr_node->is_Mach() ? addr_node->as_Mach()->rule() : _last_Mach_Node;
      if (addr_node->is_Mach() && (addr_node->as_Mach()->ideal_Opcode() == Op_AddP)) {
        MachNode* mach_addr = addr_node->as_Mach();
        Node* base_node = mach_addr->in(2);
        if (base_node->is_Mach() && base_node->as_Mach()->ideal_Opcode() == Op_ConP) {
          offset = select_oper(base_node->as_Mach()->_opnds[1]);
          base = mach_addr->rule() == addP_rReg_rule
              ? select_node(mach_addr->in(3))
              : select_oper(mach_addr->_opnds[2]);
        } else {
          base = select_node(base_node);
          offset = mach_addr->rule() == addP_rReg_rule
              ? select_node(mach_addr->in(3))
              : select_oper(mach_addr->_opnds[2]);
        }
      } else if (addr_node->is_Mach() && (addr_node->as_Mach()->ideal_Opcode() == Op_ConP)) {
        return select_oper(addr_node->as_Mach()->_opnds[1]);
        base = llvm::Constant::getNullValue(llvm::PointerType::getUnqual(offset->getType()));
      } else {
        return select_node(addr_node); 
      }
      return gep(base, offset);
    }
    case INDOFFSET: {
      Node* node = mem_node->in(op_index++);
      base = select_node(node);
      return gep(base, mop->constant_disp());
    }
    default: ShouldNotReachHere();
  }
}

llvm::Value* Selector::select_const(Node* n) {
  BasicType bt = n->as_Type()->type()->basic_type();
  switch (bt) {
    case T_ADDRESS: 
    case T_OBJECT: return get_ptr(n->get_ptr(), type(T_ADDRESS));
    case T_VOID: return null();
    default: ShouldNotReachHere();
  }
}

llvm::Value* Selector::select_oper(MachOper *oper) {
  const Type* ty = oper->type();
  BasicType bt = ty->basic_type();
  switch (bt) {
  case T_INT: return builder().getInt32(oper->constant());
  case T_LONG: return builder().getInt64(oper->constantL());
  case T_FLOAT: return llvm::ConstantFP::get(
    llvm::Type::getFloatTy(_ctx), oper->constantF());
  case T_DOUBLE: return llvm::ConstantFP::get(
    llvm::Type::getDoubleTy(_ctx), oper->constantD());
  case T_ARRAY:
  case T_OBJECT: {
    assert(ty->isa_narrowoop() == NULL, "check");
    return get_ptr(*(oop*)ty->is_oopptr()->const_oop()->constant_encoding(), type(T_OBJECT));
  }
  case T_METADATA: {
    if (ty->base() == Type::KlassPtr) {
      assert(ty->is_klassptr()->klass()->is_loaded(), "klass not loaded");
      return get_ptr(ty->is_klassptr()->klass()->constant_encoding(), type(T_METADATA));
    } else {
      return get_ptr(ty->is_metadataptr()->metadata(), type(T_METADATA));
    }
  }
  case T_NARROWOOP: return llvm::ConstantInt::get(type(T_NARROWOOP), ty->is_narrowoop()->get_con());
  case T_NARROWKLASS: {
    uintptr_t narrow_klass = ty->is_narrowklass()->get_con();
    narrow_klass >>= Universe::narrow_klass_shift();
    return llvm::ConstantInt::get(type(T_NARROWKLASS), narrow_klass);
  }
  case T_ADDRESS: {
    if (oper->constant() == NULL) return llvm::Constant::getNullValue(type(T_ADDRESS));
    return get_ptr(oper->constant(), type(T_ADDRESS));
  }
  case T_VOID: return NULL;
  default:
    tty->print_cr("BasicType %d", bt);
    ShouldNotReachHere(); return NULL;
  }
}

llvm::Value* Selector::select_node_or_const(Node* node) {
  if (node->is_Mach()) {
    int opcode = node->as_Mach()->ideal_Opcode();
    if (Op_Con <= opcode && opcode <= Op_ConP) {
      return select_oper(node->as_Mach()->_opnds[1]);
    }
  }
  if (node->flags() & Node::Flag_is_Con) {
    return select_const(node);
  }
  return select_node(node);
}

llvm::Value* Selector::get_ptr(const void* ptr, llvm::Type* ty) {
  return get_ptr((intptr_t)ptr, ty);
}

llvm::Value* Selector::get_ptr(intptr_t ptr, llvm::Type* ty) {
  llvm::IntegerType* intTy = llvm::Type::getIntNTy(ctx(), pointer_size());
  return builder().CreateIntToPtr(llvm::ConstantInt::get(intTy, ptr), ty);
}

llvm::Value* Selector::select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt) {
  assert(cmp->outcnt() == 1, "check");

  MachNode* m = cmp->unique_out()->as_Mach();
  int ccode = m->_opnds[1]->ccode();

  assert(!is_and || !flt, "try to and float operands");

  if (flt) {
    switch (ccode) {
    case 0x0: return builder().CreateFCmpUEQ(a, b); // eq
    case 0x1: return builder().CreateFCmpUNE(a, b); // ne
    case 0x2: return builder().CreateFCmpULT(a, b); // lt
    case 0x3: return builder().CreateFCmpULE(a, b); // le
    case 0x4: return builder().CreateFCmpUGT(a, b); // gt
    case 0x5: return builder().CreateFCmpUGE(a, b); // ge
    default: ShouldNotReachHere();
    }
  } else {
    if (is_and) {
      llvm::Value* a_and_b = builder().CreateAnd(a, b);
      llvm::Value* zero = llvm::ConstantInt::get(a->getType(), 0);
      switch (ccode) {
      case 0x0: return builder().CreateICmpEQ(a_and_b, zero); // eq
      case 0x1: return builder().CreateICmpNE(a_and_b, zero); // ne
      case 0x2: return builder().CreateICmpSLT(a_and_b, zero); // lt
      case 0x3: return builder().CreateICmpSLE(a_and_b, zero); // le
      case 0x4: return builder().CreateICmpSGT(a_and_b, zero); // gt
      case 0x5: return builder().CreateICmpSGE(a_and_b, zero); // ge
      default: ShouldNotReachHere();
      }
    } else {
      switch (ccode) {
      case 0x0: return builder().CreateICmpEQ(a, b); // eq
      case 0x1: return builder().CreateICmpNE(a, b); // ne
      case 0x2: return builder().CreateICmpSLT(a, b); // lt
      case 0x3: return builder().CreateICmpSLE(a, b); // le
      case 0x4: return builder().CreateICmpSGT(a, b); // gt
      case 0x5: return builder().CreateICmpSGE(a, b); // ge
      case 0x6: return builder().CreateICmpULT(a, b); // ult
      case 0x7: return builder().CreateICmpULE(a, b); // ule
      case 0x8: return builder().CreateICmpUGT(a, b); // ugt
      case 0x9: return builder().CreateICmpUGE(a, b); // uge
      ///TODO: of & nof
      default: ShouldNotReachHere();
      }
    }
  }
  return NULL;
}

void Selector::select_if(llvm::Value *pred, Node* node) {
  Node* if_node = node->raw_out(0);
  size_t true_idx = 0, false_idx = 1;
  if (if_node->Opcode() == Op_IfFalse) {
    std::swap(true_idx, false_idx);
  } else {
    assert(if_node->Opcode() == Op_IfTrue, "illegal Node type");
  }
  Block* target_block = C->cfg()->get_block_for_node(node->raw_out(true_idx)->raw_out(0));
  Block* fallthr_block = C->cfg()->get_block_for_node(node->raw_out(false_idx)->raw_out(0));
  llvm::BasicBlock* target_bb = basic_block(target_block);
  llvm::BasicBlock* fallthr_bb = basic_block(fallthr_block);
  
  // MachIfNode* if_node = node->as_MachIf();
  // float prob = if_node->_prob;
  // llvm::MDBuilder MDHelper(CGM.getLLVMContext());
  // llvm::MDNode *Weights = MDHelper.createBranchWeights(prob, 1 - prob);
  builder().CreateCondBr(pred, target_bb, fallthr_bb/*, Weights*/);
}

void Selector::replace_return_address(llvm::Value* new_addr) {
  llvm::Value* addr = call_intrinsic("llvm.addressofreturnaddress.p0i8", llvm::Type::getInt8PtrTy(ctx()));
  store(new_addr, addr);
}

std::vector<llvm::Type*> Selector::types(const std::vector<llvm::Value*>& v) const {
  std::vector<llvm::Type*> ret;
  ret.reserve(v.size());
  for (llvm::Value* val : v) {
    ret.push_back(val->getType());
  }
  return ret;
}

llvm::CallInst* Selector::call_intrinsic(const char* name, llvm::Type* retType) {
  std::vector<llvm::Value*> args;
  return call_intrinsic(name, retType, args);
}

llvm::CallInst* Selector::call_intrinsic(const char* name, llvm::Type* retType, const std::vector<llvm::Value *>& args) {
  std::vector<llvm::Type*> paramTypes = types(args);
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Function* f = llvm::cast<llvm::Function>(mod()->getOrInsertFunction(name, funcTy).getCallee());
  return builder().CreateCall(f, args);
}

llvm::CallInst* Selector::call_external(const void* func, llvm::Type* retType) {
  std::vector<llvm::Value*> args;
  return call_external(func, retType, args);
}

llvm::CallInst* Selector::call_external(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args) {
  std::vector<llvm::Type*> paramTypes = types(args);
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Value* ptr = get_ptr(func, llvm::PointerType::getUnqual(funcTy));
  llvm::FunctionCallee f(funcTy, ptr);
  return builder().CreateCall(f, args);
}

llvm::Value* Selector::create_statepoint(MachCallNode* node, llvm::FunctionType* funcTy, const std::vector<llvm::Value*>& args) {
  MachSafePointNode* sfn = static_cast<MachSafePointNode*>(node);
  DebugInfo& di = debug_info()[sfn] = scope_descriptor()->init_debug_info(sfn);
  _sfns.push_back(sfn);

  const void *func = node->entry_point();
  std::vector<llvm::Value*> sp_args { 
  builder().getInt64(di.sfn_id), builder().getInt32(0),
  get_ptr(func, llvm::PointerType::getUnqual(funcTy)), 
  builder().getInt32(args.size()), builder().getInt32(0) };
  sp_args.insert(sp_args.end(), args.begin(), args.end());
  sp_args.push_back(builder().getInt64(0));
  sp_args.push_back(builder().getInt64(0));

  llvm::Intrinsic::ID id = llvm::Function::lookupIntrinsicID("llvm.experimental.gc.statepoint");
  std::string name = llvm::Intrinsic::getName(id, { llvm::PointerType::getUnqual(funcTy) });

  std::vector<llvm::Type*> paramTypes = types(sp_args);
  paramTypes.resize(5);
  funcTy = llvm::FunctionType::get(llvm::Type::getTokenTy(ctx()), paramTypes, true);
  llvm::Function* f = llvm::cast<llvm::Function>(mod()->getOrInsertFunction(name.c_str(), funcTy).getCallee());
  llvm::Value* token = builder().CreateCall(f, sp_args, scope_descriptor()->statepoint_scope(sfn));
  return token;
}

llvm::CallInst* Selector::call(MachCallNode* node, llvm::Type* retType, std::vector<llvm::Value*>& args) {
  std::vector<llvm::Type*> paramTypes = types(args);
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Value* token = create_statepoint(node, funcTy, args);
  if (retType->isVoidTy()) return NULL;

  llvm::Intrinsic::ID id = llvm::Function::lookupIntrinsicID("llvm.experimental.gc.result");
  std::string name = llvm::Intrinsic::getName(id, { retType });
  return call_intrinsic(name.c_str(), retType, { token });
  }

llvm::Value* Selector::load(llvm::Value* addr, BasicType ty) {
  return load(addr, type(ty));
}

llvm::Value* Selector::load(llvm::Value* addr, llvm::Type* ty) {
  addr = builder().CreatePointerCast(addr, llvm::PointerType::getUnqual(ty));
  return builder().CreateLoad(addr);
}

void Selector::store(llvm::Value* value, llvm::Value* addr) {
  addr = builder().CreatePointerCast(addr, llvm::PointerType::getUnqual(value->getType()));
  builder().CreateStore(value, addr);
}

llvm::AtomicCmpXchgInst* Selector::cmpxchg(llvm::Value* addr, llvm::Value* cmp, llvm::Value* val) {
  const llvm::AtomicOrdering succ_ord = llvm::AtomicOrdering::SequentiallyConsistent,
    fail_ord = llvm::AtomicCmpXchgInst::getStrongestFailureOrdering(succ_ord);
  if (cmp->getType()->isPointerTy()) {
    if (val->getType()->isPointerTy()) {
      cmp = builder().CreatePointerCast(cmp, val->getType());
    } else {
      cmp = builder().CreatePtrToInt(cmp, val->getType());
    }
  } else if (val->getType()->isPointerTy()) {
    cmp = builder().CreateIntToPtr(cmp, val->getType());
  }
  addr = builder().CreatePointerCast(addr, llvm::PointerType::getUnqual(cmp->getType()));
  return builder().CreateAtomicCmpXchg(addr, cmp, val, succ_ord, fail_ord);
}

void Selector::mark_mptr(llvm::Value* oop) {
  OopInfo& oop_info = _oop_info[oop];
  assert(!oop_info.isNarrowPtr(), "check");
  oop_info.markManagedPtr(); 
}

void Selector::mark_nptr(llvm::Value* oop) {
  assert(UseCompressedOops, "only with enabled UseCompressedOops");
  if (is_fast_compression()) {
    mark_mptr(oop);
  }
  else {
    OopInfo& oop_info = _oop_info[oop];
    assert(!oop_info.isManagedPtr(), "check");
    oop_info.markNarrowPtr();
  }
}

llvm::Value* Selector::decodeKlass_not_null(llvm::Value* narrow_klass) {
  if (!Universe::narrow_klass_shift() && !Universe::narrow_klass_base()) {
     return narrow_klass; 
  }
  narrow_klass = builder().CreateIntCast(narrow_klass, llvm::Type::getIntNTy(ctx(), pointer_size()), false);
  if (Universe::narrow_klass_shift() != 0) {
    llvm::Value* shift = llvm::ConstantInt::get(narrow_klass->getType(), Universe::narrow_klass_shift());
    narrow_klass = builder().CreateShl(narrow_klass, shift);
  }
  if (Universe::narrow_klass_base() != NULL) {
    llvm::Value* base = get_ptr(Universe::narrow_klass_base(), type(T_METADATA));
    narrow_klass = gep(base, narrow_klass);
  }
  return builder().CreateIntToPtr(narrow_klass, type(T_METADATA));
}

llvm::Value* Selector::decode_heap_oop(llvm::Value* narrow_oop, bool not_null) {
#ifdef ASSERT
  assert (UseCompressedOops, "should be compressed");
  assert (Universe::heap() != NULL, "java heap should be initialized");

  // verify heap base
#endif

  OopInfo& narrow_oop_info = oop_info(narrow_oop);
  if (is_fast_compression()) {
    // 32-bit oops
    assert(narrow_oop_info.isManagedPtr(), "check managed oops flag");
    return narrow_oop;
  } else {
    assert(narrow_oop_info.isNarrowPtr(), "check narrow oops flag");
    // assert(narrow_oop_info.data_type == OopInfo::DATA_U32, "check narrow oop size");
    llvm::Value* oop;

    assert(Universe::narrow_oop_shift() != 0, "unsupported compression mode");
    narrow_oop = builder().CreateIntCast(narrow_oop, llvm::Type::getIntNTy(ctx(), pointer_size()), false);
    llvm::Value* narrow_oop_shift_ = llvm::ConstantInt::get(narrow_oop->getType(), Universe::narrow_oop_shift());
    llvm::Value* narrow_oop_base_ = get_ptr(Universe::narrow_klass_base(), type(T_OBJECT));
    if (Universe::narrow_oop_base() == NULL) {
      // Zero-based compressed oops
      oop = builder().CreateShl(narrow_oop, narrow_oop_shift_);
      oop = builder().CreateIntToPtr(oop, type(T_OBJECT));
    } else {
      // Heap-based compressed oops
      if (not_null) {
        oop = builder().CreateShl(narrow_oop, narrow_oop_shift_);
        oop = gep(narrow_oop_base_, oop);
      } else {
        llvm::Value* pred = builder().CreateICmpEQ(narrow_oop, llvm::ConstantInt::getNullValue(narrow_oop->getType()));
        oop = builder().CreateShl(narrow_oop, narrow_oop_shift_);
        oop = gep(narrow_oop_base_, oop);
      }
    }

    DEBUG_ONLY( if (VerifyOops) {/*verify_oop*/} );

    mark_mptr(oop);
    return oop;
  }
}

void Selector::map_phi_nodes(PhiNode* opto_phi, llvm::PHINode* llvm_phi) {
  _phiNodeMap.push_back(std::make_pair(opto_phi, llvm_phi));
}

void Selector::complete_phi_nodes() {
  for (auto &p : _phiNodeMap) {
    PhiNode* phi_node = p.first;
    llvm::PHINode* phi_inst = p.second;
    Block* phi_block = C->cfg()->get_block_for_node(phi_node);
    RegionNode* phi_region = phi_node->region();
    assert(phi_block->head() == (Node*)phi_region, "check phi block");
    for (uint i = PhiNode::Input; i < phi_node->req(); ++i) {
      Node* case_val = phi_node->in(i);
      Block* case_block = C->cfg()->get_block_for_node(phi_block->pred(i));
      complete_phi_node(case_block, case_val, phi_inst);
    }
  }
}

void Selector::complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst) {
  if (case_block->is_connector()) {
    for (uint i=1; i< case_block->num_preds(); i++) {
      Block *p = C->cfg()->get_block_for_node(case_block->pred(i));
      complete_phi_node(p, case_val, phi_inst);
    }
    return;
  }

  llvm::BasicBlock* case_bb = basic_block(case_block);
  llvm::Value* phi_case = select_node(case_val);
  llvm::Type* phiTy = phi_inst->getType();
  if (phi_case->getType()->isIntegerTy() && phiTy->isPointerTy()) {
    phi_case = builder().CreateIntToPtr(phi_case, phiTy);
    }
  else if (phi_case->getType() != phiTy) {
    llvm::BasicBlock* bb = basic_block(C->cfg()->get_block_for_node(case_val));
    phi_case = llvm::CastInst::CreatePointerCast(phi_case, phiTy);
    llvm::cast<llvm::Instruction>(phi_case)->insertBefore(bb->getTerminator());
  }
  phi_inst->addIncoming(phi_case, case_bb);
}

unsigned Selector::count_monitors() const {
  ResourceMark rm;
  VectorSet   visited(C->node_arena());
  Node_List   stack;
  Node* n = NULL;
  Node_BW_Iterator iter(C->root(), visited, stack, *(C->cfg()));

  unsigned num = 0;
  while (n = iter.next()) {
    if (n->is_MachSafePoint() == false) continue;
    MachSafePointNode* sf = (MachSafePointNode*)n;
    JVMState* jvms = sf->jvms();
    if (jvms == NULL) continue;
    num = MAX(num, jvms->monitor_depth());
  }
  return num;
}

unsigned Selector::count_max_stack() const {
  ResourceMark rm;
  VectorSet   visited(C->node_arena());
  Node_List   stack;
  Node* n = NULL;
  Node_BW_Iterator iter(C->root(), visited, stack, *(C->cfg()));

  int num = 0;
  while (n = iter.next()) {
    if (n->is_MachCallJava() == false) continue;
    MachCallJavaNode* jcall = (MachCallJavaNode*)n;
    if (jcall->_method == NULL) continue;
    int param_cnt = jcall->tf()->domain()->cnt() - TypeFunc::Parms;
    num = MAX(num, param_cnt);
  }
  return num;
}

int32_t Selector::mon_offset(int32_t index) {
  int32_t offset_monitor = 0;
  assert(index >= 0 && index < monitors_num(), "invalid monitor index");
  return offset_monitor + (-1 - index) * monitor_size();
}

int32_t Selector::mon_obj_offset(int32_t index) {
  int32_t object_offset = BasicObjectLock::obj_offset_in_bytes();
  return mon_offset(index) + object_offset;
}

int32_t Selector::mon_header_offset(int32_t index) {
  int32_t lock_offset = BasicObjectLock::lock_offset_in_bytes();
  int32_t header_offset = BasicLock::displaced_header_offset_in_bytes();
  return mon_offset(index) + lock_offset + header_offset;
}

void Selector::epilog() {
  llvm::Value* last_fp = load(FP(), type(T_ADDRESS));
  store(last_fp, _last_Java_fp);
}