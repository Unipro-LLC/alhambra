#include "selector_llvm.hpp"

#include <unordered_set>

#include "opto/cfgnode.hpp"
#include "opto/rootnode.hpp"
#include "opto/addnode.hpp"
#include "opto/locknode.hpp"

#include "code_gen/llvmCodeGen.hpp"
#include "adfiles/ad_llvm.hpp"

Selector::Selector(LlvmCodeGen* code_gen, const char* name) :
  Phase(Phase::BlockLayout),
  _cg(code_gen), _ctx(code_gen->ctx()), _mod(code_gen->mod()), _builder(ctx()),
  _pointer_size(mod()->getDataLayout().getPointerSize() * 8), _name(name),
  _is_fast_compression(Universe::narrow_oop_base() == NULL && Universe::narrow_oop_shift() == 0) {}

void Selector::run() {
  create_func();
  prolog();
  select();
  complete_phi_nodes();
  locs_for_narrow_oops();
  epilog();
}

void Selector::prolog() {
  LlvmStack& stack = cg()->stack();
  llvm::Value* FP = builder().CreateIntrinsic(llvm::Intrinsic::frameaddress, { type(T_ADDRESS) }, { null(T_INT) });
  stack.set_FP(FP);
  size_t alloc_size = stack.calc_alloc();
  builder().CreateAlloca(type(T_BYTE), builder().getInt32(alloc_size));
  llvm::Value* ret_addr = builder().CreateIntrinsic(llvm::Intrinsic::returnaddress, {}, builder().getInt32(0));
  llvm::Value* ret_addr_slot = gep(FP, stack.ret_addr_offset());
  store(ret_addr, ret_addr_slot);

  Block* block = C->cfg()->get_root_block();
  builder().CreateBr(basic_block(block));
}

llvm::Value* Selector::thread() {
  llvm::Value* thread = builder().CreateIntrinsic(llvm::Intrinsic::alhm_get_global_var_thread, type(T_LONG), {});
  return builder().CreateIntToPtr(thread, type(T_ADDRESS));
}

void Selector::select() {
  for (size_t i = 0; i < C->unique(); ++i) {
    _cache.push_back(std::make_unique<CacheEntry>());
  }

  _block = C->cfg()->get_root_block();
  builder().SetInsertPoint(basic_block());
  builder().CreateBr(basic_block(block()->non_connector_successor(0)));

  for (size_t i = 1; i < _blocks.size(); ++i) {
    _block = C->cfg()->get_block(i);
    builder().SetInsertPoint(basic_block());
    for (size_t j = 1; j < block()->number_of_nodes(); ++j) { // skip 0th node: Start or Region
      Node* node = block()->get_node(j);
      select_node(node);
    }
  }
}

llvm::Value* Selector::tlab_top() {
  llvm::Value* tto = builder().getInt32(in_bytes(JavaThread::tlab_top_offset()));
  return gep(thread(), tto);
}

llvm::Value* Selector::tlab_end() {
  llvm::Value* teo = builder().getInt32(in_bytes(JavaThread::tlab_end_offset()));
  return gep(thread(), teo);
}

llvm::Value* Selector::gep(llvm::Value* base, int offset) {
  return gep(base, builder().getInt64(offset));
}

llvm::Value* Selector::gep(llvm::Value* base, llvm::Value* offset) {
  llvm::PointerType* ty = llvm::cast<llvm::PointerType>(base->getType());
  base = builder().CreatePointerCast(base, llvm::Type::getInt8PtrTy(ctx(), ty->getAddressSpace()));
  base = builder().CreateGEP(base, offset);
  return builder().CreatePointerCast(base, ty);
}

llvm::Type* Selector::type(BasicType ty) const {
  switch (ty) {
    case T_BYTE: return llvm::Type::getInt8Ty(_ctx);
    case T_SHORT:
    case T_CHAR: return llvm::Type::getInt16Ty(_ctx);
    case T_INT: 
    case T_NARROWOOP:
    case T_NARROWKLASS: return llvm::Type::getInt32Ty(_ctx);
    case T_LONG: return llvm::Type::getInt64Ty(_ctx);
    case T_FLOAT: return llvm::Type::getFloatTy(_ctx);
    case T_DOUBLE: return llvm::Type::getDoubleTy(_ctx);
    case T_BOOLEAN: return llvm::Type::getInt1Ty(_ctx);
    case T_VOID: return llvm::Type::getVoidTy(_ctx);
    case T_OBJECT: return llvm::Type::getInt8PtrTy(_ctx, 1);
    case T_METADATA:
    case T_ADDRESS: return llvm::Type::getInt8PtrTy(_ctx);
    default: 
      assert(false, "unable to convert type");
      Unimplemented();
  }
}

void Selector::create_func() {
  llvm::Type* retType = type(C->tf()->return_type());
  const TypeTuple* domain = C->tf()->domain();
  std::vector<llvm::Type*> paramTypes;

  unsigned nf_cnt = 0;
  _param_to_arg.reserve(domain->cnt() - TypeFunc::Parms);
  for (uint i = TypeFunc::Parms; i < domain->cnt(); ++i) {
    BasicType btype = domain->field_at(i)->basic_type();
    if (btype != T_VOID) {
      if (btype != T_FLOAT && btype != T_DOUBLE) {
        nf_cnt++;
      }
      llvm::Type* ty = type(btype);
      if (nf_cnt == NF_REGS) {
        nf_cnt++;
        paramTypes.insert(paramTypes.begin(), ty);
        _param_to_arg.insert(_param_to_arg.begin(), i);
      } else {
        paramTypes.push_back(ty);
        _param_to_arg.push_back(i);
      }
    }
  }
  if (nf_cnt != 0 && nf_cnt < NF_REGS) {
    paramTypes.insert(paramTypes.begin(), type(T_LONG));
    _param_to_arg.insert(_param_to_arg.begin(), 0);
  }

  llvm::FunctionType *ftype = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage;
  _func = llvm::Function::Create(ftype, linkage, 0, _name, _mod);
  func()->addFnAttr("frame-pointer", "all");
  func()->setGC("statepoint-example");
  if (cg()->has_exceptions()) {
    llvm::FunctionCallee pf = mod()->getOrInsertFunction("__gxx_personality_v0", llvm::FunctionType::get(type(T_INT), true));
    func()->setPersonalityFn(llvm::cast<llvm::Constant>(pf.getCallee()));
  }

  create_blocks();
}

std::vector<llvm::Value*> Selector::call_args(MachCallNode* node) {
  const TypeTuple* d = node->tf()->domain();
  std::vector<llvm::Value*> args;
  for (uint i = TypeFunc::Parms; i < d->cnt(); ++i) {
    const Type* at = d->field_at(i);
    if (at->base() == Type::Half) continue;
    llvm::Value* arg = select_node(node->in(i));
    args.push_back(arg);
  }
  return args;
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
  if (C->tf()->domain()->cnt() == TypeFunc::Parms)
    return 0;
  return std::find(_param_to_arg.begin(), _param_to_arg.end(), param_num) - _param_to_arg.begin();
}

void Selector::create_blocks() {
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(ctx(), "B0", func());
  builder().SetInsertPoint(entry_block);
  std::string b_str = "B";
  _blocks.reserve(C->cfg()->number_of_blocks());
  for (size_t i = 0; i < C->cfg()->number_of_blocks(); ++i) {
    _blocks.push_back(llvm::BasicBlock::Create(ctx(), b_str + std::to_string(i + 1), func()));
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

llvm::Value* Selector::select_address(MachNode *mem_node) {
  const MachOper* mop = mem_node->memory_operand();
  int op_index = MemNode::Address;
  llvm::Value *base, *offset;
  switch (mop->opcode()) {
    case INDIRECT: {
      Node* addr_node = mem_node->in(op_index++);
      assert(addr_node != NULL, "check");
      uint addr_rule = addr_node->is_Mach() ? addr_node->as_Mach()->rule() : _last_Mach_Node;
      if (LlvmCodeGen::cmp_ideal_Opcode(addr_node, Op_AddP)) {
        MachNode* mach_addr = addr_node->as_Mach();
        Node* base_node = mach_addr->in(2);
        if (LlvmCodeGen::cmp_ideal_Opcode(base_node, Op_ConP)) {
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
      } else if (LlvmCodeGen::cmp_ideal_Opcode(addr_node, Op_ConP)) {
        return select_oper(addr_node->as_Mach()->_opnds[1]);
        base = null(llvm::PointerType::getUnqual(offset->getType()));
      } else {
        return select_node(addr_node); 
      }
      if (base->getType()->isIntegerTy() && offset->getType()->isPointerTy()) {
        std::swap(base, offset);
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

llvm::Value* Selector::select_oper(MachOper *oper) {
  const Type* ty = oper->type();
  BasicType bt = ty->basic_type();
  switch (bt) {
  case T_INT: return builder().getInt32(oper->constant());
  case T_LONG: return builder().getInt64(oper->constantL());
  case T_FLOAT: return llvm::ConstantFP::get(
    llvm::Type::getFloatTy(ctx()), llvm::APFloat(oper->constantF()));
  case T_DOUBLE: return llvm::ConstantFP::get(
    llvm::Type::getDoubleTy(ctx()), llvm::APFloat(oper->constantD()));
  case T_ARRAY:
  case T_OBJECT: {
    assert(ty->isa_narrowoop() == NULL, "check");
    return select_oper_helper(ty, true, false);
  }
  case T_METADATA: return select_oper_helper(ty, false, false); 
  case T_NARROWOOP: {
    if (ty->is_narrowoop()->get_con() != 0) {
      return select_oper_helper(ty, true, true);
    }
    return null(T_NARROWOOP);
  }
  case T_NARROWKLASS: return select_oper_helper(ty, false, true);
  case T_ADDRESS: return get_ptr(oper->constant(), T_ADDRESS);
  case T_VOID: return NULL;
  default:
    tty->print_cr("BasicType %d", bt);
    ShouldNotReachHere(); return NULL;
  }
}

llvm::Value* Selector::select_oper_helper(const Type* ty, bool oop, bool narrow) {
  uintptr_t con = [&] {
    if (oop) {
      if (narrow) return (uintptr_t)ty->is_narrowoop()->get_con();
      return (uintptr_t)ty->is_oopptr()->const_oop()->constant_encoding();
    } else {
      if (narrow) return (uintptr_t)ty->is_narrowklass()->get_con();
      if (ty->base() == Type::KlassPtr) {
        assert(ty->is_klassptr()->klass()->is_loaded(), "klass not loaded");
        return (uintptr_t)ty->is_klassptr()->klass()->constant_encoding();
      } else {
        return (uintptr_t)ty->is_metadataptr()->metadata()->constant_encoding();
      }
    }
  }();
  con = ConstantDebugInfo::encode(con);
  llvm::Value* addr = get_ptr(con, T_ADDRESS);
  consts().emplace(con, oop ? DebugInfo::Oop : DebugInfo::Metadata);
  BasicType bt = narrow ? T_LONG : (oop ? T_OBJECT : T_METADATA);
  llvm::Value* ret = load(addr, bt);
  if (narrow) {
    llvm::Value* shift = llvm::ConstantInt::get(ret->getType(), oop ? Universe::narrow_oop_shift() : Universe::narrow_klass_shift());
    ret = builder().CreateLShr(ret, shift);
    ret = builder().CreateTrunc(ret, type(oop ? T_NARROWOOP : T_NARROWKLASS));
  }
  return ret;
}

llvm::Value* Selector::get_ptr(const void* ptr, llvm::Type* ty) {
  return get_ptr((uint64_t)ptr, ty);
}

llvm::Value* Selector::get_ptr(const void* ptr, BasicType ty) {
  return get_ptr(ptr, type(ty));
}

llvm::Value* Selector::get_ptr(uint64_t ptr, llvm::Type* ty) {
  llvm::IntegerType* intTy = builder().getIntNTy(pointer_size());
  return builder().CreateIntToPtr(llvm::ConstantInt::get(intTy, ptr), ty);
}

llvm::Value* Selector::get_ptr(uint64_t ptr, BasicType ty) {
  return get_ptr(ptr, type(ty));
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
  Block* target_block = C->cfg()->get_block_for_node(node->raw_out(true_idx)->raw_out(0))->non_connector();
  Block* fallthr_block = C->cfg()->get_block_for_node(node->raw_out(false_idx)->raw_out(0))->non_connector();
  llvm::BasicBlock* target_bb = basic_block(target_block);
  llvm::BasicBlock* fallthr_bb = basic_block(fallthr_block);
  
  // MachIfNode* if_node = node->as_MachIf();
  // float prob = if_node->_prob;
  // llvm::MDBuilder MDHelper(CGM.getLLVMContext());
  // llvm::MDNode *Weights = MDHelper.createBranchWeights(prob, 1 - prob);
  builder().CreateCondBr(pred, target_bb, fallthr_bb/*, Weights*/);
}

std::vector<llvm::Type*> Selector::types(const std::vector<llvm::Value*>& v) const {
  std::vector<llvm::Type*> ret;
  ret.reserve(v.size());
  for (llvm::Value* val : v) {
    ret.push_back(val->getType());
  }
  return ret;
}

llvm::CallInst* Selector::call_C(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args) {
  llvm::FunctionCallee f = callee(func, retType, args);
  llvm::CallInst* call = builder().CreateCall(f, args);
  call->addAttribute(llvm::AttributeList::FunctionIndex, llvm::Attribute::get(ctx(), "statepoint-id", std::to_string(DebugInfo::id(DebugInfo::NativeCall))));
  call->addAttribute(llvm::AttributeList::FunctionIndex, llvm::Attribute::get(ctx(), "gc-leaf-function", "true"));
  return call;
}

llvm::FunctionCallee Selector::callee(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args) {
  std::vector<llvm::Type*> paramTypes = types(args);
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Value* ptr = get_ptr(func, llvm::PointerType::getUnqual(funcTy));
  return llvm::FunctionCallee(funcTy, ptr);
}

llvm::CallBase* Selector::call(MachCallNode* node, llvm::Type* retType, const std::vector<llvm::Value*>& args) {
  llvm::FunctionCallee f = callee(node->entry_point(), retType, args);
  llvm::Value* callee = f.getCallee();
  ScopeDescriptor& sd = cg()->scope_descriptor();
  Node* block_end = block()->end();
  CatchNode* catch_node = block_end->isa_Catch();
  ScopeInfo* si = sd.register_scope(node, catch_node);
  std::vector<llvm::Value*> deopt = sd.stackmap_scope(si);
  std::vector<llvm::OperandBundleDef> ob = { llvm::OperandBundleDef("deopt", deopt) };

  uint32_t patch_bytes = 0;
  if (node->is_MachCallJava()) {
    patch_bytes += NativeCall::instruction_size + BytesPerInt - 1;
    if (node->is_MachCallDynamicJava()) {
      patch_bytes += NativeMovConstReg::instruction_size;
    }
  }
  unsigned nf_cnt = 0;
  size_t spill_size = 0, first_spill_size = 0;
  for (llvm::Value* val : args) {
    llvm::Type* ty = val->getType();
    if (ty->isFloatingPointTy()) continue;
    nf_cnt++;
    if (nf_cnt > NF_REGS) {
      size_t size = ty->isPointerTy() 
      ? mod()->getDataLayout().getIndexTypeSizeInBits(val->getType())
      : ty->getScalarSizeInBits();
      size >>= 3;
      spill_size += size == 8 ? 8 : 4;
      first_spill_size = first_spill_size ? first_spill_size : spill_size;
    }
  }
  if (spill_size == first_spill_size) {
    spill_size = 0;
  } else {
    const int ALIGNMENT = 16;
    spill_size = ((spill_size-1) & -ALIGNMENT) + ALIGNMENT;
  }
  _max_spill = MAX(max_spill(), spill_size);
  std::unique_ptr<PatchInfo> pi_uptr = nf_cnt > NF_REGS
    ? std::make_unique<SpillPatchInfo>(patch_bytes, spill_size)
    : std::make_unique<PatchInfo>(patch_bytes);
  PatchInfo* pi = pi_uptr.get();
  patch_info().emplace(si->stackmap_id, std::move(pi_uptr));
  
  llvm::BasicBlock* next_bb = nullptr;
  llvm::CallBase* ret = nullptr;
  if (catch_node) {
    ExceptionInfo& catch_info = exception_info()[basic_block()];
    uint num_succs = block()->_num_succs;
    catch_info.reserve(num_succs);
    for (size_t i = 0; i < num_succs; ++i) {
      CatchProjNode* cp = catch_node->raw_out(i)->as_CatchProj();
      Block* b = C->cfg()->get_block_for_node(cp->raw_out(0))->non_connector();
      llvm::BasicBlock* bb = basic_block(b);
      if (cp->_con == CatchProjNode::fall_through_index) {
        next_bb = bb;
      } else {
        catch_info.emplace_back(bb, cp->handler_bci());
      }
    }

    if (next_bb) {
      assert(num_succs == 2, "unexpected num_succs");
      llvm::BasicBlock* handler_bb = catch_info[0].first;
      builder().SetInsertPoint(handler_bb);
      llvm::LandingPadInst* lp = builder().CreateLandingPad(llvm::Type::getTokenTy(ctx()), 0);
      lp->setCleanup(true);
      builder().SetInsertPoint(basic_block());
      ret = builder().CreateInvoke(f, next_bb, handler_bb, args, ob);
    } else {
      ret = builder().CreateCall(f, args, ob);
      // a faux comparison just to attach blocks to the CFG
      llvm::BasicBlock* right_bb = catch_info[1].first;
      for (auto it = catch_info.rbegin() + 1; it != catch_info.rend() - 1; ++it) {
        right_bb = llvm::BasicBlock::Create(ctx(), basic_block()->getName() + "_handler" + std::to_string(std::distance(catch_info.rbegin(), it - 1)), func());
        builder().SetInsertPoint(right_bb);
        llvm::Value* pred = builder().CreateICmpEQ(thread(), null(thread()->getType()));
        builder().CreateCondBr(pred, it->first, (it - 1)->first);
      }
      builder().SetInsertPoint(basic_block());
      llvm::Value* pred = builder().CreateICmpEQ(thread(), null(thread()->getType()));
      builder().CreateCondBr(pred, catch_info[0].first, right_bb);
    }
  } else {
    ret = builder().CreateCall(f, args, ob);
    next_bb = basic_block(block()->non_connector_successor(0));
    if (node->is_MachCallJava() && !block_end->is_MachReturn() && !block_end->is_MachGoto()) { // ShouldNotReachHere and jmpDir
      builder().CreateBr(next_bb);
    }
  }
  ret->addAttribute(llvm::AttributeList::FunctionIndex, llvm::Attribute::get(ctx(), "statepoint-id", std::to_string(si->stackmap_id)));
  call_info().emplace_back(ret, pi);
  return retType->isVoidTy() ? NULL : ret;
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

llvm::Value* Selector::left_circular_shift(llvm::Value* arg, llvm::Value* shift, unsigned capacity) {
  llvm::Value* size = builder().getIntN(capacity, capacity);
  llvm::Value* shift2 = builder().CreateSub(size, shift);
  llvm::Value* addend1 = builder().CreateShl(arg, shift);
  llvm::Value* addend2 = builder().CreateLShr(arg, shift2);
  return builder().CreateOr(addend1, addend2);
}

llvm::Value* Selector::loadKlass_not_null(llvm::Value* obj) {
  llvm::Value* klass_offset = builder().getInt64(oopDesc::klass_offset_in_bytes());
  llvm::Value* addr = gep(obj, klass_offset);
  if (UseCompressedClassPointers) {
    llvm::Value* narrow_klass = load(addr, T_NARROWKLASS);
    return decodeKlass_not_null(narrow_klass);
  }
  return load(addr, T_METADATA);
}

llvm::Value* Selector::decodeKlass_not_null(llvm::Value* narrow_klass) {
  if (!Universe::narrow_klass_shift() && !Universe::narrow_klass_base()) {
     return narrow_klass; 
  }
  narrow_klass = builder().CreateZExt(narrow_klass, builder().getIntNTy(pointer_size()));
  if (Universe::narrow_klass_shift() != 0) {
    llvm::Value* shift = llvm::ConstantInt::get(narrow_klass->getType(), Universe::narrow_klass_shift());
    narrow_klass = builder().CreateShl(narrow_klass, shift);
  }
  if (Universe::narrow_klass_base() != NULL) {
    llvm::Value* base = get_ptr(Universe::narrow_klass_base(), T_METADATA);
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
  llvm::Value* oop;

  assert(Universe::narrow_oop_shift() != 0, "unsupported compression mode");
  narrow_oop = builder().CreateZExt(narrow_oop, builder().getIntNTy(pointer_size()));
  llvm::Value* narrow_oop_shift_ = llvm::ConstantInt::get(narrow_oop->getType(), Universe::narrow_oop_shift());
  llvm::Value* narrow_oop_base_ = get_ptr(Universe::narrow_klass_base(), T_OBJECT);
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
      llvm::Value* narrow_zero = null(narrow_oop->getType());
      llvm::Value* zero = null(oop->getType());
      llvm::Value* pred = builder().CreateICmpEQ(narrow_oop, narrow_zero);
      oop = builder().CreateShl(narrow_oop, narrow_oop_shift_);
      oop = gep(narrow_oop_base_, oop);
      oop = builder().CreateSelect(pred, zero, oop);
    }
  }

  DEBUG_ONLY( if (VerifyOops) {/*verify_oop*/} );

  return oop;
}

llvm::Value* Selector::encode_heap_oop(llvm::Value *oop, bool not_null) {
  #ifdef ASSERT
    if (VerifyOops) {
      // verify oops
    }
    if (Universe::narrow_oop_base() != NULL) {
      // also check something
    }
  #endif

  if (is_fast_compression()) {
    // 32-bit oops
    return oop;
  } else {
    llvm::Value* narrow_oop = builder().CreatePtrToInt(oop, builder().getIntNTy(pointer_size()));
    assert(Universe::narrow_oop_shift() != 0, "unsupported compression mode");
    llvm::Value* narrow_oop_shift_ = llvm::ConstantInt::get(narrow_oop->getType(), Universe::narrow_oop_shift());
    llvm::Value* narrow_oop_base_ = builder().getIntN(pointer_size(), (uint64_t)Universe::narrow_klass_base());
    if (Universe::narrow_oop_base() != NULL) {
      // Heap-based compressed oops
      if (not_null) {
        narrow_oop = builder().CreateSub(narrow_oop, narrow_oop_base_);
      } else {
        llvm::Value* zero = null(narrow_oop->getType());
        llvm::Value* pred = builder().CreateICmpEQ(narrow_oop, zero);
        narrow_oop = builder().CreateSub(narrow_oop, narrow_oop_base_);
        narrow_oop = builder().CreateSelect(pred, zero, narrow_oop);
      }
    }
    narrow_oop = builder().CreateAShr(narrow_oop, narrow_oop_shift_);
    narrow_oop = builder().CreateTrunc(narrow_oop, type(T_NARROWOOP));
    // mark_nptr(narrow_oop);
    return narrow_oop;
  }
}

void Selector::locs_for_narrow_oops() {
  llvm::DominatorTree DT(*func());
  std::vector<llvm::Instruction*> narrow_oops_to_transform;
  std::vector<std::vector<llvm::User*>> users_to_transform;
  for (llvm::Instruction* narrow_oop : narrow_oops()) {
    std::unordered_set<llvm::BasicBlock*> visited;
    std::deque<llvm::BasicBlock*> to_visit;
    bool to_transform = false;
    for (llvm::User* user : narrow_oop->users()) {
      bool found = false;
      llvm::Instruction* inst = llvm::cast<llvm::Instruction>(user);
      llvm::BasicBlock* bb = inst->getParent();
      auto check_statepoint = [&](llvm::Instruction& inst) {
        llvm::CallBase* call = llvm::dyn_cast<llvm::CallBase>(&inst);
        found = call && !call->hasFnAttr("gc-leaf-function");
        if (found) {
          if (!to_transform) {
            narrow_oops_to_transform.push_back(narrow_oop);
            users_to_transform.emplace_back();
            to_transform = true;
          }
          users_to_transform.back().push_back(user);
        }
      };
      auto end_it = [&] {
        if (bb == narrow_oop->getParent()) return narrow_oop->getReverseIterator();
        if (llvm::PHINode* phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
          llvm::Value* val = llvm::cast<llvm::Value>(narrow_oop);
          for (size_t i = 0; i < phi->getNumIncomingValues(); ++i) {
            if (phi->getIncomingValue(i) == val) {
              to_visit.push_back(phi->getIncomingBlock(i));
            }
          }
          return inst->getReverseIterator();
        }
        for (llvm::BasicBlock* pred : llvm::predecessors(bb)) {
          to_visit.push_back(pred);
        }
        return bb->rend();
      } ();
      for (auto it = inst->getReverseIterator(); !found && it != end_it; ++it) {
        check_statepoint(*it);
      }
      while (!found && !to_visit.empty()) {
        llvm::BasicBlock* bb = *(to_visit.rbegin());
        to_visit.pop_back();
        if (visited.count(bb)) continue;
        if (!DT.dominates(narrow_oop, bb) && (bb != narrow_oop->getParent())) continue;
        for (auto it = bb->rbegin(); !found && it != bb->rend(); ++it) {
          check_statepoint(*it);
        }
        if (found) break;
        visited.insert(bb);
        for (llvm::BasicBlock* pred : llvm::predecessors(bb)) {
          to_visit.push_back(pred);
        }
      }
    }
  }

  for (size_t i = 0; i < narrow_oops_to_transform.size(); ++i) {
    llvm::Instruction* narrow_oop = narrow_oops_to_transform[i];
    llvm::BasicBlock* bb = narrow_oop->getParent();
    auto insert_pt = llvm::isa<llvm::PHINode>(narrow_oop) ? bb->getFirstInsertionPt() : ++narrow_oop->getIterator();
    builder().SetInsertPoint(bb, insert_pt);
    llvm::Value* oop = decode_heap_oop(narrow_oop, false);
    for (llvm::User* user : users_to_transform[i]) {
      llvm::Instruction* inst = llvm::cast<llvm::Instruction>(user);
      if (llvm::PHINode* phi = llvm::dyn_cast<llvm::PHINode>(inst)) {
        for (size_t j = 0; j < phi->getNumIncomingValues(); ++j) {
          if (llvm::cast<llvm::Instruction>(phi->getIncomingValue(j)) == narrow_oop) {
            builder().SetInsertPoint(phi->getIncomingBlock(j)->getTerminator());
            llvm::Value* new_use = encode_heap_oop(oop, false);
            phi->setOperand(j, new_use);
          }
        }
      } else {
        builder().SetInsertPoint(inst);
        llvm::Value* new_use = encode_heap_oop(oop, false);
        user->replaceUsesOfWith(narrow_oop, new_use);
      }
    }
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

void Selector::stackmap(DebugInfo::Type type, size_t idx, size_t patch_bytes) {
  llvm::Value* id = builder().getInt64(DebugInfo::id(type, idx));
  builder().CreateIntrinsic(llvm::Intrinsic::experimental_stackmap, {}, { id, builder().getInt32(patch_bytes) });
}

void Selector::complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst) {
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

void Selector::epilog() {
  std::unordered_set<llvm::BasicBlock*> exception_blocks;
  for (auto& pair : call_info()) {
    llvm::CallBase* cb = pair.first;
    PatchInfo* pi = pair.second;
    size_t* tmp = &pi->size;
    size_t& patch_bytes = *tmp;
    if (max_spill()) {
      SpillPatchInfo* spi = pi->asSpill();
      if (!spi || (spi->spill_size != max_spill())) {
        if (patch_bytes == 0) {
          patch_bytes += NativeCall::instruction_size;
        }
        patch_bytes += CallDebugInfo::SUB_RSP_SIZE + CallDebugInfo::ADD_RSP_SIZE;
      }
      llvm::BasicBlock* bb = cb->getParent();
      if (exception_info().count(bb)) {
        ExceptionInfo& ei = exception_info().at(bb);
        for (auto pair : ei) {
          llvm::BasicBlock* hbb = pair.first;
          if (exception_blocks.find(hbb) == exception_blocks.end()) {
            builder().SetInsertPoint(hbb, hbb->getFirstInsertionPt());
            stackmap(DebugInfo::Exception, 0, CallDebugInfo::ADD_RSP_SIZE);
            stackmap(DebugInfo::PatchBytes);
            exception_blocks.insert(hbb);
          }
        }
      }
    }
    cb->addAttribute(llvm::AttributeList::FunctionIndex, llvm::Attribute::get(ctx(), "statepoint-num-patch-bytes", std::to_string(patch_bytes)));
  }
}
