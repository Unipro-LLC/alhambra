#include "selector_llvm.hpp"
#include "opto/cfgnode.hpp"
#include "opto/rootnode.hpp"
#include "adfiles/ad_llvm.hpp"

Selector::Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name) :
  Phase(Phase::BlockLayout), 
  _comp(comp), _ctx(ctx), _builder(ctx), _mod(mod), _cache(comp->unique()), 
  _blocks(comp->cfg()->number_of_blocks()),
  _pointer_size(mod->getDataLayout().getPointerSize() * 8), _name(name) {
  create_func();
  prolog();
  select();
  complete_phi_nodes();
}

Selector::~Selector() {
  for (auto elem : _cache) {
    delete elem;
  }
}

void Selector::prolog() {
  llvm::Type* retType = llvm::PointerType::getUnqual(llvm::Type::getInt8PtrTy(ctx()));
  std::vector<llvm::Type*> paramTypes { convert_type(T_INT) };
  std::vector<llvm::Value*> args { builder().getInt32(ThreadLocalStorage::thread_index()) };                                                                                            
  _thread = call_external((void*)os::thread_local_storage_at, retType, paramTypes, args);

  uint slots = OptoReg::reg2stack(comp()->matcher()->_old_SP);
  _SP = builder().CreateAlloca(convert_type(T_INT), builder().getInt32(slots));
  _last_Java_fp = gep(thread(), in_bytes(JavaThread::last_Java_fp_offset()));
  llvm::Value* last_fp = builder().CreateLoad(_last_Java_fp);
  _FP = gep(_SP, 16);
  store(last_fp, _FP);
  store(_FP, _last_Java_fp);
  Block* block = comp()->cfg()->get_root_block();
  builder().CreateBr(basic_block(block));
}

llvm::Value* Selector::tlab_top() {
  if (!_tlab_top) {
    llvm::Value* tto = builder().getInt32(in_bytes(JavaThread::tlab_top_offset()));
    _tlab_top = gep(thread(), tto);
  }
  return _tlab_top;
}

llvm::Value* Selector::gep(llvm::Value* base, int offset) {
  llvm::Type* elTy = llvm::cast<llvm::PointerType>(base->getType())->getElementType();
  offset /= elTy->isIntegerTy() ? (elTy->getIntegerBitWidth() / 8) : (pointer_size() / 8);
  return builder().CreateGEP(base, builder().getInt32(offset));
}

llvm::Value* Selector::gep(llvm::Value* base, llvm::Value* offset) {
  llvm::Type* ty = base->getType();
  base = builder().CreatePointerCast(base, llvm::Type::getInt8PtrTy(ctx()));
  base = builder().CreateGEP(base, offset);
  return builder().CreatePointerCast(base, ty);
}

llvm::Type* Selector::convert_type(BasicType type) const {
  switch (type) {
    case T_BYTE: return llvm::Type::getInt8Ty(_ctx);
    case T_SHORT: return llvm::Type::getInt16Ty(_ctx);
    case T_INT: return llvm::Type::getInt32Ty(_ctx);
    case T_LONG: return llvm::Type::getInt64Ty(_ctx);
    case T_FLOAT: return llvm::Type::getFloatTy(_ctx);
    case T_DOUBLE: return llvm::Type::getDoubleTy(_ctx);
    case T_BOOLEAN: return llvm::Type::getInt8Ty(_ctx);
    case T_CHAR: return llvm::Type::getInt32Ty(_ctx);
    case T_VOID: return llvm::Type::getVoidTy(_ctx);
    case T_OBJECT: return llvm::PointerType::getUnqual(llvm::Type::getInt8PtrTy(_ctx));
    case T_ADDRESS: return llvm::PointerType::getUnqual(llvm::Type::getInt8PtrTy(_ctx));
    default: 
      assert(false, "unable to convert type");
      Unimplemented();
  }
}

void Selector::create_func() {
  llvm::Type *retType = convert_type(_comp->tf()->return_type());
  const TypeTuple* domain = _comp->tf()->domain();
  std::vector<llvm::Type*> paramTypes;
  for (uint i = TypeFunc::Parms; i < domain->cnt(); ++i) {
    BasicType btype = domain->field_at(i)->basic_type();
    paramTypes.push_back(convert_type(btype));
  }

  llvm::FunctionType *ftype = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage;
  _func = llvm::Function::Create(ftype, linkage, 0, _name, _mod);
  create_blocks();
}

void Selector::callconv_adjust(std::vector<llvm::Type*>& paramTypes, std::vector<llvm::Value*>& args) {
  assert(paramTypes.size() == args.size(), "length check");
  const unsigned NF_PARAMS = 6;
  unsigned nonFloatParams = 0;
  for (size_t i = 0; i < paramTypes.size(); ++i) {
    if (paramTypes[i]->isFloatingPointTy()) continue;
    nonFloatParams++;
    if (nonFloatParams == NF_PARAMS) {
      llvm::Type* ty = paramTypes[i];
      paramTypes.erase(paramTypes.begin() + i);
      paramTypes.insert(paramTypes.begin(), ty);
      llvm::Value* val = args[i];
      args.erase(args.begin() + i);
      args.insert(args.begin(), val);
      return;
    }
  }
  if (nonFloatParams != 0) {
    paramTypes.insert(paramTypes.begin(), convert_type(T_LONG));
    args.insert(args.begin(), builder().getInt64(0));
  }
}

void Selector::create_blocks() {
  assert(&(func()->getContext()) == &(ctx()), "different contexts");
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(ctx(), "B0", func());
  builder().SetInsertPoint(entry_block);
  std::string b_str = "B";
  for (size_t i = 0; i < comp()->cfg()->number_of_blocks(); ++i) {
    _blocks.append(llvm::BasicBlock::Create(ctx(), b_str + std::to_string(i + 1), func()));
  }
}

void Selector::select() {
  for (size_t i = 0; i < comp()->unique(); ++i) {
    _cache.append(new CacheEntry());
  }
  select_root_block();
  for (size_t i = 1; i < _blocks.length(); ++i) {
    select_block(_comp->cfg()->get_block(i));
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
  CacheEntry* entry = _cache.at(node->_idx);
  if (!entry->hit) {
    entry->val = node->select(this);
    entry->hit = true;
  }
  return entry->val;

}

void Selector::select_root_block() {
  RootNode* node = comp()->cfg()->get_root_node();
  Node* start_node;
  for (uint i = 0; i < node->outcnt(); ++i) {
    if (node->raw_out(i)->is_Start()) {
      start_node = node->raw_out(i);
      break;
    }
  }
  Block* block = comp()->cfg()->get_block_for_node(start_node)->non_connector();
  builder().SetInsertPoint(basic_block(comp()->cfg()->get_root_block()));
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

llvm::Value* Selector::select_oper(MachOper *oper) {
  const Type* type = oper->type();
  BasicType bt = type->basic_type();
  switch (bt) {
  case T_INT: return builder().getInt32(oper->constant());
  case T_LONG: return builder().getInt64(oper->constantL());
  case T_FLOAT: return llvm::ConstantFP::get(
    llvm::Type::getFloatTy(_ctx), oper->constantF());
  case T_DOUBLE: return llvm::ConstantFP::get(
    llvm::Type::getDoubleTy(_ctx), oper->constantD());
  case T_ARRAY:
  case T_OBJECT: {
    assert(type->isa_narrowoop() == NULL, "check");
    return get_ptr(type->is_oopptr()->const_oop(), convert_type(T_OBJECT));
  }
  case T_METADATA: {
    if (type->base() == Type::KlassPtr) {
      return get_ptr(type->is_klassptr()->klass(), convert_type(T_ADDRESS));
    } else {
      return get_ptr(type->is_metadataptr()->metadata(), convert_type(T_ADDRESS));
    }
  }
  case T_NARROWOOP: return get_ptr(type->is_narrowoop()->get_con(), convert_type(T_OBJECT));
  case T_NARROWKLASS: return get_ptr(type->is_narrowklass()->get_con(), convert_type(T_ADDRESS));
  case T_ADDRESS: {
    if (oper->constant() == NULL) return llvm::Constant::getNullValue(convert_type(T_ADDRESS));
    return get_ptr(oper->constant(), convert_type(T_ADDRESS));
  }
  case T_VOID: return NULL;
  default:
    tty->print_cr("BasicType %d", bt);
    ShouldNotReachHere(); return NULL;
  }
}

llvm::Value* Selector::get_ptr(const void* ptr, llvm::Type* type) {
  return get_ptr((intptr_t)ptr, type);
}

llvm::Value* Selector::get_ptr(intptr_t ptr, llvm::Type* type) {
  llvm::IntegerType* intTy = llvm::Type::getIntNTy(ctx(), pointer_size());
  return builder().CreateIntToPtr(llvm::ConstantInt::get(intTy, ptr), type);
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
  }
  else {
    assert(if_node->Opcode() == Op_IfTrue, "illegal Node type");
  }
  Block* target_block = comp()->cfg()->get_block_for_node(node->raw_out(true_idx)->raw_out(0));
  Block* fallthr_block = comp()->cfg()->get_block_for_node(node->raw_out(false_idx)->raw_out(0));
  llvm::BasicBlock* target_bb = basic_block(target_block);
  llvm::BasicBlock* fallthr_bb = basic_block(fallthr_block);
  
  // MachIfNode* if_node = node->as_MachIf();
  // float prob = if_node->_prob;
  // llvm::MDBuilder MDHelper(CGM.getLLVMContext());
  // llvm::MDNode *Weights = MDHelper.createBranchWeights(prob, 1 - prob);
  builder().CreateCondBr(pred, target_bb, fallthr_bb/*, Weights*/);
}

void Selector::replace_return_address(llvm::Value* new_addr) {
  llvm::Value* addr = call_intrinsic("llvm.addressofreturnaddress", llvm::Type::getInt8PtrTy(ctx()));
  store(new_addr, addr);
}

llvm::CallInst* Selector::call_intrinsic(const char* name, llvm::Type* retType) {
  std::vector<llvm::Type*> paramTypes;
  std::vector<llvm::Value*> args;
  return call_intrinsic(name, retType, paramTypes, args);
}

llvm::CallInst* Selector::call_intrinsic(
  const char* name, 
  llvm::Type* retType, 
  const std::vector<llvm::Type*>& paramTypes, 
  const std::vector<llvm::Value*>& args
  ) {
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Function* f = llvm::cast<llvm::Function>(mod()->getOrInsertFunction(name, funcTy).getCallee());
  return builder().CreateCall(f, args);
}

llvm::CallInst* Selector::call_external(void* func, llvm::Type* retType) {
  std::vector<llvm::Type*> paramTypes;
  std::vector<llvm::Value*> args;
  return call_external(func, retType, paramTypes, args);
}

llvm::CallInst* Selector::call_external(
  void* func, 
  llvm::Type* retType, 
  const std::vector<llvm::Type*>& paramTypes, 
  const std::vector<llvm::Value*>& args
  ) {
  llvm::FunctionType* funcTy = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::Function* f = static_cast<llvm::Function*>(
    get_ptr(func, llvm::PointerType::getUnqual(funcTy)));
  return builder().CreateCall(f, args);
}

void Selector::store(llvm::Value* value, llvm::Value* addr) {
  llvm::PointerType* addrTy = llvm::cast<llvm::PointerType>(addr->getType());
  addr = builder().CreatePointerCast(addr, llvm::PointerType::getUnqual(value->getType()));
  builder().CreateStore(value, addr);
}

void Selector::map_phi_nodes(PhiNode* opto_phi, llvm::PHINode* llvm_phi) {
  _phiNodeMap.push_back(std::make_pair(opto_phi, llvm_phi));
}

void Selector::complete_phi_nodes() {
  for (auto &p : _phiNodeMap) {
    PhiNode* phi_node = p.first;
    llvm::PHINode* phi_inst = p.second;
    Block* phi_block = comp()->cfg()->get_block_for_node(phi_node);
    RegionNode* phi_region = phi_node->region();
    assert(phi_block->head() == (Node*)phi_region, "check phi block");
    for (uint i = PhiNode::Input; i < phi_node->req(); ++i) {
      Node* case_val = phi_node->in(i);
      Block* case_block = comp()->cfg()->get_block_for_node(phi_block->pred(i));
      complete_phi_node(case_block, case_val, phi_inst);
    }
  }
}

void Selector::complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst) {
  if (case_block->is_connector()) {
    for (uint i=1; i< case_block->num_preds(); i++) {
      Block *p = comp()->cfg()->get_block_for_node(case_block->pred(i));
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
    llvm::BasicBlock* bb = basic_block(comp()->cfg()->get_block_for_node(case_val));
    phi_case = llvm::CastInst::CreatePointerCast(phi_case, phiTy);
    llvm::cast<llvm::Instruction>(phi_case)->insertBefore(bb->getTerminator());
  }
  phi_inst->addIncoming(phi_case, case_bb);
}

void Selector::epilog() {
  llvm::Value* last_fp = builder().CreateLoad(_FP);
  store(last_fp, _last_Java_fp);
}