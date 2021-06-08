#include "selector_llvm.hpp"
#include "opto/block.hpp"
#include "opto/machnode.hpp"
#include "adfiles/ad_llvm.hpp"

Selector::Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name) :
  Phase(Phase::BlockLayout), _comp(comp), _ctx(ctx), _builder(ctx), 
  _mod(mod), _name(name),
  _blocks(comp->cfg()->number_of_blocks(), comp->cfg()->number_of_blocks(), false),
  _cache(comp->unique(), comp->unique(), false) {
  gen_func();
  create_blocks();
  select();
  for (int i = 0; i < _cache.length(); ++i) {
     delete _cache.at(i);
  }
}

llvm::Type* Selector::convert_type(BasicType type) const {
  switch (type){
    case T_BYTE: return llvm::Type::getInt8Ty(_ctx);
    case T_SHORT: return llvm::Type::getInt16Ty(_ctx);
    case T_INT: return llvm::Type::getInt32Ty(_ctx);
    case T_LONG: return llvm::Type::getInt64Ty(_ctx);
    case T_FLOAT: return llvm::Type::getFloatTy(_ctx);
    case T_DOUBLE: return llvm::Type::getDoubleTy(_ctx);
    case T_BOOLEAN: return llvm::Type::getInt8Ty(_ctx);
    case T_CHAR: return llvm::Type::getInt32Ty(_ctx);
    case T_VOID: return llvm::Type::getVoidTy(_ctx);
    case T_OBJECT: return llvm::PointerType::getUnqual(llvm::ArrayType::get(llvm::Type::getInt8Ty(_ctx), sizeof(oopDesc)));
    case T_ADDRESS: return llvm::PointerType::getUnqual(llvm::ArrayType::get(llvm::Type::getInt8Ty(_ctx), sizeof(Klass)));
    default: 
      assert(false, "unable to convert type");
      Unimplemented();
  }
}

void Selector::gen_func() {
  llvm::Type *retType = convert_type(_comp->tf()->return_type());
  const TypeTuple* domain = _comp->tf()->domain();
  std::vector<llvm::Type*> paramTypes;

  for (uint i = TypeFunc::Parms; i < domain->cnt(); ++i) {
    BasicType btype = domain->field_at(i)->basic_type();
    llvm::Type* type = convert_type(btype);
    paramTypes.push_back(type);
  }

  llvm::FunctionType *ftype = llvm::FunctionType::get(retType, paramTypes, false);
  llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage;
  _func = llvm::Function::Create(ftype, linkage, 0, _name, _mod);
}

void Selector::create_blocks() {
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(_func->getContext(), "B0", _func);
  _builder.SetInsertPoint(entry_block);
  std::string b_str = "B";
  for (int i = 0; i < _blocks.length(); ++i) {
    _blocks.at_put(i, llvm::BasicBlock::Create(_func->getContext(), b_str + std::to_string(i + 1), _func));
  }
  Block* block = _comp->cfg()->get_root_block();
  create_br(block);
}

void Selector::select() {
  for (int i = 0; i < _cache.length(); ++i) {
    _cache.at_put(i, new CacheEntry);
  }
  
  for (uint i = 0; i < _blocks.length(); ++i) {
    select_block(_comp->cfg()->get_block(i));
  }
}

void Selector::select_block(Block* block) {
  _block = block;
  _builder.SetInsertPoint(_blocks.at(_block->_pre_order - 1));
  if (_block->get_node(0) == (Node *)_comp->cfg()->get_root_node()) {
    jump_on_start(_block->get_node(0));
  }
  else {
    for (uint i = 0; i < _block->number_of_nodes(); ++i) {
      Node* node = _block->get_node(i);
      select_node(node);
    }
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

void Selector::jump_on_start(Node* node) {
  Node* start_node;
  for (uint i = 0; i < node->outcnt(); ++i) {
    if (node->raw_out(i)->is_Start()) {
      start_node = node->raw_out(i);
      break;
    }
  }
  Block* block = _comp->cfg()->get_block_for_node(start_node)->non_connector();
  create_br(block);
}

void Selector::create_br(Block* block) {
  _builder.CreateBr(_blocks.at(block->_pre_order - 1));
}

llvm::Value* Selector::select_address(MachNode *mem_node) {
  int op_index;
  return select_address(mem_node, op_index);
}

llvm::Value* Selector::select_address(MachNode *mem_node, int& op_index) {
  const MachOper* mop = mem_node->memory_operand();
  op_index = MemNode::Address;
  switch (mop->opcode()){
    case INDOFFSET: {
      Node* node = mem_node->in(op_index++);
      llvm::Value* base = select_node(node);
      llvm::Value* offset = _builder.getIntN(
        _mod.getDataLayout().getPointerSize() * 8, 
        mop->constant_disp() / _mod.getDataLayout().getPointerSize());
      return builder().CreateGEP(base, offset);
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
    return get_ptr((intptr_t)(type->is_oopptr()->const_oop()), convert_type(T_OBJECT));
  }
  case T_METADATA: {
    if (type->base() == Type::KlassPtr) {
      return get_ptr((intptr_t)(type->is_klassptr()->klass()), convert_type(T_ADDRESS));
    } else {
      return get_ptr((intptr_t)(type->is_metadataptr()->metadata()), convert_type(T_ADDRESS));
    }
  }
  case T_NARROWOOP: return get_ptr((intptr_t)(jobject)(type->is_narrowoop()->get_con()), convert_type(T_OBJECT));
  case T_NARROWKLASS: return get_ptr((intptr_t)((Klass*)type->is_narrowklass()->get_con()), convert_type(T_ADDRESS));
  case T_ADDRESS: {
    if (oper->constant() == NULL) return llvm::Constant::getNullValue(llvm::Type::getInt8PtrTy(ctx()));
    return get_ptr((intptr_t)(oper->constant()), convert_type(T_ADDRESS));
  }
  case T_VOID: return NULL;
  default:
    tty->print_cr("BasicType %d", bt);
    ShouldNotReachHere(); return NULL;
  }
}

llvm::Value* Selector::get_ptr(intptr_t value, llvm::Type* type) {
  llvm::IntegerType* intTy = llvm::Type::getIntNTy(ctx(), 
    mod()->getDataLayout().getPointerSize() * 8);
  return builder().CreateIntToPtr(
    llvm::ConstantInt::get(intTy, value, false),
    llvm::PointerType::getUnqual(type));
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
  Block* target_block = _block->non_connector_successor(0);
  Block* fallthr_block = _block->non_connector_successor(1);
  llvm::BasicBlock* target_bb = _blocks.at(target_block->_pre_order - 1);
  llvm::BasicBlock* fallthr_bb = _blocks.at(fallthr_block->_pre_order - 1);
  
  MachIfNode* if_node = node->as_MachIf();
  float prob = if_node->_prob;
  // llvm::MDBuilder MDHelper(CGM.getLLVMContext());
  // llvm::MDNode *Weights = MDHelper.createBranchWeights(prob, 1 - prob);
  builder().CreateCondBr(pred, target_bb, fallthr_bb/*, Weights*/);
}
