#include "selector_llvm.hpp"
#include "opto/block.hpp"
#include "opto/machnode.hpp"
#include "adfiles/ad_llvm.hpp"

Selector::Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module& mod) : 
  Phase(Phase::BlockLayout), _comp(comp), _ctx(ctx), _builder(ctx), 
  _mod(mod),
  _blocks(comp->cfg()->number_of_blocks(), comp->cfg()->number_of_blocks(), false),
  _cache(comp->unique(), comp->unique(), false) {
  gen_func();
  create_blocks();
  select();
  NOT_PRODUCT( _func->viewCFG(); ) 
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
  llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalWeakLinkage;
  _func = llvm::Function::Create(ftype, linkage, 0, "ViewCFG_Test", &_mod);
}

void Selector::create_blocks() {
  std::string b_str = "B";
  for (int i = 0; i < _blocks.length(); ++i) {
    _blocks.at_put(i, llvm::BasicBlock::Create(_func->getContext(), b_str + std::to_string(i), _func));
  }
  create_entry_block();
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
  _builder.SetInsertPoint(_blocks.at(_block->_pre_order));
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

void Selector::create_entry_block() {
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(_func->getContext(), "B0", _func);
  _builder.SetInsertPoint(entry_block);
  Block* block = _comp->cfg()->get_root_block();
  create_br(block);
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
  _builder.CreateBr(_blocks.at(block->_pre_order));
}

int Selector::select_address(MachNode *mem_node, llvm::Value *&base, llvm::Value *&offset){
  const MachOper* mop = mem_node->memory_operand();
  int op_index = MemNode::Address;
  switch (mop->opcode()){
    case INDOFFSET: {
      Node* node = mem_node->in(op_index++);
      base = select_node(node);
      offset = _builder.getIntN(
        _mod.getDataLayout().getPointerSize() * 8, 
        mop->constant_disp());
      break;
    }
    default: ShouldNotReachHere();
  }
  return op_index;
}
