#include "selector_llvm.hpp"
#include "opto/block.hpp"

Selector::Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module& mod) : 
  Phase(Phase::BlockLayout), _comp(comp), _ctx(ctx), _mod(mod),
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
  for (uint i = 0; i < _blocks.length(); ++i) {
    _blocks.at_put(i, llvm::BasicBlock::Create(_func->getContext(), b_str + std::to_string(i + 1), _func));
  }
}

void Selector::select() {
  for (int i = 0; i < _comp->unique(); ++i) {
    _cache.at_put(i, new CacheEntry);
  }

  for (uint i = 0; i < _blocks.length(); ++i) {
    Block* block = _comp->cfg()->get_block(i);
    select_block(block);
  }
}

void Selector::select_block(Block* block) {
  for (uint j = 0; j < block->number_of_nodes(); ++j) {
      Node* node = block->get_node(j);
      select_node(node);
    }
}

llvm::Value* Selector::select_node(Node* node) {
  node_idx_t idx = node->_idx;
  CacheEntry* entry = _cache.at(idx);
  if (!entry->hit) {
    entry->val = node->select(this);
    entry->hit = true;
  }
  return entry->val;
}