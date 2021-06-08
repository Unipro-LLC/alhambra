#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include "code_gen/llvmGlobals.hpp"
#include "opto/phase.hpp"
#include "opto/node.hpp"
#include "opto/machnode.hpp"
#include "utilities/growableArray.hpp"

class PhaseCFG;
class Block;

struct CacheEntry {
  llvm::Value* val = NULL;
  bool hit = false;
};

class Selector : public Phase {

private:
  Compile* _comp;
  llvm::Function* _func;
  llvm::LLVMContext& _ctx;
  llvm::IRBuilder<> _builder;
  llvm::Module* _mod;
  const char* _name;
  GrowableArray<llvm::BasicBlock*> _blocks;

  GrowableArray<CacheEntry*> _cache;
  Block* _block;

  void gen_func();
  void create_blocks();
  void select();
  void select_block(Block* block);
  void jump_on_start(Node* node);
  void create_br(Block* block);
public:
  llvm::Type* convert_type(BasicType btype) const;
  llvm::Value* select_node(Node* node);
  llvm::Value* select_oper(MachOper *oper);
  llvm::Value* get_ptr(intptr_t value, llvm::Type* type);
  Compile* comp() { return _comp ; }
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return _mod; }
  llvm::IRBuilder<>& builder() { return _builder; }
  llvm::Function* func() { return _func; } 
  llvm::Value* select_address(MachNode *mem_node);
  llvm::Value* select_address(MachNode *mem_node, int& op_index);
  llvm::Value* select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt);
  void select_if(llvm::Value *pred, Node* node);
  Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name);
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP
