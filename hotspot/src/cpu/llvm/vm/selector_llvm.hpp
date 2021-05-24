#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include "llvmHeaders.hpp"
#include "opto/phase.hpp"
#include "opto/node.hpp"
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
  llvm::Module& _mod;
  GrowableArray<llvm::BasicBlock*> _blocks;

  GrowableArray<CacheEntry*> _cache;
  Block* _block;

  void gen_func();
  void create_blocks();
  void select();
  void select_block(Block* block);
  void create_entry_block();
  void jump_on_start(Node* node);
  void create_br(Block* block);
public:
  llvm::Type* convert_type(BasicType btype) const;
  llvm::Value* select_node(Node* node);
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return &_mod; }
  llvm::IRBuilder<>& builder() { return _builder; }
  llvm::Function* func() { return _func; } 
  int select_address(MachNode *mem_node, llvm::Value *&base, llvm::Value *&offset);
  Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module& mod);
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP