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
  llvm::IRBuilder<>* _builder;
  llvm::LLVMContext& _ctx;
  llvm::Module& _mod;
  GrowableArray<llvm::BasicBlock*> _blocks;

  GrowableArray<CacheEntry*> _cache;

  llvm::Type* convert_type(BasicType btype) const;
  void gen_func();
  void create_blocks();
  void select();
  void select_block(Block* block);
public:
  Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module& mod);
  llvm::Value* select_node(Node* node);
};


#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP