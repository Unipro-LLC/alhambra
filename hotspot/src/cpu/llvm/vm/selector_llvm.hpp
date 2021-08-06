#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include "code_gen/llvmGlobals.hpp"
#include "opto/phase.hpp"
#include "opto/node.hpp"
#include "opto/block.hpp"
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
  llvm::Value* _thread;
  llvm::Value* _SP;
  llvm::Value* _FP;
  llvm::Value* _last_Java_fp;
  llvm::Value* _tlab_top = nullptr;
  GrowableArray<llvm::BasicBlock*> _blocks;
  std::vector<std::pair<PhiNode*, llvm::PHINode*>> _phiNodeMap;

  GrowableArray<CacheEntry*> _cache;
  Block* _block;
  unsigned _pointer_size;
  const char* _name;

  void create_func();
  void create_blocks();
  void prolog();
  void select();
  void select_block(Block* block);
  void select_root_block();
  void complete_phi_nodes();
  void complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst);

public:
  llvm::Type* convert_type(BasicType btype) const;
  llvm::Value* select_node(Node* node);
  llvm::Value* select_oper(MachOper *oper);
  llvm::Value* get_ptr(intptr_t ptr, llvm::Type* type);
  llvm::Value* get_ptr(const void* ptr, llvm::Type* type);
  Compile* comp() { return _comp ; }
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return _mod; }
  llvm::IRBuilder<>& builder() { return _builder; }
  llvm::Function* func() { return _func; }
  Block* block() { return _block; }
  llvm::BasicBlock* basic_block(Block* block) { return _blocks.at(block->_pre_order - 1); }
  llvm::Value* thread() { return _thread; }
  llvm::Value* tlab_top();
  llvm::Value* FP() { return _FP; };
  unsigned pointer_size() { return _pointer_size; }
  void callconv_adjust(std::vector<llvm::Type*>& paramTypes, std::vector<llvm::Value*>& args);
  llvm::Value* gep(llvm::Value* base, llvm::Value* offset);
  llvm::Value* gep(llvm::Value* base, int offset);
  llvm::Value* select_address(MachNode *mem_node);
  llvm::Value* select_address(MachNode *mem_node, int& op_index);
  llvm::Value* select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt);
  void select_if(llvm::Value *pred, Node* node);
  void replace_return_address(llvm::Value* new_addr);
  llvm::CallInst* call_intrinsic(const char* name, llvm::Type* retType);
  llvm::CallInst* call_intrinsic(const char* name, llvm::Type* retType, const std::vector<llvm::Type*>& paramTypes, const std::vector<llvm::Value *>& args);
  llvm::CallInst* call_external(void* func, llvm::Type* retType);
  llvm::CallInst* call_external(void* func, llvm::Type* retType, const std::vector<llvm::Type*>& paramTypes, const std::vector<llvm::Value *>& args);
  void store(llvm::Value* value, llvm::Value* addr);
  void map_phi_nodes(PhiNode* opto_node, llvm::PHINode* llvm_node);
  void epilog();
  Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name);
  ~Selector();
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP
