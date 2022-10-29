#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include <unordered_map>

#include "opto/phase.hpp"
#include "opto/node.hpp"
#include "opto/block.hpp"
#include "opto/machnode.hpp"
#include "utilities/growableArray.hpp"

#include "code_gen/llvmHeaders.hpp"
#include "code_gen/debugInfo_llvm.hpp"

class PhaseCFG;
class Block;
class LlvmCodeGen;
class PatchInfo;

struct PatchInfo {
  size_t size;
  PatchInfo(size_t s) : size(s) { }
};

class Selector : public Phase {
private:
  struct CacheEntry {
    llvm::Value* val = NULL;
    bool hit = false;
  };

  LlvmCodeGen* _cg;
  llvm::LLVMContext& _ctx;
  llvm::Module* _mod;
  llvm::Function* _func;
  llvm::IRBuilder<> _builder;
  std::vector<llvm::BasicBlock*> _blocks;
  std::vector<std::pair<PhiNode*, llvm::PHINode*>> _phiNodeMap;
  std::vector<Node*> _oops;
  std::vector<llvm::Instruction*> _narrow_oops;
  std::unordered_map<Node*, Node*> _derived_base;
  llvm::SmallVector<std::unique_ptr<CacheEntry>, 256> _cache;
  Block* _block;
  size_t _pointer_size;
  const char* _name;
  bool _is_fast_compression;
  std::vector<size_t> _nf_pos;
  std::unordered_map<llvm::BasicBlock*, ExceptionInfo> _exception_info;
  std::unordered_map<uint64_t, std::unique_ptr<PatchInfo>> _patch_info;
  std::vector<size_t> _param_to_arg;
  std::unordered_map<uintptr_t, DebugInfo::Type> _consts;

  void create_func();
  void create_blocks();
  void prolog();
  void select();
  llvm::Value* select_oop_or_klass(const Type* ty, bool oop, bool narrow);
  void complete_phi_nodes();
  void complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst);
  void locs_for_narrow_oops();

public:
  const static int NF_REGS = 6;
  Selector(LlvmCodeGen* code_gen, const char* name);
  void run();

  LlvmCodeGen* cg() { return _cg; }
  bool is_fast_compression() { return _is_fast_compression; }
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return _mod; }
  llvm::IRBuilder<>& builder() { return _builder; }
  llvm::Function* func() { return _func; }
  Block* block() { return _block; }
  llvm::BasicBlock* basic_block() { return basic_block(block()); }
  llvm::BasicBlock* basic_block(Block* block) { return _blocks[block->_pre_order - 1]; }
  llvm::Value* thread();
  unsigned pointer_size() const { return _pointer_size; }
  std::unordered_map<llvm::BasicBlock*, ExceptionInfo>& exception_info() { return _exception_info; }
  std::unordered_map<uintptr_t, DebugInfo::Type>& consts() { return _consts; }

  llvm::Type* type(BasicType btype) const;
  std::vector<llvm::Type*> types(const std::vector<llvm::Value*>& v) const;
  llvm::Value* null(llvm::Type* ty) { return llvm::Constant::getNullValue(ty); }
  llvm::Value* null(BasicType ty) { return null(type(ty)); }
  llvm::Value* get_ptr(uint64_t ptr, llvm::Type* type);
  llvm::Value* get_ptr(const void* ptr, llvm::Type* type);
  llvm::Value* get_ptr(uint64_t ptr, BasicType type);
  llvm::Value* get_ptr(const void* ptr, BasicType type);

  llvm::Value* gep(llvm::Value* base, llvm::Value* offset_in_bytes);
  llvm::Value* gep(llvm::Value* base, int offset_in_bytes);
  llvm::Value* tlab_top();
  llvm::Value* tlab_end();
  llvm::Value* load(llvm::Value* addr, BasicType ty);
  llvm::Value* load(llvm::Value* addr, llvm::Type* ty);
  void store(llvm::Value* value, llvm::Value* addr);
  llvm::AtomicCmpXchgInst* cmpxchg(llvm::Value* addr, llvm::Value* cmp, llvm::Value* val);
  llvm::Value* left_circular_shift(llvm::Value* arg, llvm::Value* shift, unsigned capacity);
  void stackmap(DebugInfo::Type type, size_t idx = 0, size_t patch_bytes = 0);
  llvm::Value* ret_addr(bool rethrow = false);

  llvm::Value* select_node(Node* node);
  llvm::Value* select_oper(MachOper *oper);
  llvm::Value* select_address(MachNode *mem_node);
  llvm::Value* select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt);
  void select_if(llvm::Value *pred, Node* node);

  std::unordered_map<uint64_t, std::unique_ptr<PatchInfo>>& patch_info() { return _patch_info; }
  std::vector<llvm::Value*> call_args(MachCallNode* node);
  void callconv_adjust(std::vector<llvm::Value*>& args);
  int param_to_arg(int param_num);
  llvm::FunctionCallee callee(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args = {});
  llvm::CallInst* call_C(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args = {});
  llvm::CallBase* call(MachCallNode* node, llvm::Type* retType, const std::vector<llvm::Value*>& args);

  llvm::Value* loadKlass_not_null(llvm::Value* obj);
  llvm::Value* decodeKlass_not_null(llvm::Value* narrow_klass);
  llvm::Value* decode_heap_oop(llvm::Value* narrow_oop, bool not_null);
  llvm::Value* encode_heap_oop(llvm::Value *oop, bool not_null);
  std::vector<Node*>& oops() { return _oops; }
  std::vector<llvm::Instruction*>& narrow_oops() { return _narrow_oops; }

  void map_phi_nodes(PhiNode* opto_node, llvm::PHINode* llvm_node);
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP
