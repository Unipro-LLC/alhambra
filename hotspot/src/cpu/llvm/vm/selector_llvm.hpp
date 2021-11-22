#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include "opto/phase.hpp"
#include "opto/node.hpp"
#include "opto/block.hpp"
#include "opto/machnode.hpp"
#include "utilities/growableArray.hpp"
#include <unordered_map>
#include "code_gen/debugInfo.hpp"
#include "code_gen/oopInfo.hpp"
#include "code_gen/relocator_llvm.hpp"
#include "code_gen/scopeDescriptor.hpp"
#include "code_gen/llvmGlobals.hpp"

class PhaseCFG;
class Block;
class ScopeDescriptor;

class Selector : public Phase {
public:
  Compile* C;
private:
  struct CacheEntry {
    llvm::Value* val = NULL;
    bool hit = false;
  };

  const int NF_REGS = 6;

  llvm::Function* _func;
  llvm::LLVMContext& _ctx;
  llvm::IRBuilder<> _builder;
  llvm::Module* _mod;
  llvm::Value* _thread;
  llvm::Value* _SP;
  llvm::Value* _FP;
  uint _frame_size;
  llvm::Value* _last_Java_fp;
  llvm::Value* _last_Java_sp;
  llvm::Value* _tlab_top = nullptr;
  llvm::Value* _tlab_end = nullptr;
  llvm::Value* _null = nullptr;
  GrowableArray<llvm::BasicBlock*> _blocks;
  std::vector<std::pair<PhiNode*, llvm::PHINode*>> _phiNodeMap;
  std::vector<MachSafePointNode*> _sfns;
  std::unordered_map<MachSafePointNode*, DebugInfo> _debug_info;
  std::unordered_map<llvm::Value*, OopInfo> _oop_info;
  LLVMRelocator _relocator;
  ScopeDescriptor _scope_descriptor;
  std::unique_ptr<StackMapParser> _sm_parser;
  llvm::SmallVector<std::unique_ptr<CacheEntry>, 256> _cache;
  Block* _block;
  unsigned _pointer_size;
  unsigned _monitors_num;
  unsigned _max_stack;
  const char* _name;
  bool _is_fast_compression;
  std::vector<unsigned> _nf_pos;

  bool is_fast_compression() { return _is_fast_compression; }
  void create_func();
  void create_blocks();
  void prolog();
  void select();
  void select_block(Block* block);
  void select_root_block();
  llvm::Value* select_const(Node* n);
  llvm::Value* create_statepoint(MachCallNode* node, llvm::FunctionType* funcTy, const std::vector<llvm::Value*>& args);
  void complete_phi_nodes();
  void complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst);
  unsigned count_monitors() const;
  unsigned count_max_stack() const;

public:
  llvm::Type* type(BasicType btype) const;
  llvm::Value* select_node(Node* node);
  llvm::Value* select_oper(MachOper *oper);
  llvm::Value* select_node_or_const(Node* node);
  llvm::Value* get_ptr(intptr_t ptr, llvm::Type* type);
  llvm::Value* get_ptr(const void* ptr, llvm::Type* type);
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return _mod; }
  llvm::IRBuilder<>& builder() { return _builder; }
  llvm::Function* func() { return _func; }
  Block* block() { return _block; }
  llvm::BasicBlock* basic_block(Block* block) { return _blocks.at(block->_pre_order - 1); }
  llvm::Value* thread() { return _thread; }
  llvm::Value* tlab_top();
  llvm::Value* tlab_end();
  llvm::Value* null();
  llvm::Value* FP() const { return _FP; }
  llvm::Value* SP() const { return _SP; }
  uint frame_size() const { return _frame_size; }
  unsigned pointer_size() const { return _pointer_size; }
  size_t monitor_size() const { return BasicObjectLock::size() * wordSize; }
  unsigned monitors_num() { return _monitors_num; }
  size_t max_stack() { return _max_stack; }
  std::unordered_map<MachSafePointNode*, DebugInfo>& debug_info() { return _debug_info; }
  MachSafePointNode* sfns(uint i) const { return _sfns[i]; }
  DebugInfo& debug_info(MachSafePointNode* sfn) { assert(debug_info().count(sfn), "no such node in debug_info");  return _debug_info[sfn]; }
  void mark_mptr(llvm::Value* oop);
  void mark_nptr(llvm::Value* oop);
  OopInfo& oop_info(llvm::Value* oop) { assert(_oop_info.count(oop), "no such oop in oop_info");  return _oop_info[oop]; }
  LLVMRelocator& relocator() { return _relocator; }
  ScopeDescriptor* scope_descriptor() { return &_scope_descriptor; }
  StackMapParser* sm_parser() { return _sm_parser.get(); }
  void init_sm_parser(llvm::ArrayRef<uint8_t> sm) { _sm_parser = std::make_unique<StackMapParser>(sm); }
  llvm::Value* gep(llvm::Value* base, llvm::Value* offset_in_bytes);
  llvm::Value* gep(llvm::Value* base, int offset_in_bytes);
  llvm::Value* select_address(MachNode *mem_node);
  llvm::Value* select_address(MachNode *mem_node, int& op_index);
  llvm::Value* select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt);
  void callconv_adjust(std::vector<llvm::Value*>& args);
  int param_to_arg(int param_num);
  void select_if(llvm::Value *pred, Node* node);
  void replace_return_address(llvm::Value* new_addr);
  std::vector<llvm::Type*> types(const std::vector<llvm::Value*>& v) const;
  llvm::CallInst* call_intrinsic(const char* name, llvm::Type* retType);
  llvm::CallInst* call_intrinsic(const char* name, llvm::Type* retType, const std::vector<llvm::Value *>& args);
  llvm::CallInst* call_external(const void* func, llvm::Type* retType);
  llvm::CallInst* call_external(const void* func, llvm::Type* retType, const std::vector<llvm::Value *>& args);
  llvm::CallInst* call(MachCallNode* node, llvm::Type* retType, std::vector<llvm::Value*>& args);
  llvm::Value* load(llvm::Value* addr, BasicType ty);
  llvm::Value* load(llvm::Value* addr, llvm::Type* ty);
  void store(llvm::Value* value, llvm::Value* addr);
  llvm::AtomicCmpXchgInst* cmpxchg(llvm::Value* addr, llvm::Value* cmp, llvm::Value* val);
  llvm::Value* decodeKlass_not_null(llvm::Value* narrow_klass);
  llvm::Value* decode_heap_oop(llvm::Value* narrow_oop, bool not_null);
  void map_phi_nodes(PhiNode* opto_node, llvm::PHINode* llvm_node);
  int32_t mon_offset(int32_t index);
  int32_t mon_obj_offset(int32_t index);
  int32_t mon_header_offset(int32_t index);
  void epilog();
  Selector(Compile* comp, llvm::LLVMContext& ctx, llvm::Module* mod, const char* name);
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP
