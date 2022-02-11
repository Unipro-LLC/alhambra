#ifndef CPU_LLVM_VM_SELECTOR_LLVM_HPP
#define CPU_LLVM_VM_SELECTOR_LLVM_HPP

#include <unordered_map>

#include "opto/phase.hpp"
#include "opto/node.hpp"
#include "opto/block.hpp"
#include "opto/machnode.hpp"
#include "utilities/growableArray.hpp"

#include "code_gen/llvmHeaders.hpp"
#include "code_gen/oopInfo.hpp"

class PhaseCFG;
class Block;
class LlvmCodeGen;

class Selector : public Phase {
private:
  struct CacheEntry {
    llvm::Value* val = NULL;
    bool hit = false;
  };

  const int NF_REGS = 6;

  LlvmCodeGen* _cg;
  llvm::LLVMContext& _ctx;
  llvm::Module* _mod;
  llvm::Function* _func;
  llvm::IRBuilder<> _builder;
  llvm::Value* _thread = nullptr;
  llvm::Type* _landing_pad_ty;
  GrowableArray<llvm::BasicBlock*> _blocks;
  std::vector<std::pair<PhiNode*, llvm::PHINode*>> _phiNodeMap;
  std::unordered_map<llvm::Value*, std::unique_ptr<OopInfo>> _oop_info;
  std::unordered_map<Node*, Node*> _derived_base;
  llvm::SmallVector<std::unique_ptr<CacheEntry>, 256> _cache;
  Block* _block;
  size_t _pointer_size;
  const char* _name;
  bool _is_fast_compression;
  std::vector<size_t> _nf_pos;
  std::unordered_map<Block*, std::vector<Block*>> _handler_table;

  void create_func();
  void create_blocks();
  void prolog();
  void select();
  void complete_phi_nodes();
  void complete_phi_node(Block *case_block, Node* case_val, llvm::PHINode *phi_inst);

public:
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
  llvm::BasicBlock* basic_block(Block* block) { return _blocks.at(block->_pre_order - 1); }
  llvm::Value* thread() const { return _thread; }
  unsigned pointer_size() const { return _pointer_size; }
  std::unordered_map<Block*, std::vector<Block*>>& handler_table() { return _handler_table; }
  llvm::Type* landing_pad_ty() { return _landing_pad_ty; }

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
  void replace_return_address(llvm::Value* new_addr);
  void mark_inblock();

  llvm::Value* select_node(Node* node);
  llvm::Value* select_oper(MachOper *oper);
  llvm::Value* select_address(MachNode *mem_node);
  llvm::Value* select_condition(Node* cmp, llvm::Value* a, llvm::Value* b, bool is_and, bool flt);
  void select_if(llvm::Value *pred, Node* node);

  void mark_mptr(llvm::Value* oop);
  void mark_nptr(llvm::Value* oop);
  void mark_dptr(llvm::Value* ptr, llvm::Value* base);
  OopInfo* oop_info(llvm::Value* oop) { return _oop_info.count(oop) ? _oop_info[oop].get() : NULL; }
  Node* derived_base(Node* derived) { return _derived_base.count(derived) ? _derived_base[derived] : NULL; }
  Node* find_derived_base(Node* derived);

  std::vector<llvm::Value*> call_args(MachCallNode* node);
  void callconv_adjust(std::vector<llvm::Value*>& args);
  int param_to_arg(int param_num);
  llvm::FunctionCallee callee(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args = {});
  llvm::CallInst* call_C(const void* func, llvm::Type* retType, const std::vector<llvm::Value*>& args = {});
  llvm::CallInst* call(MachCallNode* node, llvm::Type* retType, const std::vector<llvm::Value*>& args);

  llvm::Value* loadKlass_not_null(llvm::Value* obj);
  llvm::Value* decodeKlass_not_null(llvm::Value* narrow_klass);
  llvm::Value* decode_heap_oop(llvm::Value* narrow_oop, bool not_null);
  llvm::Value* encode_heap_oop(llvm::Value *oop, bool not_null);

  void map_phi_nodes(PhiNode* opto_node, llvm::PHINode* llvm_node);
};

#endif // CPU_LLVM_VM_SELECTOR_LLVM_HPP
