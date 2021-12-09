#ifndef CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP
#define CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP

#include "selector_llvm.hpp"
#include "scopeDescriptor.hpp"
#include "relocator_llvm.hpp"
#include "debugInfo_llvm.hpp"
#include "stack_llvm.hpp"

#include "llvmHeaders.hpp"

class LlvmMethod;

class Compile;
class CodeBuffer;

class LlvmCodeGen {
 public:
  LlvmCodeGen(LlvmMethod* method, Compile* c, const char* name);

  Compile* C;
  CodeBuffer* cb() { return _cb; }
  llvm::LLVMContext& ctx() { return _ctx; }
  llvm::Module* mod() { return _mod; }
  LlvmMethod* method() { return _method; }
  Selector& selector() { return _selector; }
  ScopeDescriptor& scope_descriptor() { return _scope_descriptor; } 
  LlvmRelocator& relocator() { return _relocator; }
  std::vector<std::unique_ptr<DebugInfo>>& debug_info() { return _debug_info; }
  LlvmStack& stack() { return _stack; }
  StackMapParser* sm_parser() { return _sm_parser.get(); }
  size_t patch_bytes(DebugInfo::Type type) const;
  unsigned nof_monitors() const { return _nof_monitors; }
  bool has_exceptions() const { return _has_exceptions; }
  unsigned nof_Java_calls() const { return _nof_Java_calls; }
  unsigned nof_to_interp_stubs() const { return _nof_to_interp_stubs; }
  std::vector<Block*>& blocks() { return _blocks; }
  bool has_tail_jump() const { return _has_tail_jump; }
  unsigned nof_consts() const { return _nof_consts; }
  address code_start() { return _code_start; }
  address code_end() { return _code_end; }

  void run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV);
  void process_object_file(const llvm::object::ObjectFile& obj_file, const char *obj_file_start, address& code_start, uint64_t& code_size);
  void fill_code_buffer(address src, uint64_t size, int& exc_offset, int& deopt_offset);
  bool cmp_ideal_Opcode(Node* n, int opcode) const { return n->is_Mach() && n->as_Mach()->ideal_Opcode() == opcode; }
  
 private:
  CodeBuffer* _cb;
  llvm::LLVMContext _ctx;
  std::unique_ptr<llvm::Module> _mod_owner;
  llvm::Module* _mod;
  LlvmMethod* _method;
  Selector _selector;
  ScopeDescriptor _scope_descriptor;
  LlvmRelocator _relocator;
  std::vector<std::unique_ptr<DebugInfo>> _debug_info;
  LlvmStack _stack;
  std::unique_ptr<StackMapParser> _sm_parser = nullptr;
  unsigned _nof_monitors = 0;
  bool _has_exceptions = false;
  unsigned _nof_Java_calls = 0;
  unsigned _nof_to_interp_stubs = 0;
  std::vector<Block*> _blocks;
  bool _has_tail_jump = false;
  unsigned _nof_consts = 0;
  address _code_start;
  address _code_end;

  void patch(address& pos, const std::vector<byte>& inst);
  void patch_call(std::vector<std::unique_ptr<DebugInfo>>::iterator it, std::unordered_map<size_t, uint32_t>& call_offsets);
  void patch_rethrow_exception(std::vector<std::unique_ptr<DebugInfo>>::iterator it);
  void patch_tail_jump(std::vector<std::unique_ptr<DebugInfo>>::iterator it);
  void add_stubs(int& exc_offset, int& deopt_offset);
  void fill_handler_table(const std::vector<size_t>& block_offsets, const std::unordered_map<size_t, uint32_t>& call_offsets);
};

#endif // CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP
