#ifndef CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP

#include "utilities/globalDefinitions.hpp"
#include <unordered_map>

#include "llvmHeaders.hpp"

namespace llvm {
  class Value;
}

class LlvmCodeGen;
class MachCallNode;
class MachSafePointNode;

//                                                     SP(stub)              SP(method)
//                                                        v                       v
// prev sp|ret_addr(x86)|FP|ret_addr(llvm)|orig_pc(method)|mon0|...|mon_n-1|spills|
//        |                          frame_size                                   |

class LlvmStack {
private:
  llvm::Value* _FP;  
  llvm::Value* _SP;
  unsigned _nof_monitors;
  size_t _frame_size;
  int32_t _orig_pc_offset;
  int32_t _ret_addr_offset;
  int32_t _mon_offset;
  size_t _max_spill = 0;
  std::unordered_map<MachCallNode*, size_t> spill_sizes;

  LlvmCodeGen* _cg;
public:
  LlvmStack(LlvmCodeGen* code_gen) : _cg(code_gen) {}
  LlvmCodeGen* cg() const { return _cg; }

  size_t calc_alloc();

  llvm::Value* FP() const { return _FP; }
  void set_FP(llvm::Value* FP) { _FP = FP; }

  size_t frame_size(MachSafePointNode* sfn = nullptr) const;
  void set_frame_size(size_t frame_size) { _frame_size = frame_size; }

  size_t monitor_size() const;

  int32_t mon_offset(int32_t index) const;

  int32_t mon_obj_offset(int32_t index) const;

  int32_t mon_header_offset(int32_t index) const;

  int32_t unext_offset(MachSafePointNode* sfn) const { return frame_size(sfn) - 2 * wordSize; }

  int32_t unextended_mon_offset(MachSafePointNode* sfn, int idx) const { return unext_offset(sfn) + mon_offset(idx); }

  int32_t unextended_mon_obj_offset(MachSafePointNode* sfn, int idx) const;

  int32_t unext_orig_pc_offset() { return frame_size() - 2 * wordSize + _orig_pc_offset; }

  int32_t ret_addr_offset() { return _ret_addr_offset; }

  size_t count_spills(MachCallNode* node, const std::vector<llvm::Value*>& args);

  size_t max_spill() const { return _max_spill; }

  int32_t offset(MachSafePointNode* sfn, LocationAccessor la);
};
#endif // CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP