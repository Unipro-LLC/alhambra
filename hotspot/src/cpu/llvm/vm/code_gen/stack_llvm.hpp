#ifndef CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP

#include "utilities/globalDefinitions.hpp"

namespace llvm {
  class Value;
}

class LlvmCodeGen;

//                                                                                      SP
//                                                                                      v
// prev sp|arg spills(?)|ret_addr|FP|tail jump(optional)|orig_pc|mon0|...|mon_n-1|spills|
//        |                                  frame_size                                 |


class LlvmStack {
private:
  llvm::Value* _FP;  
  llvm::Value* _SP;
  unsigned _nof_monitors;
  size_t _frame_size;
  int32_t _orig_pc_offset;
  int32_t _mon_offset;

  LlvmCodeGen* _cg;
public:
  LlvmStack(LlvmCodeGen* code_gen) : _cg(code_gen) {}
  LlvmCodeGen* cg() const { return _cg; }

  size_t calc_alloc();

  llvm::Value* FP() const { return _FP; }
  void set_FP(llvm::Value* FP) { _FP = FP; }

  size_t frame_size() const { return _frame_size; }
  void set_frame_size(size_t frame_size) { _frame_size = frame_size; }

  size_t monitor_size() const;

  int32_t mon_offset(int32_t index) const;

  int32_t mon_obj_offset(int32_t index) const;

  int32_t mon_header_offset(int32_t index) const;

  int32_t unext_offset() const { return frame_size() - 2 * wordSize; } 

  int32_t unextended_mon_offset(int idx) const { return unext_offset() + mon_offset(idx); }

  int32_t unextended_mon_obj_offset(int idx) const;

  int32_t orig_pc_offset() { return _orig_pc_offset; }

  int32_t unext_orig_pc_offset() { return unext_offset() + _orig_pc_offset; }
};

#endif // CPU_LLVM_VM_CODE_GEN_STACK_LLVM_HPP