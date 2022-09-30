#ifndef CPU_LLVM_VM_CODE_GEN_METHOD_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_METHOD_LLVM_HPP

#include "utilities/globalDefinitions.hpp"

class Compile;

class LlvmMethod {
public:
  LlvmMethod(Compile* C, const char* target_name);
  static const char* method_name(const char* klass, const char* method);
  size_t frame_size() { return _frame_size; }
  int vep_offset() { return _vep_offset; }
  int deopt_offset() { return _deopt_offset; }
  int exc_offset() { return _exc_offset; }
  int orig_pc_offset() { return _orig_pc_offset; }
private:
  size_t _frame_size = wordSize;
  int _vep_offset = 0;
  int _deopt_offset = 0;
  int _exc_offset = 0;
  int _orig_pc_offset = 0;
};

#endif // CPU_LLVM_VM_CODE_GEN_METHOD_LLVM_HPP