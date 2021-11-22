#ifndef CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP
#define CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP

#include "llvmGlobals.hpp"

struct OopInfo {
  enum Mask { managed_ptr, narrow_ptr };
  uint mask = 0;

  enum DataType {
    DATA_U1,
    DATA_I8,
    DATA_U8,
    DATA_I16,
    DATA_U16,
    DATA_I32,
    DATA_U32,
    DATA_I64,
    DATA_U64,
    DATA_S,
    DATA_D,
    DATA_X,
    DATA_VOID,
    DATA_LAST
  };
  DataType data_type;
  const static uint MANAGED_PTR = (1 << managed_ptr), NARROW_PTR = (1 << narrow_ptr);
  OopInfo() {}
  OopInfo(uint _mask_): mask(_mask_) {}

  bool isManagedPtr() { return mask & MANAGED_PTR; }
  bool isNarrowPtr() { return mask & NARROW_PTR; }
  void markManagedPtr() { mask |= MANAGED_PTR; }
  void markNarrowPtr() { mask |= NARROW_PTR; }
};

#endif // CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP