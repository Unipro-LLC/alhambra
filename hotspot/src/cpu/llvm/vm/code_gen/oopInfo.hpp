#ifndef CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP
#define CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP

struct OopInfo {
  enum Mask { managed_ptr, narrow_ptr, derived_ptr };
  uint mask = 0;
  const static uint MANAGED_PTR = (1 << managed_ptr), 
                    NARROW_PTR  = (1 << narrow_ptr) ,
                    DERIVED_PTR = (1 << derived_ptr);
  OopInfo() {}
  OopInfo(uint _mask_): mask(_mask_) {}

  bool isManagedPtr() { return mask & MANAGED_PTR; }
  bool isNarrowPtr() { return mask & NARROW_PTR; }
  bool isDerivedPtr() { return mask & DERIVED_PTR; }
  void markManagedPtr() { mask |= MANAGED_PTR; }
  void markNarrowPtr() { mask |= NARROW_PTR; }
  void markDerivedPtr() { mask |= DERIVED_PTR; }
};

#endif // CPU_LLVM_VM_CODE_GEN_OOPINFO_HPP