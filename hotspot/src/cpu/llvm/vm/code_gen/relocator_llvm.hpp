#ifndef CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP

#include <vector>

class MacroAssembler;
class Reloc;
class Selector;

class LLVMRelocator {
private:
  Selector* _sel;
  std::vector<Reloc*> relocs;

  Selector* sel() { return _sel; }
public:
  void apply_relocs(MacroAssembler* masm);
  LLVMRelocator(Selector* sel) : _sel(sel) {}
};

#endif // CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP