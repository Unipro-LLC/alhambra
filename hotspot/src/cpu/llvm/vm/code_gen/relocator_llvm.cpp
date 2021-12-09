#include "relocator_llvm.hpp"

#include <algorithm>

#include "utilities/debug.hpp"
#include "asm/macroAssembler.hpp"

#include "llvmCodeGen.hpp"

RelocationHolder CallReloc::getHolder() {
  switch (kind()) {
    case HotspotRelocInfo::RelocOptVirtualCall: return opt_virtual_call_Relocation::spec();
    case HotspotRelocInfo::RelocStaticCall:     return static_call_Relocation::spec();
    case HotspotRelocInfo::RelocRuntimeCall:    return runtime_call_Relocation::spec();
    default: ShouldNotReachHere();     return Relocation::spec_simple(relocInfo::none);
  }
}

RelocationHolder VirtualCallReloc::getHolder() {
  assert(_IC_addr, "address not set");
  return virtual_call_Relocation::spec(_IC_addr);
}

RelocationHolder FPReloc::getHolder() {
  assert(_con_addr, "address not set");
  return internal_word_Relocation::spec(_con_addr);
}

void LlvmRelocator::add(DebugInfo* di, size_t offset) {
  CallReloc* rel;
  switch (di->type()) {
    case DebugInfo::DynamicCall: {
      rel = new VirtualCallReloc(offset);
      break;
    }
    case DebugInfo::StaticCall: {
      ciMethod* method = di->asCallDebugInfo()->scope_info->cjn->_method;
      bool is_runtime = method == NULL;
      HotspotRelocInfo reloc_info;
      if (is_runtime) {
        reloc_info = HotspotRelocInfo::RelocRuntimeCall;
      } else if (method->is_static()) {
        reloc_info = HotspotRelocInfo::RelocStaticCall;
      } else {
        reloc_info = HotspotRelocInfo::RelocOptVirtualCall;
      }
      rel = new CallReloc(reloc_info, offset);
      break;
    }
    case DebugInfo::Rethrow: rel = new CallReloc(HotspotRelocInfo::RelocRuntimeCall, offset); break;
    default: ShouldNotReachHere();
  }
  relocs.push_back(rel);
}

void LlvmRelocator::add_float(size_t offset, float con) {
  FloatReloc* rel = new FloatReloc(offset, con);
  relocs.push_back(rel);
}

void LlvmRelocator::add_double(size_t offset, double con) {
  DoubleReloc* rel = new DoubleReloc(offset, con);
  relocs.push_back(rel);
}

void LlvmRelocator::apply_relocs(MacroAssembler* masm) {
  std::sort(relocs.begin(), relocs.end(),
    [](const Reloc* a, const Reloc* b) { return a->offset() < b->offset(); });

  assert(masm->code_section() == cg()->cb()->insts(), "wrong section");
  for (Reloc* rel : relocs) {
    if (rel->asFPReloc()) {
      FPReloc* fp_rel = rel->asFPReloc();
      address con_addr = nullptr;
      if (rel->asFloatReloc()) {
        FloatReloc* f_rel = rel->asFloatReloc();
        con_addr = masm->float_constant(f_rel->con());
      } else if (rel->asDoubleReloc()) {
        DoubleReloc* d_rel = rel->asDoubleReloc();
        assert(d_rel, "no other choice");
        con_addr = masm->double_constant(d_rel->con());
      }
      fp_rel->set_con_addr(con_addr);
    } else {
      assert(rel->asCallReloc(), "no other choice");
      masm->set_code_section(cg()->cb()->insts());
      if (rel->asVirtualCallReloc()) {
        VirtualCallReloc* vc_rel = rel->asVirtualCallReloc();
        vc_rel->set_IC_addr(masm->addr_at(vc_rel->offset() - NativeMovConstReg::instruction_size));
      }
    }
    address addr = masm->addr_at(rel->offset());
    masm->code_section()->relocate(addr, rel->getHolder());
  }
}