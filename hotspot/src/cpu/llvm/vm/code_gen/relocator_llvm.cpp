#include "relocator_llvm.hpp"

#include <algorithm>

#include "utilities/debug.hpp"
#include "asm/macroAssembler.hpp"

#include "llvmCodeGen.hpp"

int Reloc::format() { return Assembler::imm_operand; }

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

RelocationHolder ConstReloc::getHolder() {
  assert(_con_addr, "address not set");
  return internal_word_Relocation::spec(_con_addr);
}

RelocationHolder InternalReloc::getHolder() {
  return Relocation::spec_simple(relocInfo::internal_word_type);
}

RelocationHolder PollReloc::getHolder() {
  return Relocation::spec_simple(relocInfo::poll_type);
}

OopReloc::OopReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg): ConstReloc(offset) {
  int oop_index = cg->masm()->oop_recorder()->allocate_oop_index((jobject)con);
  address con_addr = cg->masm()->address_constant((address)con);
  cg->cb()->consts()->relocate(con_addr, oop_Relocation::spec(oop_index));
  set_con_addr(con_addr);
}

MetadataReloc::MetadataReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg): ConstReloc(offset) {
  int md_index = cg->masm()->oop_recorder()->allocate_metadata_index((Metadata*)con);
  address con_addr = cg->masm()->address_constant((address)con);
  cg->cb()->consts()->relocate(con_addr, metadata_Relocation::spec(md_index));
  set_con_addr(con_addr);
}

SwitchReloc::SwitchReloc(size_t offset, SwitchInfo& si, LlvmCodeGen* cg): ConstReloc(offset) {
  auto& bo = cg->block_offsets();
  address con_addr = nullptr;
  for (const std::vector<llvm::BasicBlock*>& bbs : si) {
    size_t case_offset = (size_t)-1;
    for (llvm::BasicBlock* bb : bbs) {
      if (bo.count(bb)) {
        case_offset = bo.at(bb);
        break;
      }
    }
    assert(case_offset != (size_t)-1, "case BasicBlock not found");
    address addr = cg->masm()->address_constant(cg->masm()->addr_at(case_offset));
    con_addr = con_addr ? con_addr : addr;
    cg->cb()->consts()->relocate(addr, Relocation::spec_simple(relocInfo::internal_word_type));
  }
  set_con_addr(con_addr);
}

CallReloc::CallReloc(size_t offset, DebugInfo* di): Reloc(offset) {
  if (di->asRethrow()) {
    _kind = HotspotRelocInfo::RelocRuntimeCall;
  } else if (di->asDynamicCall()) {
    _kind = HotspotRelocInfo::RelocVirtualCall;
  } else {
    ciMethod* method = di->asCall()->scope_info->cjn->_method;
    bool is_runtime = method == NULL;
    if (is_runtime) {
      _kind = HotspotRelocInfo::RelocRuntimeCall;
    } else if (method->is_static()) {
      _kind = HotspotRelocInfo::RelocStaticCall;
    } else {
      _kind = HotspotRelocInfo::RelocOptVirtualCall;
    }
  }
}

VirtualCallReloc::VirtualCallReloc(size_t offset, DynamicCallDebugInfo* di, address ic_addr): CallReloc(offset, di), _IC_addr(ic_addr) {}

void LlvmRelocator::add_float(size_t offset, float con) {
  FloatReloc* rel = new FloatReloc(offset, con);
  relocs.push_back(rel);
  f_relocs.push_back(rel);
}

void LlvmRelocator::add_double(size_t offset, double con, bool align) {
  DoubleReloc* rel = new DoubleReloc(offset, con);
  relocs.push_back(rel);
  (align ? da_relocs : d_relocs).push_back(rel);
}

void LlvmRelocator::floats_to_cb() {
  MacroAssembler* masm = cg()->masm();
  for (DoubleReloc* rel : da_relocs) {
    rel->set_con_addr(masm->double_constant(rel->con()));
    masm->long_constant(0);
  }
  for (DoubleReloc* rel : d_relocs) {
    rel->set_con_addr(masm->double_constant(rel->con()));
  }
  for (FloatReloc* rel : f_relocs) {
    rel->set_con_addr(masm->float_constant(rel->con()));
  }
}

void LlvmRelocator::apply_relocs() {
  std::sort(relocs.begin(), relocs.end(),
    [](const Reloc* a, const Reloc* b) { return a->offset() < b->offset(); });
  for (Reloc* rel : relocs) {
    address addr = cg()->addr(rel->offset());
    cg()->cb()->insts()->relocate(addr, rel->getHolder(), rel->format());
  }
}