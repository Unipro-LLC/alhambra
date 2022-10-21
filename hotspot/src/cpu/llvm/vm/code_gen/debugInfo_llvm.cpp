#include "debugInfo_llvm.hpp"

#include "opto/block.hpp"
#include "opto/runtime.hpp"
#include "llvmCodeGen.hpp"

std::unique_ptr<DebugInfo> DebugInfo::create(uint64_t id, LlvmCodeGen* cg) {
  auto& patch_info = cg->selector().patch_info();
  PatchInfo* pi = patch_info.count(id) ? patch_info[id].get() : nullptr;
  switch (type(id)) {
    case SafePoint: return std::make_unique<SafePointDebugInfo>();
    case Call: return std::make_unique<CallDebugInfo>(pi);
    case StaticCall: return std::make_unique<StaticCallDebugInfo>(pi);
    case DynamicCall: return std::make_unique<DynamicCallDebugInfo>(pi);
    case PatchBytes: return std::make_unique<PatchBytesDebugInfo>();
    case Oop: return std::make_unique<OopDebugInfo>();
    case Metadata: return std::make_unique<MetadataDebugInfo>();
    case Exception: return std::make_unique<ExceptionDebugInfo>();
    default: ShouldNotReachHere();
  }
}

bool DebugInfo::less(DebugInfo* other) {
  assert(type() != other->type(), "same types");
  if (block_start()) {
    assert(other->block_can_start() || other->block_can_end(), "wrong type");
    if (other->block_can_start()) return true;
    return false;
  }
  if (block_can_start()) {
    assert(other->block_start() || other->block_can_end(), "wrong type");
    return false;
  }
  if (block_can_end()) {
    assert(other->block_start() || other->block_can_start(), "wrong type");
    return true;
  }
  ShouldNotReachHere();
}

void DebugInfo::patch(address& pos, const std::vector<byte>& inst) {
  for (size_t i = 0; i < inst.size(); ++i) {
    *(pos++) = inst[i];
  }
}

void SafePointDebugInfo::patch_movabs_rax(address& pos, uintptr_t x) {
  *(pos++) = 0x48;
  *(pos++) = 0xB8;
  *(uintptr_t*)pos = x;
  pos += wordSize;
}

void SafePointDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  cg->relocator().add(new PollReloc(pc_offset));
}

void SwitchDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  SwitchReloc* rel = new SwitchReloc(pc_offset, Cases, cg);
  cg->relocator().add(rel);
}

void OopDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  address pos = cg->addr(pc_offset);
  assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  uintptr_t con = *(uintptr_t*)(pos + NativeMovConstReg::data_offset);
  con = decode(con);
  Reloc* rel = new OopReloc(pc_offset, con, cg);
  cg->relocator().add(rel);
}

void MetadataDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  address pos = cg->addr(pc_offset);
  assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  uintptr_t con = *(uintptr_t*)(pos + NativeMovConstReg::data_offset);
  con = decode(con);
  Reloc* rel = new MetadataReloc(pc_offset, con, cg);
  cg->relocator().add(rel);
}

void CallDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  address code_start = cg->code_start();
  PatchInfo* pi = patch_info;
  if (pi->size != 0) {
    SpillPatchInfo* spi = pi->asSpill();
    size_t max_spill = cg->selector().max_spill(), spill_size = spi ? max_spill - spi->spill_size : max_spill;
    bool patch_spill = max_spill && spill_size;
    address next_inst = code_start + pc_offset;
    address call_site = next_inst - sizeof(uint32_t);

    if (patch_spill) {
      call_site -= ADD_RSP_SIZE;
    }

    JavaCallDebugInfo* jcdi = asJavaCall();
    if (jcdi) {
      call_site = (address)((intptr_t)call_site & -BytesPerInt); // should be aligned by BytesPerInt
    }

    address pos, nop_end = call_site - NativeCall::displacement_offset, call_start = nop_end, ic_addr;

    DynamicCallDebugInfo* dcdi = asDynamicCall();
    if (dcdi) {
      ic_addr = pos = nop_end -= NativeMovConstReg::instruction_size;
      patch_movabs_rax(pos, (uintptr_t)Universe::non_oop_word());
    }

    if (patch_spill) {
      std::vector<byte> SUB_RSP = SUB_x_RSP(spill_size);
      pos = nop_end -= SUB_RSP.size();
      patch(pos, SUB_RSP);
    }

    pos = next_inst - pi->size;
    while (pos < nop_end) {
      *(pos++) = NativeInstruction::nop_instruction_code;
    }

    pos = call_start;
    address ret_addr = pos + NativeCall::return_address_offset;
    size_t call_offset = pos - code_start;
    *(pos++) = NativeCall::instruction_code;
    *(uint32_t*)pos = scope_info->cn->entry_point() - ret_addr;
    pos += sizeof(uint32_t);
    pc_offset = pos - code_start;

    if (patch_spill) {
      std::vector<byte> ADD_RSP = ADD_x_RSP(spill_size);
      patch(pos, ADD_RSP);
    }

    while (pos < next_inst) {
      *(pos++) = NativeInstruction::nop_instruction_code;
    }

    Reloc* rel = dcdi ? new VirtualCallReloc(call_offset, dcdi, ic_addr) : new CallReloc(call_offset, this);
    cg->relocator().add(rel);

    ThrowScopeInfo* tsi = scope_info->asThrow();
    if (tsi) {
      ExceptionInfo& ei = cg->selector().exception_info().at(tsi->bb);
      GrowableArray<intptr_t> handler_bcis(ei.size());
      GrowableArray<intptr_t> handler_pcos(ei.size());
      for (const auto& pair : ei) {
        handler_bcis.append(pair.second);
        handler_pcos.append(cg->block_offsets().at(pair.first));
      }
      cg->C->handler_table()->add_subtable(pc_offset, &handler_bcis, NULL, &handler_pcos);
    }
  }
}

void ExceptionDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  BlockStartDebugInfo* bsdi = cg->debug_info()[idx - 1]->asBlockStart();
  assert(bsdi, "should be BlockStart");
  address pos = cg->code_start() + pc_offset, bs = cg->code_start() + bsdi->pc_offset;
  while (--pos >= bs) {
    *(pos + CallDebugInfo::ADD_RSP_SIZE) = *pos;
  }
  std::vector<byte> ADD_RSP = ADD_x_RSP(cg->selector().max_spill());
  patch(bs, ADD_RSP);
}
