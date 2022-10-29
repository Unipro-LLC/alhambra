#include "debugInfo_llvm.hpp"

#include "opto/block.hpp"
#include "opto/runtime.hpp"
#include "llvmCodeGen.hpp"

std::unique_ptr<DebugInfo> DebugInfo::create(uint64_t id, LlvmCodeGen* cg) {
  Type ty = type(id);
  if (ty == StaticCall || ty == DynamicCall) {
    PatchInfo* pi = cg->selector().patch_info().at(id).get();
    if (ty == StaticCall)
      return std::make_unique<StaticCallDebugInfo>(pi);
    return std::make_unique<DynamicCallDebugInfo>(pi);
  }
  switch (ty) {
    default: ShouldNotReachHere();
    case SafePoint: return std::make_unique<SafePointDebugInfo>();
    case Poll: return std::make_unique<PollDebugInfo>();
    case Other: return std::make_unique<OtherDebugInfo>();
    case Oop: return std::make_unique<OopDebugInfo>();
    case Metadata: return std::make_unique<MetadataDebugInfo>();
  }
}

void patch_movabs_rax(address& pos, uintptr_t x) {
  *(pos++) = 0x48;
  *(pos++) = 0xB8;
  *(uintptr_t*)pos = x;
  pos += wordSize;
}

void PollDebugInfo::handle(LlvmCodeGen* cg) {
  cg->relocator().add(new PollReloc(pc_offset));
}

void SwitchDebugInfo::handle(LlvmCodeGen* cg) {
  SwitchReloc* rel = new SwitchReloc(pc_offset, Cases, cg);
  cg->relocator().add(rel);
}

void OopDebugInfo::handle(LlvmCodeGen* cg) {
  address pos = cg->addr(pc_offset);
  assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  uintptr_t con = *(uintptr_t*)(pos + NativeMovConstReg::data_offset);
  con = decode(con);
  Reloc* rel = new OopReloc(pc_offset, con, cg);
  cg->relocator().add(rel);
}

void MetadataDebugInfo::handle(LlvmCodeGen* cg) {
  address pos = cg->addr(pc_offset);
  assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  uintptr_t con = *(uintptr_t*)(pos + NativeMovConstReg::data_offset);
  con = decode(con);
  Reloc* rel = new MetadataReloc(pc_offset, con, cg);
  cg->relocator().add(rel);
}

void CallDebugInfo::handle(LlvmCodeGen* cg) {
  address code_start = cg->code_start();
  PatchInfo* pi = patch_info;
  address next_inst = code_start + pc_offset;
  address call_site = next_inst - sizeof(uint32_t);
  call_site = (address)((intptr_t)call_site & -BytesPerInt); // should be aligned by BytesPerInt
  address pos, nop_end = call_site - NativeCall::displacement_offset, call_start = nop_end, ic_addr;

  DynamicCallDebugInfo* dcdi = asDynamicCall();
  if (dcdi) {
    ic_addr = pos = nop_end -= NativeMovConstReg::instruction_size;
    patch_movabs_rax(pos, (uintptr_t)Universe::non_oop_word());
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

  while (pos < next_inst) {
    *(pos++) = NativeInstruction::nop_instruction_code;
  }

  Reloc* rel = dcdi ? new VirtualCallReloc(call_offset, dcdi, ic_addr) : new CallReloc(call_offset, this);
  cg->relocator().add(rel);

  Block* b = cg->C->cfg()->get_block_for_node(scope_info->cn);
  if (b->end()->is_Catch()) {
    ExceptionInfo& ei = cg->selector().exception_info().at(cg->selector().basic_block(b));
    GrowableArray<intptr_t> handler_bcis(ei.size());
    GrowableArray<intptr_t> handler_pcos(ei.size());
    for (const auto& pair : ei) {
      handler_bcis.append(pair.second);
      handler_pcos.append(cg->block_offsets().at(pair.first));
    }
    cg->C->handler_table()->add_subtable(pc_offset, &handler_bcis, NULL, &handler_pcos);
  }
}
