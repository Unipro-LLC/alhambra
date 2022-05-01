#include "debugInfo_llvm.hpp"

#include "opto/block.hpp"
#include "opto/runtime.hpp"
#include "llvmCodeGen.hpp"

std::vector<byte> TailJumpDebugInfo::MOV_RDX = { Assembler::REX_W,  NativeMovRegMem::instruction_code_mem2reg, 0x55, -wordSize };
std::vector<byte> TailJumpDebugInfo::MOV_R10 = { Assembler::REX_WR, NativeMovRegMem::instruction_code_mem2reg, 0x55, -2*wordSize };
std::vector<byte> TailJumpDebugInfo::JMPQ_R10 = { 0x41, 0xFF, 0xE2 };

std::unique_ptr<DebugInfo> DebugInfo::create(uint64_t id, LlvmCodeGen* cg) {
  auto& patch_info = cg->selector().patch_info();
  PatchInfo* pi = patch_info.count(id) ? patch_info[id].get() : nullptr;
  switch (type(id)) {
    case NativeCall: return std::make_unique<NativeCallDebugInfo>();
    case SafePoint: return std::make_unique<SafePointDebugInfo>();
    case Call: return std::make_unique<CallDebugInfo>(pi);
    case StaticCall: return std::make_unique<StaticCallDebugInfo>(pi);
    case DynamicCall: return std::make_unique<DynamicCallDebugInfo>(pi);
    case BlockStart: return std::make_unique<BlockStartDebugInfo>();
    case Rethrow: return std::make_unique<RethrowDebugInfo>(pi);
    case TailJump: return std::make_unique<TailJumpDebugInfo>(pi);
    case PatchBytes: return std::make_unique<PatchBytesDebugInfo>();
    case Oop: return std::make_unique<OopDebugInfo>();
    case NarrowOop: return std::make_unique<NarrowOopDebugInfo>();
    case OrigPC: return std::make_unique<OrigPCDebugInfo>();
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

void OrigPCDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  address pos = cg->code_start() + pc_offset;
  assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  pos += NativeMovConstReg::data_offset;
  assert(*(uintptr_t*)pos == MAGIC_NUMBER, "expected magic number");
}

void OopDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  // Constant ... MOVABS REG, IMM ... PatchBytes
  address pos = cg->code_start() + pc_offset;
  const size_t size = NativeMovConstReg::instruction_size;
  if (mov(pos)) {
    if (mov_mem(pos)) return; // it's not the first load of this constant and there's already a relocation
    if (!movabs(pos)) { // try looking from the other end
      assert(mov_reg(pos), "expected MOV REG, REG");
      assert(idx < cg->debug_info().size() - 1, "expected PatchBytes next");
      PatchBytesDebugInfo* pbdi = cg->debug_info()[idx + 1]->asPatchBytes();
      assert(pbdi, "probably incorrect sorting");
      pos = cg->code_start() + pbdi->pc_offset - (MOV_REG_SIZE + size);
      assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
      assert(mov(pos + size) && mov_mem(pos + size), "expected MOV REG, [REG]");
    }
  } else { // the constant is somewhere in between Constant and PatchBytes, so far we can only handle individual cases 
    Unimplemented();
  }
  con = *(uintptr_t*)(pos + NativeMovConstReg::data_offset);
  cg->relocator().add(this, pos - cg->code_start());
}

void NarrowOopDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  size_t off;
  address pos = cg->code_start() + pc_offset;
  if (movl(pos)) { // MOV DWORD PTR [REG+OFF], IMM
    off = rex(pos) ? 4 : 3;
  } else { // CMP REG, IMM
    if (cmp(pos, true)) {
      pc_offset++;
      *(pos++) = NativeInstruction::nop_instruction_code;
    }
    assert(cmp(pos, false), "no other choice");
    off = cmp_rax(pos, false) ? 1 :
    (cmp_indir(pos) ? 3 :
    (cmp_no_rex(pos) ? 2 : 3));
  }
  oop_index = *(uint32_t*)(pos + off) - MAGIC_NUMBER;
  cg->relocator().add(this, pc_offset);
}

void TailJumpDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  // |                  nop*8                 |   nop*6   |  add rsp, pop rbp, etc.   |retq|
  // |mov rdx,[rbp - 0x8]|mov r10,[rbp - 0x10]|add rsp, pop rbp, etc.|add rsp, 0x8|jmpq r10|
  size_t pb = patch_info->size;
  assert(idx > 0, "there should be PatchBytes before");
  PatchBytesDebugInfo* pbdi = cg->debug_info()[idx - 1]->asPatchBytes();
  assert(pbdi && pc_offset - pbdi->pc_offset == pb, "wrong distance");

  address pos = cg->code_start() + pbdi->pc_offset, start_pos = pos;
  patch(pos, MOV_RDX);
  patch(pos, MOV_R10);

  address next_addr = cg->code_end();
  if (idx < cg->debug_info().size() - 1) {
    BlockStartDebugInfo* bsdi = cg->debug_info()[idx + 1]->asBlockStart();
    assert(bsdi, "should be BlockStart");
    next_addr = cg->code_start() + bsdi->pc_offset;
  }
  assert(next_addr[-NativeReturn::instruction_size] == NativeReturn::instruction_code, "not retq");

  std::vector<byte> ADD_0x8_RSP = ADD_x_RSP(0x8);
  size_t offset = pb - (pos - start_pos), footer_size = ADD_0x8_RSP.size() + JMPQ_R10.size();
  do {
    pos[0] = pos[offset];
  } while (++pos != next_addr - footer_size);
  patch(pos, ADD_0x8_RSP);
  patch(pos, JMPQ_R10);
}

void RethrowDebugInfo::handle(size_t idx, LlvmCodeGen* cg) {
  // [nop*4|add rsp, pop rbp, etc. |retq|
  // [add rsp, pop rbp, etc.| jmpq dest |
  size_t pb = patch_info->size;

  address retq_addr = cg->code_end(), code_start = cg->code_start();
  if (idx < cg->debug_info().size() - 1) {
    BlockStartDebugInfo* bsdi = cg->debug_info()[idx + 1]->asBlockStart();
    assert(bsdi, "should be BlockStart");
    retq_addr = code_start + bsdi->pc_offset;
  }
  retq_addr -= NativeReturn::instruction_size;
  assert(*retq_addr == NativeReturn::instruction_code, "not retq");

  address pos = code_start + pc_offset - pb;
  do {
    pos[0] = pos[pb];
  } while (++pos != (retq_addr - pb));
  size_t rel_off = pos - code_start;
  *(pos++) = NativeJump::instruction_code;
  *(uint32_t*)pos = OptoRuntime::rethrow_stub() - (pos + sizeof(uint32_t));

  cg->relocator().add(this, rel_off);
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

    address pos, nop_end = call_site - NativeCall::displacement_offset, call_start = nop_end;

    if (asDynamicCall()) {
      pos = nop_end -= NativeMovConstReg::instruction_size;
      const byte movabs = 0x48, rax = 0xb8;
      *(pos++) = movabs;
      *(pos++) = rax;
      *(uintptr_t*)pos = (uintptr_t)Universe::non_oop_word();
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
    if (jcdi) {
      jcdi->call_offset = pos - code_start;
    }
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

    if (jcdi) {
      cg->relocator().add(jcdi, jcdi->call_offset);
    }

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

  if (!cg->C->has_method()) {
    assert(idx > 0, "expect OrigPC");
    OrigPCDebugInfo* opdi = cg->debug_info()[idx - 1]->asOrigPC();
    assert(opdi, "sanity check");
    *(uintptr_t*)(code_start + opdi->pc_offset + NativeMovConstReg::data_offset) = (uintptr_t)code_start + pc_offset;
    cg->relocator().add(opdi, opdi->pc_offset);
  }
}