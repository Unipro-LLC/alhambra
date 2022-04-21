#include "debugInfo_llvm.hpp"

#include "opto/block.hpp"
#include "llvmCodeGen.hpp"

std::vector<byte> PatchInfo::MOV_RDX = { Assembler::REX_W,  NativeMovRegMem::instruction_code_mem2reg, 0x55, -wordSize };
std::vector<byte> PatchInfo::MOV_R10 = { Assembler::REX_WR, NativeMovRegMem::instruction_code_mem2reg, 0x55, -2*wordSize };
std::vector<byte> PatchInfo::JMPQ_R10 = { 0x41, 0xFF, 0xE2 };

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
    case Exception: return std::make_unique<ExceptionDebugInfo>();
    case Constant: return std::make_unique<ConstantDebugInfo>();
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