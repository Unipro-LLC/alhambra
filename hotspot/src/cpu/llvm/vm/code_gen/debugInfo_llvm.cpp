#include "debugInfo_llvm.hpp"
#include "opto/block.hpp"

std::vector<byte> DebugInfo::MOV_RDX = { Assembler::REX_W,  NativeMovRegMem::instruction_code_mem2reg, 0x55, -wordSize };
std::vector<byte> DebugInfo::MOV_R10 = { Assembler::REX_WR, NativeMovRegMem::instruction_code_mem2reg, 0x55, -2*wordSize };
std::vector<byte> DebugInfo::ADD_0x8_RSP = { 0x48, 0x83, 0xC4, wordSize };
std::vector<byte> DebugInfo::JMPQ_R10 = { 0x41, 0xFF, 0xE2 };

std::unique_ptr<DebugInfo> DebugInfo::create(uint64_t id) {
  switch (type(id)) {
    case NativeCall: return std::make_unique<NativeCallDebugInfo>();
    case SafePoint: return std::make_unique<SafePointDebugInfo>();
    case Call: return std::make_unique<CallDebugInfo>();
    case StaticCall: return std::make_unique<StaticCallDebugInfo>();
    case DynamicCall: return std::make_unique<DynamicCallDebugInfo>();
    case BlockStart: return std::make_unique<BlockStartDebugInfo>();
    case Rethrow: return std::make_unique<RethrowDebugInfo>();
    case TailJump: return std::make_unique<TailJumpDebugInfo>();
    case PatchBytes: return std::make_unique<PatchBytesDebugInfo>();
    case Exception: return std::make_unique<ExceptionDebugInfo>();
    case Constant: return std::make_unique<ConstantDebugInfo>();
    default: ShouldNotReachHere();
  }
}

size_t DebugInfo::patch_bytes(Type type) {
  const size_t JAVA_CALL_PATCH_BYTES = NativeCall::instruction_size + BytesPerInt - 1;
  // 0 leaves the call as it is, 1 is the minimum number of nops so the call won't be inserted
  switch (type) {
    case SafePoint: return 1;
    case Call: return 0;
    case DynamicCall: return JAVA_CALL_PATCH_BYTES + NativeMovConstReg::instruction_size;
    case StaticCall: return JAVA_CALL_PATCH_BYTES;
    case Rethrow: return NativeJump::instruction_size - NativeReturn::instruction_size;
    case TailJump: return 2 * NativeMovRegMem::instruction_size + ADD_0x8_RSP.size() + JMPQ_R10.size() - NativeReturn::instruction_size;
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