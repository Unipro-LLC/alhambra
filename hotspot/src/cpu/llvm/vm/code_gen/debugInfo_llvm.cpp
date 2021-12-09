#include "debugInfo_llvm.hpp"

std::vector<byte> DebugInfo::MOV_RDX = { Assembler::REX_W,  NativeMovRegMem::instruction_code_mem2reg, 0x55, -wordSize };
std::vector<byte> DebugInfo::MOV_R10 = { Assembler::REX_WR, NativeMovRegMem::instruction_code_mem2reg, 0x55, -2*wordSize };
std::vector<byte> DebugInfo::ADD_0x8_RSP = { 0x48, 0x83, 0xC4, wordSize };
std::vector<byte> DebugInfo::JMPQ_R10 = { 0x41, 0xFF, 0xE2 };

std::unique_ptr<DebugInfo> DebugInfo::create(uint64_t id) {
  uint32_t idx = DebugInfo::idx(id);
  switch (DebugInfo::type(id)) {
    case StaticCall: return std::make_unique<StaticCallDebugInfo>(idx);
    case DynamicCall: return std::make_unique<DynamicCallDebugInfo>(idx);
    case BlockStart: return std::make_unique<BlockStartDebugInfo>(idx);
    case Inblock: return std::make_unique<InblockDebugInfo>();
    case Rethrow: return std::make_unique<RethrowDebugInfo>();
    case TailJump: return std::make_unique<TailJumpDebugInfo>();
    case PatchBytes: return std::make_unique<PatchBytesDebugInfo>();
    case Exception: return std::make_unique<ExceptionDebugInfo>();
    default: ShouldNotReachHere();
  }
}

size_t DebugInfo::patch_bytes(Type type) {
  const size_t JAVA_CALL_PATCH_BYTES = NativeCall::instruction_size + BytesPerInt - 1;
  switch (type) {
    case DynamicCall: return JAVA_CALL_PATCH_BYTES + NativeMovConstReg::instruction_size;
    case StaticCall: return JAVA_CALL_PATCH_BYTES;
    case Rethrow: return NativeJump::instruction_size - NativeReturn::instruction_size;
    case TailJump: return 2 * NativeMovRegMem::instruction_size + ADD_0x8_RSP.size() + JMPQ_R10.size() - NativeReturn::instruction_size; 
    case Exception: return 1; // minimum number of nops so the call won't be inserted
    default: ShouldNotReachHere();
  }
}