#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "opto/compile.hpp"

#include "llvmHeaders.hpp"

class OopMap;
class Block;
struct IndexDebugInfo;
struct SafePointDebugInfo;
struct CallDebugInfo;
struct JavaCallDebugInfo;
struct StaticCallDebugInfo;
struct DynamicCallDebugInfo;
struct BlockStartDebugInfo;
struct InblockDebugInfo;
struct RethrowDebugInfo;
struct TailJumpDebugInfo;
struct PatchBytesDebugInfo;
struct ExceptionDebugInfo;
struct ScopeInfo;

//unique to each pc_offset
struct DebugInfo {
  enum Type { BlockStart, SafePoint, Call, StaticCall, DynamicCall, Inblock, Rethrow, TailJump, PatchBytes, Exception, Count };
  uint32_t pc_offset;
  DebugInfo() {}
  virtual Type type() = 0;
  static uint64_t id(Type ty, uint64_t idx = 0) { return ty + Count * idx; }
  static uint32_t idx(uint64_t id) { return id / Count; }
  static Type type(uint64_t id) { return static_cast<Type>(id % Count); }
  static std::unique_ptr<DebugInfo> create(uint64_t id);
  static size_t patch_bytes(Type type);

  static std::vector<byte> MOV_RDX;
  static std::vector<byte> MOV_R10;
  static std::vector<byte> ADD_0x8_RSP;
  static std::vector<byte> JMPQ_R10;

  virtual SafePointDebugInfo* asSafePointDebugInfo() { return nullptr; }
  virtual CallDebugInfo* asCallDebugInfo() { return nullptr; }
  virtual JavaCallDebugInfo* asJavaCallDebugInfo() { return nullptr; }
  virtual StaticCallDebugInfo* asStaticCallDebugInfo() { return nullptr; }
  virtual DynamicCallDebugInfo* asDynamicCallDebugInfo() { return nullptr; }
  virtual BlockStartDebugInfo* asBlockStartDebugInfo() { return nullptr; }
  virtual InblockDebugInfo* asInblockDebugInfo() { return nullptr; }
  virtual RethrowDebugInfo* asRethrowDebugInfo() { return nullptr; }
  virtual TailJumpDebugInfo* asTailJumpDebugInfo() { return nullptr; }
  virtual PatchBytesDebugInfo* asPatchBytesDebugInfo() { return nullptr; }
  virtual ExceptionDebugInfo* asExceptionDebugInfo() { return nullptr; }
};
struct IndexDebugInfo : public DebugInfo {
  uint32_t idx;
  IndexDebugInfo(uint32_t idx_): DebugInfo(), idx(idx_) {}
};
struct SafePointDebugInfo : public IndexDebugInfo {
  unsigned record_idx;
  ScopeInfo* scope_info;
  OopMap* oopmap;

  SafePointDebugInfo(uint32_t idx): IndexDebugInfo(idx) {}
  SafePointDebugInfo* asSafePointDebugInfo() override { return this; }
  Type type() override { return SafePoint; }
  RecordAccessor record(StackMapParser* parser) const { return parser->getRecord(record_idx); }
};
struct CallDebugInfo : public SafePointDebugInfo {
  CallDebugInfo(uint32_t idx): SafePointDebugInfo(idx) {}
  CallDebugInfo* asCallDebugInfo() override { return this; }
  Type type() override { return Call; }
};
struct JavaCallDebugInfo : public CallDebugInfo {
  uint32_t call_offset;
  JavaCallDebugInfo(uint32_t idx): CallDebugInfo(idx) {}
  JavaCallDebugInfo* asJavaCallDebugInfo() override { return this; }
};

struct StaticCallDebugInfo : public JavaCallDebugInfo {
  StaticCallDebugInfo(uint32_t idx): JavaCallDebugInfo(idx) {}
  StaticCallDebugInfo* asStaticCallDebugInfo() override { return this; }
  Type type() override { return StaticCall; }
};
struct DynamicCallDebugInfo : public JavaCallDebugInfo {
  DynamicCallDebugInfo(uint32_t idx): JavaCallDebugInfo(idx) {}
  DynamicCallDebugInfo* asDynamicCallDebugInfo() override { return this; }
  Type type() override { return DynamicCall; }
};
struct BlockStartDebugInfo : public IndexDebugInfo {
  Block* block;
  BlockStartDebugInfo(uint32_t idx): IndexDebugInfo(idx) {}
  BlockStartDebugInfo* asBlockStartDebugInfo() override { return this; }
  Type type() override { return BlockStart; }
};
struct InblockDebugInfo : public DebugInfo {
  InblockDebugInfo(): DebugInfo() {}
  InblockDebugInfo* asInblockDebugInfo() override { return this; }
  Type type() override { return Inblock; }
};
struct RethrowDebugInfo : public DebugInfo {
  RethrowDebugInfo(): DebugInfo() {}
  RethrowDebugInfo* asRethrowDebugInfo() override { return this; }
  Type type() override { return Rethrow; }
};
struct TailJumpDebugInfo : public DebugInfo {
  TailJumpDebugInfo(): DebugInfo() {}
  TailJumpDebugInfo* asTailJumpDebugInfo() override { return this; }
  Type type() override { return TailJump; }
};
struct PatchBytesDebugInfo : public DebugInfo {
  PatchBytesDebugInfo(): DebugInfo() {}
  PatchBytesDebugInfo* asPatchBytesDebugInfo() override { return this; }
  Type type() override { return PatchBytes; }
};

struct ExceptionDebugInfo : public DebugInfo {
  ExceptionDebugInfo(): DebugInfo() {}
  ExceptionDebugInfo* asExceptionDebugInfo() override { return this; }
  Type type() override { return Exception; }
};
#endif // CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP