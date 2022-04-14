#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "opto/compile.hpp"

#include "llvmHeaders.hpp"

class OopMap;
class Block;
struct GCDebugInfo;
struct SafePointDebugInfo;
struct NativeCallDebugInfo;
struct CallDebugInfo;
struct JavaCallDebugInfo;
struct StaticCallDebugInfo;
struct DynamicCallDebugInfo;
struct BlockStartDebugInfo;
struct RethrowDebugInfo;
struct TailJumpDebugInfo;
struct PatchBytesDebugInfo;
struct ExceptionDebugInfo;
struct ConstantDebugInfo;
struct ScopeInfo;

//unique to each pc_offset
struct DebugInfo {
  enum Type { NativeCall, SafePoint, Call, StaticCall, DynamicCall, BlockStart, Rethrow, TailJump, PatchBytes, Exception, Constant, Count };
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

  virtual GCDebugInfo* asGC() { return nullptr; }
  virtual NativeCallDebugInfo* asNativeCall() { return nullptr; }
  virtual SafePointDebugInfo* asSafePoint() { return nullptr; }
  virtual CallDebugInfo* asCall() { return nullptr; }
  virtual JavaCallDebugInfo* asJavaCall() { return nullptr; }
  virtual StaticCallDebugInfo* asStaticCall() { return nullptr; }
  virtual DynamicCallDebugInfo* asDynamicCall() { return nullptr; }
  virtual BlockStartDebugInfo* asBlockStart() { return nullptr; }
  virtual RethrowDebugInfo* asRethrow() { return nullptr; }
  virtual TailJumpDebugInfo* asTailJump() { return nullptr; }
  virtual PatchBytesDebugInfo* asPatchBytes() { return nullptr; }
  virtual ExceptionDebugInfo* asException() { return nullptr; }
  virtual ConstantDebugInfo* asConstant() { return nullptr; }

  virtual bool block_start() { return false; }
  virtual bool block_can_start() { return false; }
  virtual bool block_can_end() { return false; }
  bool less(DebugInfo* other);
};
struct GCDebugInfo : public DebugInfo {
  OopMap* oopmap;
  unsigned record_idx;
  GCDebugInfo() : DebugInfo() {}
  GCDebugInfo* asGC() override { return this; }
  RecordAccessor record(StackMapParser* parser) const { return parser->getRecord(record_idx); }
};
struct NativeCallDebugInfo : public DebugInfo {
  NativeCallDebugInfo(): DebugInfo() {}
  NativeCallDebugInfo* asNativeCall() override { return this; }
  Type type() override { return NativeCall; }
  bool block_can_end() override { return true; }
};
struct SafePointDebugInfo : public GCDebugInfo {
  ScopeInfo* scope_info;
  SafePointDebugInfo(): GCDebugInfo() {}
  SafePointDebugInfo* asSafePoint() override { return this; }
  Type type() override { return SafePoint; }
};
struct CallDebugInfo : public SafePointDebugInfo {
  CallDebugInfo(): SafePointDebugInfo() {}
  CallDebugInfo* asCall() override { return this; }
  Type type() override { return Call; }
  bool block_can_end() override { return true; }
};
struct JavaCallDebugInfo : public CallDebugInfo {
  uint32_t call_offset;
  JavaCallDebugInfo(): CallDebugInfo() {}
  JavaCallDebugInfo* asJavaCall() override { return this; }
};
struct StaticCallDebugInfo : public JavaCallDebugInfo {
  StaticCallDebugInfo(): JavaCallDebugInfo() {}
  StaticCallDebugInfo* asStaticCall() override { return this; }
  Type type() override { return StaticCall; }
};
struct DynamicCallDebugInfo : public JavaCallDebugInfo {
  DynamicCallDebugInfo(): JavaCallDebugInfo() {}
  DynamicCallDebugInfo* asDynamicCall() override { return this; }
  Type type() override { return DynamicCall; }
};

struct BlockStartDebugInfo : public DebugInfo {
  BlockStartDebugInfo(): DebugInfo() {}
  BlockStartDebugInfo* asBlockStart() override { return this; }
  Type type() override { return BlockStart; }
  bool block_start() override { return true; }
};
struct RethrowDebugInfo : public DebugInfo {
  RethrowDebugInfo(): DebugInfo() {}
  RethrowDebugInfo* asRethrow() override { return this; }
  Type type() override { return Rethrow; }
};
struct TailJumpDebugInfo : public DebugInfo {
  TailJumpDebugInfo(): DebugInfo() {}
  TailJumpDebugInfo* asTailJump() override { return this; }
  Type type() override { return TailJump; }
};
struct PatchBytesDebugInfo : public DebugInfo {
  PatchBytesDebugInfo(): DebugInfo() {}
  PatchBytesDebugInfo* asPatchBytes() override { return this; }
  Type type() override { return PatchBytes; }
  bool block_can_end() override { return true; }
};

struct ExceptionDebugInfo : public DebugInfo {
  ExceptionDebugInfo(): DebugInfo() {}
  ExceptionDebugInfo* asException() override { return this; }
  Type type() override { return Exception; }
  bool block_start() override { return true; }
};

struct ConstantDebugInfo : public DebugInfo {
  uintptr_t con;
  ConstantDebugInfo(): DebugInfo() {}
  ConstantDebugInfo* asConstant() override { return this; }
  Type type() override { return Constant; }
  bool block_can_start() override { return true; }
};
#endif // CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP