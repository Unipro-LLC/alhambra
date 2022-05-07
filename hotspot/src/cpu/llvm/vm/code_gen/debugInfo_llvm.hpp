#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "opto/compile.hpp"

#include "llvmHeaders.hpp"

class OopMap;
class Block;
class LlvmCodeGen;
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
struct LoadConstantDebugInfo;
struct OopDebugInfo;
struct NarrowOopDebugInfo;
struct MetadataDebugInfo;
struct OrigPCDebugInfo;
struct ScopeInfo;
struct PatchInfo;
struct SpillPatchInfo;

struct DebugInfo {
  enum Type { 
    NativeCall, 
    SafePoint, 
    Call, 
    StaticCall, 
    DynamicCall, 
    BlockStart, 
    Rethrow, 
    TailJump, 
    PatchBytes, 
    Oop, 
    NarrowOop, 
    Metadata, 
    OrigPC, 

    Count };
  uint32_t pc_offset;
  DebugInfo() {}
  virtual Type type() = 0;
  static uint64_t id(Type ty, uint64_t idx = 0) { return ty + Count * idx; }
  static uint32_t idx(uint64_t id) { return id / Count; }
  static Type type(uint64_t id) { return static_cast<Type>(id % Count); }
  static std::unique_ptr<DebugInfo> create(uint64_t id, LlvmCodeGen* cg);
  virtual void handle(size_t idx, LlvmCodeGen* cg) {}
  static void patch(address& pos, const std::vector<byte>& inst);

  static std::vector<byte> ADD_x_RSP(byte x) { return { 0x48, 0x83, 0xC4, x }; }
  const static size_t ADD_RSP_SIZE = 4;
  static std::vector<byte> SUB_x_RSP(byte x) { return { 0x48, 0x83, 0xEC, x }; }
  const static size_t SUB_RSP_SIZE = 4;

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
  virtual LoadConstantDebugInfo* asLoadConstant() { return nullptr; }
  virtual OopDebugInfo* asOop() { return nullptr; }
  virtual NarrowOopDebugInfo* asNarrowOop() { return nullptr; }
  virtual MetadataDebugInfo* asMetadata() { return nullptr; }
  virtual OrigPCDebugInfo* asOrigPC() { return nullptr; }

  virtual bool block_start() { return false; }
  virtual bool block_can_start() { return false; }
  virtual bool block_can_end() { return false; }
  bool less(DebugInfo* other);
};
struct NativeCallDebugInfo : public DebugInfo {
  NativeCallDebugInfo(): DebugInfo() {}
  NativeCallDebugInfo* asNativeCall() override { return this; }
  Type type() override { return NativeCall; }
  bool block_can_end() override { return true; }
};
struct SafePointDebugInfo : public DebugInfo {
  ScopeInfo* scope_info;
  OopMap* oopmap;
  unsigned record_idx;
  SafePointDebugInfo(): DebugInfo() {}
  SafePointDebugInfo* asSafePoint() override { return this; }
  Type type() override { return SafePoint; }
  RecordAccessor record(StackMapParser* parser) const { return parser->getRecord(record_idx); }
};
struct CallDebugInfo : public SafePointDebugInfo {
  PatchInfo* patch_info;
  CallDebugInfo(PatchInfo* pi): SafePointDebugInfo(), patch_info(pi) {}
  CallDebugInfo* asCall() override { return this; }
  Type type() override { return Call; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
  bool block_can_end() override { return true; }
};
struct JavaCallDebugInfo : public CallDebugInfo {
  JavaCallDebugInfo(PatchInfo* pi): CallDebugInfo(pi) {}
  JavaCallDebugInfo* asJavaCall() override { return this; }
};
struct StaticCallDebugInfo : public JavaCallDebugInfo {
  StaticCallDebugInfo(PatchInfo* pi): JavaCallDebugInfo(pi) {}
  StaticCallDebugInfo* asStaticCall() override { return this; }
  Type type() override { return StaticCall; }
};
struct DynamicCallDebugInfo : public JavaCallDebugInfo {
  DynamicCallDebugInfo(PatchInfo* pi): JavaCallDebugInfo(pi) {}
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
  PatchInfo* patch_info;
  RethrowDebugInfo(PatchInfo* pi): DebugInfo(), patch_info(pi) {}
  RethrowDebugInfo* asRethrow() override { return this; }
  Type type() override { return Rethrow; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};
struct TailJumpDebugInfo : public DebugInfo {
  PatchInfo* patch_info;
  static std::vector<byte> MOV_RDX;
  static std::vector<byte> MOV_R10;
  static std::vector<byte> JMPQ_R10;
  TailJumpDebugInfo(PatchInfo* pi): DebugInfo(), patch_info(pi) {}
  TailJumpDebugInfo* asTailJump() override { return this; }
  Type type() override { return TailJump; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};
struct PatchBytesDebugInfo : public DebugInfo {
  PatchBytesDebugInfo(): DebugInfo() {}
  PatchBytesDebugInfo* asPatchBytes() override { return this; }
  Type type() override { return PatchBytes; }
  bool block_can_end() override { return true; }
};

struct ConstantDebugInfo : public DebugInfo {
  static bool mov(address pos) { return pos[0] == 0x48 || pos[0] == 0x49; }
  static bool movabs(address pos) { return pos[1] >= 0xB8 && pos[1] <= 0xBF; }
  static bool mov_mem(address pos) { return pos[1] == 0x8B; }
  static bool mov_reg(address pos) { return pos[1] == 0x89; }
  const static size_t MOV_REG_SIZE = 3;
  ConstantDebugInfo(): DebugInfo() {}
  ConstantDebugInfo* asConstant() override { return this; }
  bool block_can_start() override { return true; }
};

struct LoadConstantDebugInfo : public ConstantDebugInfo {
  uintptr_t con;
  LoadConstantDebugInfo(): ConstantDebugInfo() {}
  LoadConstantDebugInfo* asLoadConstant() override { return this; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct OopDebugInfo : public LoadConstantDebugInfo {
  OopDebugInfo(): LoadConstantDebugInfo() {}
  OopDebugInfo* asOop() override { return this; }
  Type type() override { return Oop; }
};

struct NarrowOopDebugInfo : public ConstantDebugInfo {
  const static size_t MAGIC_NUMBER = 1 << 30; // addend to oopIndex so it's always 4 bytes
  size_t oop_index;
  static bool rex(address pos) { return pos[0] == 0x41; }
  static bool movl(address pos) { return pos[0] == 0xC7 || (rex(pos) && pos[1] == 0xC7); }
  static bool cmp(address pos, bool is64bit) {
    return cmp_no_rax(pos, is64bit) || cmp_rax(pos, is64bit);
  }
  static bool cmp_rax(address pos, bool is64bit) {
    if (is64bit) return pos[0] == 0x48 && cmp_rax(pos + 1, false);
    return pos[0] == 0x3D;
  }
  static bool cmp_no_rax(address pos, bool is64bit) {
    if (is64bit) return (pos[0] == 0x48 || pos[0] == 0x49) && cmp_no_rex(pos + 1);
    return (rex(pos) && cmp_no_rex(pos + 1)) || cmp_no_rex(pos);
  }
  static bool cmp_no_rex(address pos) { return pos[0] == 0x81; }
  static bool cmp_indir(address pos) { return cmp_no_rex(pos) && pos[1] == 0x7D; }
  NarrowOopDebugInfo(): ConstantDebugInfo() {}
  NarrowOopDebugInfo* asNarrowOop() override { return this; }
  Type type() override { return NarrowOop; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct OrigPCDebugInfo : public ConstantDebugInfo {
  const static uintptr_t MAGIC_NUMBER = 0xdeadbeefdeadbeef;
  OrigPCDebugInfo(): ConstantDebugInfo() {}
  Type type() override { return OrigPC; }
  OrigPCDebugInfo* asOrigPC() override { return this; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct MetadataDebugInfo : public LoadConstantDebugInfo {
  MetadataDebugInfo(): LoadConstantDebugInfo() {}
  MetadataDebugInfo* asMetadata() override { return this; }
  Type type() override { return Metadata; }
};

struct PatchInfo {
  size_t size;
  PatchInfo(size_t s) : size(s) { }
  virtual SpillPatchInfo* asSpill() { return nullptr; }
};

struct SpillPatchInfo : public PatchInfo {
  size_t spill_size;
  SpillPatchInfo(size_t s, size_t ss) : PatchInfo(s), spill_size(ss) { }
  SpillPatchInfo* asSpill() override { return this; }
};
#endif // CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP