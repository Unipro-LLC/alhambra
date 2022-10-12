#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "opto/compile.hpp"
#include "opto/runtime.hpp"

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
struct PatchBytesDebugInfo;
struct ConstantDebugInfo;
struct OopDebugInfo;
struct MetadataDebugInfo;
struct SwitchDebugInfo;
struct ExceptionDebugInfo; 
struct ScopeInfo;
struct PatchInfo;
struct SpillPatchInfo;

struct DebugInfo {
  enum Type {
    SafePoint, 
    Call, 
    StaticCall, 
    DynamicCall, 
    BlockStart, 
    PatchBytes, 
    Oop, 
    Metadata, 
    Switch, 
    Exception, 

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

  static bool mov(address pos) { return pos[0] == 0x48 || pos[0] == 0x49; }
  static bool movabs(address pos) { return pos[1] >= 0xB8 && pos[1] <= 0xBF; }
  static bool mov_mem(address pos) { return pos[1] == 0x8B; }
  static bool mov_reg(address pos) { return pos[1] == 0x89; }
  const static size_t MOV_REG_SIZE = 3;
  static std::vector<byte> ADD_x_RSP(byte x) { return { 0x48, 0x83, 0xC4, x }; }
  const static size_t ADD_RSP_SIZE = 4;
  static std::vector<byte> SUB_x_RSP(byte x) { return { 0x48, 0x83, 0xEC, x }; }
  const static size_t SUB_RSP_SIZE = 4;

  virtual SafePointDebugInfo* asSafePoint() { return nullptr; }
  virtual CallDebugInfo* asCall() { return nullptr; }
  virtual JavaCallDebugInfo* asJavaCall() { return nullptr; }
  virtual StaticCallDebugInfo* asStaticCall() { return nullptr; }
  virtual DynamicCallDebugInfo* asDynamicCall() { return nullptr; }
  virtual BlockStartDebugInfo* asBlockStart() { return nullptr; }
  virtual PatchBytesDebugInfo* asPatchBytes() { return nullptr; }
  virtual ConstantDebugInfo* asConstant() { return nullptr; }
  virtual OopDebugInfo* asOop() { return nullptr; }
  virtual MetadataDebugInfo* asMetadata() { return nullptr; }
  virtual SwitchDebugInfo* asSwitch() { return nullptr; }
  virtual ExceptionDebugInfo* asException() { return nullptr; }

  virtual bool block_start() { return false; }
  virtual bool block_can_start() { return false; }
  virtual bool block_can_end() { return false; }
  bool less(DebugInfo* other);
};

struct SafePointDebugInfo : public DebugInfo {
  static std::vector<byte> MOV_RAX_AL;
  ScopeInfo* scope_info;
  OopMap* oopmap;
  unsigned record_idx;
  SafePointDebugInfo(): DebugInfo() {}
  SafePointDebugInfo* asSafePoint() override { return this; }
  Type type() override { return SafePoint; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
  RecordAccessor record(StackMapParser* parser) const { return parser->getRecord(record_idx); }
  static void patch_movabs_rax(address& pos, uintptr_t x);
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
  const llvm::BasicBlock* bb;
  BlockStartDebugInfo(): DebugInfo() {}
  BlockStartDebugInfo* asBlockStart() override { return this; }
  Type type() override { return BlockStart; }
  bool block_start() override { return true; }
};

struct PatchBytesDebugInfo : public DebugInfo {
  PatchBytesDebugInfo(): DebugInfo() {}
  PatchBytesDebugInfo* asPatchBytes() override { return this; }
  Type type() override { return PatchBytes; }
  bool block_can_end() override { return true; }
};

struct ConstantDebugInfo : public DebugInfo {
  const static uintptr_t MAGIC_NUMBER = (1UL << 32) - 1;
  ConstantDebugInfo(): DebugInfo() {}
  ConstantDebugInfo* asConstant() override { return this; }
  bool block_can_start() override { return true; }
  static uintptr_t encode(uintptr_t con) { return con + ((con & MAGIC_NUMBER) << 32); }
  static uintptr_t decode(uintptr_t con) { return con - ((con & MAGIC_NUMBER) << 32); }
};

struct OopDebugInfo : public ConstantDebugInfo {
  OopDebugInfo(): ConstantDebugInfo() {}
  OopDebugInfo* asOop() override { return this; }
  Type type() override { return Oop; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct MetadataDebugInfo : public ConstantDebugInfo {
  MetadataDebugInfo(): ConstantDebugInfo() {}
  MetadataDebugInfo* asMetadata() override { return this; }
  Type type() override { return Metadata; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct SwitchDebugInfo : public ConstantDebugInfo {
  std::vector<const llvm::BasicBlock*>& Cases;
  SwitchDebugInfo(std::vector<const llvm::BasicBlock*>& cases) : ConstantDebugInfo(), Cases(cases) {}
  Type type() override { return Switch; }
  SwitchDebugInfo* asSwitch() override { return this; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
};

struct ExceptionDebugInfo : public DebugInfo {
  ExceptionDebugInfo(): DebugInfo() {}
  Type type() override { return Exception; }
  ExceptionDebugInfo* asException() override { return this; }
  void handle(size_t idx, LlvmCodeGen* cg) override;
  bool block_can_start() override { return true; }
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