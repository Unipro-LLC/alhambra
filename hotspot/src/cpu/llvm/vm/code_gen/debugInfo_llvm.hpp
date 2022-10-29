#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "opto/compile.hpp"
#include "opto/runtime.hpp"

#include "llvmHeaders.hpp"

class OopMap;
class LlvmCodeGen;
struct SafePointDebugInfo;
struct PollDebugInfo;
struct CallDebugInfo;
struct StaticCallDebugInfo;
struct DynamicCallDebugInfo;
struct OtherDebugInfo;
struct ConstantDebugInfo;
struct OopDebugInfo;
struct MetadataDebugInfo;
struct SwitchDebugInfo;
struct ScopeInfo;
struct PatchInfo;

struct DebugInfo {
  enum Type {
    Poll, 
    SafePoint, 
    StaticCall, 
    DynamicCall, 
    Other, 
    Oop, 
    Metadata, 
    Switch, 

    Count };

  uint32_t pc_offset;

  static uint64_t id(Type ty, uint64_t idx = 0) { return ty + Count * idx; }
  static uint32_t idx(uint64_t id) { return id / Count; }
  static Type type(uint64_t id) { return static_cast<Type>(id % Count); }
  static std::unique_ptr<DebugInfo> create(uint64_t id, LlvmCodeGen* cg);
  virtual void handle(LlvmCodeGen* cg) {}

  static bool mov(address pos) { return pos[0] == 0x48 || pos[0] == 0x49; }
  static bool movabs(address pos) { return pos[1] >= 0xB8 && pos[1] <= 0xBF; }

  virtual SafePointDebugInfo* asSafePoint() { return nullptr; }
  virtual PollDebugInfo* asPoll() { return nullptr; }
  virtual CallDebugInfo* asCall() { return nullptr; }
  virtual StaticCallDebugInfo* asStaticCall() { return nullptr; }
  virtual DynamicCallDebugInfo* asDynamicCall() { return nullptr; }
  virtual OtherDebugInfo* asOther() { return nullptr; }
  virtual ConstantDebugInfo* asConstant() { return nullptr; }
  virtual OopDebugInfo* asOop() { return nullptr; }
  virtual MetadataDebugInfo* asMetadata() { return nullptr; }
  virtual SwitchDebugInfo* asSwitch() { return nullptr; }
};

struct SafePointDebugInfo : public DebugInfo {
  ScopeInfo* scope_info;
  OopMap* oopmap;
  unsigned record_idx;
  SafePointDebugInfo(): DebugInfo() {}
  SafePointDebugInfo* asSafePoint() override { return this; }
  RecordAccessor record(StackMapParser* parser) const { return parser->getRecord(record_idx); }
};

struct PollDebugInfo : public SafePointDebugInfo {
  PollDebugInfo(): SafePointDebugInfo() {}
  PollDebugInfo* asPoll() override { return this; }
  void handle(LlvmCodeGen* cg) override;
};

struct CallDebugInfo : public SafePointDebugInfo {
  PatchInfo* patch_info;
  CallDebugInfo(PatchInfo* pi): SafePointDebugInfo(), patch_info(pi) {}
  CallDebugInfo* asCall() override { return this; }
  void handle(LlvmCodeGen* cg) override;
};

struct StaticCallDebugInfo : public CallDebugInfo {
  StaticCallDebugInfo(PatchInfo* pi): CallDebugInfo(pi) {}
  StaticCallDebugInfo* asStaticCall() override { return this; }
};

struct DynamicCallDebugInfo : public CallDebugInfo {
  DynamicCallDebugInfo(PatchInfo* pi): CallDebugInfo(pi) {}
  DynamicCallDebugInfo* asDynamicCall() override { return this; }
};

struct OtherDebugInfo : public DebugInfo {
  OtherDebugInfo(): DebugInfo() {}
  OtherDebugInfo* asOther() override { return this; }
};

struct ConstantDebugInfo : public DebugInfo {
  const static uintptr_t MAGIC_NUMBER = (1UL << 32) - 1;
  ConstantDebugInfo(): DebugInfo() {}
  ConstantDebugInfo* asConstant() override { return this; }
  static uintptr_t encode(uintptr_t con) { return con + ((con & MAGIC_NUMBER) << 32); }
  static uintptr_t decode(uintptr_t con) { return con - ((con & MAGIC_NUMBER) << 32); }
};

struct OopDebugInfo : public ConstantDebugInfo {
  OopDebugInfo(): ConstantDebugInfo() {}
  OopDebugInfo* asOop() override { return this; }
  void handle(LlvmCodeGen* cg) override;
};

struct MetadataDebugInfo : public ConstantDebugInfo {
  MetadataDebugInfo(): ConstantDebugInfo() {}
  MetadataDebugInfo* asMetadata() override { return this; }
  void handle(LlvmCodeGen* cg) override;
};

struct SwitchDebugInfo : public ConstantDebugInfo {
  std::vector<const llvm::BasicBlock*>& Cases;
  SwitchDebugInfo(std::vector<const llvm::BasicBlock*>& cases) : ConstantDebugInfo(), Cases(cases) {}
  SwitchDebugInfo* asSwitch() override { return this; }
  void handle(LlvmCodeGen* cg) override;
};

#endif // CPU_LLVM_VM_CODE_GEN_DEBUGINFO_LLVM_HPP