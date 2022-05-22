#ifndef CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP

#include <vector>

#include "utilities/globalDefinitions.hpp"
#include "memory/allocation.hpp"

#include "llvmHeaders.hpp"

class MacroAssembler;
class Reloc;
class MachCallJavaNode;
class LlvmCodeGen;
class DebugInfo;

enum HotspotRelocInfo {
  RelocNone,
  RelocOffsetInCode,
  RelocOffsetInConst,
  RelocOop,
  RelocPollPage,
  RelocPollPageRet,
  RelocCodesOffset,
  RelocCodePc,
  RelocVirtualCall,
  RelocOptVirtualCall,
  RelocStaticCall,
  RelocRuntimeCall,
  RelocFieldOffset,
  RelocMetadata
};

class RelocationHolder;
class CallReloc;
class VirtualCallReloc;
class ConstReloc;
class FloatReloc;
class DoubleReloc;
class OopReloc;
class MetadataReloc;
class InternalReloc;
class InlineOopReloc;
class SwitchReloc;
class DynamicCallDebugInfo;

class Reloc: public ResourceObj {
protected:
  size_t     _offset;
  Reloc(size_t offset) : _offset(offset) {}

public:
  size_t     offset() const              { return _offset; }

  virtual CallReloc* asCall()    { return nullptr; }
  virtual VirtualCallReloc* asVirtualCall()    { return nullptr; }
  virtual ConstReloc* asConst() { return nullptr; }
  virtual FloatReloc* asFloat()    { return nullptr; }
  virtual DoubleReloc* asDouble()    { return nullptr; }
  virtual OopReloc* asOop()    { return nullptr; }
  virtual MetadataReloc* asMetadata()    { return nullptr; }
  virtual InternalReloc* asInternal()    { return nullptr; }
  virtual InlineOopReloc* asInlineOop()    { return nullptr; }
  virtual SwitchReloc* asSwitch()    { return nullptr; }
  virtual RelocationHolder getHolder() = 0;
  virtual int format();
};

class CallReloc: public Reloc {
  HotspotRelocInfo _kind;

public:
  CallReloc(size_t offset, DebugInfo* di);

  RelocationHolder getHolder() override;
  CallReloc* asCall() override         { return this; }
  HotspotRelocInfo kind() const       { return _kind; }
};

class VirtualCallReloc : public CallReloc {
  address _IC_addr;
public:
  VirtualCallReloc(size_t offset, DynamicCallDebugInfo* di, address ic_addr);
  VirtualCallReloc* asVirtualCall() override { return this; }
  RelocationHolder getHolder() override;
};

class ConstReloc : public Reloc {
  address _con_addr = nullptr;
protected:
  ConstReloc(size_t offset): Reloc(offset) {}
public:
  void set_con_addr(address con_addr) { _con_addr = con_addr; }
  ConstReloc* asConst() override { return this; }
  RelocationHolder getHolder() override;
};

class FloatReloc : public ConstReloc {
  float _con;
public: 
  FloatReloc(size_t offset, float con): ConstReloc(offset), _con(con) {}
  float con() const { return _con; }
  FloatReloc* asFloat() override { return this; }
};

class DoubleReloc : public ConstReloc {
  double _con;
public:
  DoubleReloc(size_t offset, double con): ConstReloc(offset), _con(con) {}
  double con() const { return _con; }
  DoubleReloc* asDouble() override { return this; }
};

class OopReloc : public ConstReloc {
public:
  OopReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg);
  OopReloc* asOop() override { return this; }
};

class MetadataReloc : public ConstReloc {
public:
  MetadataReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg);
  MetadataReloc* asMetadata() override { return this; }
};

class InternalReloc : public Reloc {
public:
  InternalReloc(size_t offset): Reloc(offset) {}
  InternalReloc* asInternal() override { return this; }
  RelocationHolder getHolder() override;
};

class SwitchReloc : public ConstReloc {
public: 
  SwitchReloc(size_t offset, SwitchInfo& si, LlvmCodeGen* cg);
  SwitchReloc* asSwitch() override { return this; }
};

class LlvmRelocator {
private:
  LlvmCodeGen* _cg;
  std::vector<Reloc*> relocs;
  std::vector<FloatReloc*> f_relocs;
  std::vector<DoubleReloc*> d_relocs, da_relocs;

public:
  LlvmCodeGen* cg() { return _cg; }
  void add(Reloc* rel) { relocs.push_back(rel); }
  void add_float(size_t offset, float con);
  void add_double(size_t offset, double con, bool align);
  void apply_relocs();
  void floats_to_cb();

  LlvmRelocator(LlvmCodeGen* code_gen) : _cg(code_gen) {}
};

#endif // CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP