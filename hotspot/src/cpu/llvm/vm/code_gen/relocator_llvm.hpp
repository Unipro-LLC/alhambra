#ifndef CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP

#include <vector>

#include "utilities/globalDefinitions.hpp"
#include "memory/allocation.hpp"

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
class LoadConstReloc;
class OopReloc;
class MetadataReloc;
class InternalReloc;
class InlineOopReloc;

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
  virtual LoadConstReloc* asLoadConst() { return nullptr; }
  virtual OopReloc* asOop()    { return nullptr; }
  virtual MetadataReloc* asMetadata()    { return nullptr; }
  virtual InternalReloc* asInternal()    { return nullptr; }
  virtual InlineOopReloc* asInlineOop()    { return nullptr; }
  virtual RelocationHolder getHolder() = 0;
  virtual int format();
};

class CallReloc: public Reloc {
  HotspotRelocInfo _kind;

public:
  CallReloc(HotspotRelocInfo info, size_t offset):
    Reloc(offset),
    _kind(info) {}

  RelocationHolder getHolder() override;
  CallReloc* asCall() override         { return this; }
  HotspotRelocInfo kind() const       { return _kind; }
};

class VirtualCallReloc : public CallReloc {
  address _IC_addr;
public:
  VirtualCallReloc(size_t offset): CallReloc(HotspotRelocInfo::RelocVirtualCall, offset) {}
  void set_IC_addr(address IC_addr) { _IC_addr = IC_addr; }
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

class LoadConstReloc : public ConstReloc {
  uintptr_t _con;
public:
  LoadConstReloc(size_t offset, uintptr_t con): ConstReloc(offset), _con(con) {}
  uintptr_t con() const { return _con; }
  LoadConstReloc* asLoadConst() override { return this; }
};

class OopReloc : public LoadConstReloc {
public:
  OopReloc(size_t offset, uintptr_t con): LoadConstReloc(offset, con) {}
  OopReloc* asOop() override { return this; }
};

class MetadataReloc : public LoadConstReloc {
public:
  MetadataReloc(size_t offset, uintptr_t con): LoadConstReloc(offset, con) {}
  MetadataReloc* asMetadata() override { return this; }
};

class InternalReloc : public Reloc {
public:
  InternalReloc(size_t offset): Reloc(offset) {}
  InternalReloc* asInternal() override { return this; }
  RelocationHolder getHolder() override;
};

class InlineOopReloc : public Reloc {
  size_t _oop_index;
public:
  InlineOopReloc(size_t offset, size_t oop_index): Reloc(offset), _oop_index(oop_index) {}
  InlineOopReloc* asInlineOop() override { return this; }
  RelocationHolder getHolder() override;
  int format() override;
};

class LlvmRelocator {
private:
  LlvmCodeGen* _cg;
  std::vector<Reloc*> relocs;

public:
  LlvmCodeGen* cg() { return _cg; }
  void add(DebugInfo* di, size_t offset);
  void add_float(size_t offset, float con);
  void add_double(size_t offset, double con);
  void apply_relocs(MacroAssembler* masm);

  LlvmRelocator(LlvmCodeGen* code_gen) : _cg(code_gen) {}
};

#endif // CPU_LLVM_VM_CODE_GEN_RELOCATOR_LLVM_HPP