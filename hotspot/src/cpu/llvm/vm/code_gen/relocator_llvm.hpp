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

class FPReloc;
class FloatReloc;
class DoubleReloc;


class Reloc: public ResourceObj {
protected:
  size_t     _offset;
  Reloc(size_t offset) : _offset(offset) {}

public:
  size_t     offset() const              { return _offset; }

  virtual int getFormat() const       { return 0; }
  virtual CallReloc* asCallReloc()    { return nullptr; }
  virtual VirtualCallReloc* asVirtualCallReloc()    { return nullptr; }
  virtual FPReloc* asFPReloc() { return nullptr; }
  virtual FloatReloc* asFloatReloc()    { return nullptr; }
  virtual DoubleReloc* asDoubleReloc()    { return nullptr; }
  virtual RelocationHolder getHolder() = 0;
};

class CallReloc: public Reloc {
  HotspotRelocInfo _kind;

public:
  CallReloc(HotspotRelocInfo info, size_t offset):
    Reloc(offset),
    _kind(info) {}

  RelocationHolder getHolder() override;
  CallReloc* asCallReloc() override         { return this; }
  HotspotRelocInfo kind() const       { return _kind; }
};

class VirtualCallReloc : public CallReloc {
  address _IC_addr = nullptr;
public:
  VirtualCallReloc(size_t offset): CallReloc(HotspotRelocInfo::RelocVirtualCall, offset) {}
  void set_IC_addr(address IC_addr) { _IC_addr = IC_addr; }
  VirtualCallReloc* asVirtualCallReloc() override { return this; }
  RelocationHolder getHolder() override;
};

class FPReloc : public Reloc {
  address _con_addr = nullptr;
protected:
  FPReloc(size_t offset): Reloc(offset) {}
public:
  void set_con_addr(address con_addr) { _con_addr = con_addr;}
  FPReloc* asFPReloc() override { return this; }
  RelocationHolder getHolder() override;
};

class FloatReloc : public FPReloc {
  float _con;
public: 
  FloatReloc(size_t offset, float con): FPReloc(offset), _con(con) {}
  float con() const { return _con; }
  FloatReloc* asFloatReloc() override { return this; }
};

class DoubleReloc : public FPReloc {
  double _con;
public: 
  DoubleReloc(size_t offset, double con): FPReloc(offset), _con(con) {}
  double con() const { return _con; }
  DoubleReloc* asDoubleReloc() override { return this; }
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