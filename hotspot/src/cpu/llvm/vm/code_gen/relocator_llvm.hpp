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

  virtual RelocationHolder getHolder() = 0;
  virtual int format();
};

class CallReloc: public Reloc {
  HotspotRelocInfo _kind;

public:
  CallReloc(size_t offset, DebugInfo* di);
  CallReloc(size_t offset = 0, HotspotRelocInfo kind = HotspotRelocInfo::RelocRuntimeCall): Reloc(offset), _kind(kind) {}

  RelocationHolder getHolder() override;
  HotspotRelocInfo kind() const       { return _kind; }
};

class VirtualCallReloc : public CallReloc {
  address _IC_addr;
public:
  VirtualCallReloc(size_t offset, DynamicCallDebugInfo* di, address ic_addr);
  RelocationHolder getHolder() override;
};

class ConstReloc : public Reloc {
  address _con_addr = nullptr;
protected:
  ConstReloc(size_t offset): Reloc(offset) {}
public:
  void set_con_addr(address con_addr) { _con_addr = con_addr; }
  RelocationHolder getHolder() override;
};

class FloatReloc : public ConstReloc {
  float _con;
public: 
  FloatReloc(size_t offset, float con): ConstReloc(offset), _con(con) {}
  float con() const { return _con; }
};

class DoubleReloc : public ConstReloc {
  double _con;
public:
  DoubleReloc(size_t offset, double con): ConstReloc(offset), _con(con) {}
  double con() const { return _con; }
};

class OopReloc : public ConstReloc {
public:
  OopReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg);
};

class MetadataReloc : public ConstReloc {
public:
  MetadataReloc(size_t offset, uintptr_t con, LlvmCodeGen* cg);
};

class InternalReloc : public Reloc {
public:
  InternalReloc(size_t offset): Reloc(offset) {}
  RelocationHolder getHolder() override;
};

class SwitchReloc : public ConstReloc {
public: 
  SwitchReloc(size_t offset, std::vector<const llvm::BasicBlock*>& cases, LlvmCodeGen* cg);
};

class PollReloc : public Reloc {
public: 
  PollReloc(size_t offset) : Reloc(offset) {}
  RelocationHolder getHolder() override;
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