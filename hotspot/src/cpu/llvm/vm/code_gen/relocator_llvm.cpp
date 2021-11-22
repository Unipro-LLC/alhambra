#include <algorithm>
#include "utilities/debug.hpp"
#include "asm/macroAssembler.hpp"

#include "relocator_llvm.hpp"
#include "selector_llvm.hpp"

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
  RelocE2kCt,
  RelocFieldOffset,
  RelocMetadata
};
class CallReloc;

class Reloc {

protected:
  void*     _address = NULL;
  int       _index = 0;  //For links between relocations

public:

  void      setAddress(void *address) { _address = address; }
  void*     addr() const              { return _address; }
  int       index() const             { return _index; }

  virtual int getFormat() const       { return 0; }
  virtual CallReloc* asCallReloc()    { return nullptr; }
  virtual RelocationHolder getHolder() = 0;
};

class CallReloc: public Reloc {
  HotspotRelocInfo _kind;
  void* _IC_oop_reloc;
  int   _IC_oop_reloc_index;

public:
  CallReloc(HotspotRelocInfo info, int IC_oop_reloc_index = -1):
    _kind(info),
    _IC_oop_reloc(NULL),
    _IC_oop_reloc_index(IC_oop_reloc_index) {}

  RelocationHolder getHolder() {
    assert(_address, "address should not be NULL");
    switch (kind()) {
    case HotspotRelocInfo::RelocVirtualCall:
      assert(_IC_oop_reloc != NULL, "couldn't be null");
      return virtual_call_Relocation::spec((address)_IC_oop_reloc);
    case HotspotRelocInfo::RelocOptVirtualCall: return opt_virtual_call_Relocation::spec();
    case HotspotRelocInfo::RelocStaticCall:     return static_call_Relocation::spec();
    case HotspotRelocInfo::RelocRuntimeCall:    return runtime_call_Relocation::spec();
    default: ShouldNotReachHere();     return Relocation::spec_simple(relocInfo::none);
    }
}

  void       setICOopReloc(void *oop_reloc) { _IC_oop_reloc = oop_reloc; }
  int        IC_oop_index() const           { return _IC_oop_reloc_index; }
  CallReloc* asCallReloc()                  { return this; }
  HotspotRelocInfo kind() const       { return _kind; }
};

struct compareRelocs {
  bool operator()(const Reloc* lhs, const Reloc* rhs) const {
    return lhs->addr() < rhs->addr();
  }
};

void LLVMRelocator::apply_relocs(MacroAssembler* masm) {
  address code_start = masm->code()->insts()->start();
  for (RecordAccessor& record : sel()->sm_parser()->records()) {
    MachSafePointNode* sfn = sel()->sfns(record.getID());
    HotspotRelocInfo reloc_info;
    ciMethod* method = static_cast<MachCallJavaNode*>(sfn)->_method;
    bool is_runtime = method == NULL;

    if (is_runtime) {
      reloc_info = HotspotRelocInfo::RelocRuntimeCall;
    } else if (method->is_static()) {
      reloc_info = HotspotRelocInfo::RelocStaticCall;
    } else {
      reloc_info = HotspotRelocInfo::RelocOptVirtualCall;
    }
    
    CallReloc* rel = new CallReloc(reloc_info);
    uint32_t pc_offset = record.getInstructionOffset();
    address call_addr = sel()->debug_info(sfn).call_addr = code_start + pc_offset - NativeCall::instruction_size_2;
    rel->setAddress(call_addr);
    relocs.push_back(rel);
  }
  compareRelocs comparator;
  std::sort(relocs.begin(), relocs.end(), comparator);

  for (auto it = relocs.begin(); it != relocs.end(); ++it) {
    Reloc* rel = *it;

    bool verify_ok = false;
    if (rel->asCallReloc()) {
      CallReloc *call_rel = rel->asCallReloc();
      if (call_rel && call_rel->kind() == HotspotRelocInfo::RelocFieldOffset) {
      continue;
    }
      if (call_rel->kind() == HotspotRelocInfo::RelocVirtualCall) {
        assert(call_rel->IC_oop_index() >= 0, "virtual call relocation must have IC oop");
        for (auto int_it = relocs.begin(); int_it != relocs.end(); ++int_it) {
          Reloc *int_rel = *int_it;
          assert(int_rel != NULL, "check");
          if (int_rel->index() == call_rel->IC_oop_index()) {
            assert(static_cast<CallReloc*>(int_rel)->kind() == HotspotRelocInfo::RelocMetadata, "must be oop reloc");
            call_rel->setICOopReloc(int_rel->addr());
            verify_ok = int_rel->addr() != NULL;
          }
        }
        assert(verify_ok, "must be");
      }
    }

    if (rel->asCallReloc()) {
      CallReloc* call_reloc = static_cast<CallReloc*>(rel);
      masm->code_section()->relocate((address)call_reloc->addr(), call_reloc->getHolder(), rel->getFormat());
    }
  }
}