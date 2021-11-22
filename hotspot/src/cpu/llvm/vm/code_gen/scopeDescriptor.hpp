#ifndef CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
#define CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP

#include <vector>
#include "compiler/oopMap.hpp"
#include "llvmGlobals.hpp"

class Selector;
class DebugInfo;
class MachSafePointNode;
class Compile;
class JVMState;
class ciMethod;
class OopMap;
class ScopeValue;
class ScopeInfo;
class ScalarObjectInfo;
class Node;
class NodeInfo;

class ScopeDescriptor {
  
public:
  ScopeDescriptor(Selector* Sel);
  void describe_scopes();
  DebugInfo init_debug_info(MachSafePointNode* sfn);
  llvm::OperandBundleDef statepoint_scope(MachSafePointNode* sfn);
private:
  Selector* sel;
  Compile* C;
  RecordAccessor* record;
  JVMState* youngest_jvms;
  JVMState* jvms;
  ciMethod* method;
  uint32_t pc_offset;
  OopMap* oopmap;
  MachSafePointNode* sfn;
  GrowableArray<ScopeValue*> *objs;
  uint max_spill;
  int num_mon;
  int la_idx;
  ScalarObjectInfo* sc_obj;

  void fill_loc_array(GrowableArray<ScopeValue*> *array, Node* n);
  void describe_scope();
  void init_obj_info(NodeInfo* ni);
  int32_t calcUnextendedMonOffset(int idx) const;
  int32_t calcUnextendedMonObjOffset(int idx) const;
};

#endif //CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
