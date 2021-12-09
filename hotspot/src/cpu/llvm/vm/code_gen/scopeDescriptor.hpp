#ifndef CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
#define CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP

#include <vector>
#include <memory>

#include "compiler/oopMap.hpp"

namespace llvm {
  class Value;
}

class LlvmCodeGen;
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
class CallDebugInfo;
class Type;

class ScopeDescriptor {
  
public:
  ScopeDescriptor(LlvmCodeGen* code_gen);
  LlvmCodeGen* cg() const { return _cg; }

  void describe_scopes();
  void fill_scope_info(ScopeInfo* scope_info);
  std::vector<llvm::Value*> statepoint_scope(const ScopeInfo& si);
private:
  LlvmCodeGen* _cg;
  Compile* C;
  const int LOC_OFFSET = 3;

  void fill_loc_array(GrowableArray<ScopeValue*> *array, const std::vector<std::unique_ptr<NodeInfo>>& src, CallDebugInfo* di, int& la_idx);
  bool fill_loc_array_helper(GrowableArray<ScopeValue*> *array, NodeInfo* ni, CallDebugInfo* di, int& la_idx);
  ScopeValue* con_value(const Type *t, bool& largeType);
  void describe_scope(CallDebugInfo* di);
  std::unique_ptr<NodeInfo> init_node_info(ScopeInfo* si, Node* n);
  void add_statepoint_arg(std::vector<llvm::Value*>& args, NodeInfo* ni);
  bool empty_loc(Node* n) const;
  bool con_loc(Node* n) const;
};

#endif //CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
