#ifndef CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
#define CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP

#include <vector>
#include <memory>

#include "scopeInfo_llvm.hpp"

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
class ScalarObjectInfo;
class Node;
class NodeInfo;
class SafePointDebugInfo;
class Type;

class ScopeDescriptor {
  
public:
  ScopeDescriptor(LlvmCodeGen* code_gen);
  LlvmCodeGen* cg() const { return _cg; }

  std::vector<std::unique_ptr<ScopeInfo>>& scope_info() { return _scope_info; }
  void describe_scopes();
  ScopeInfo* register_scope(MachSafePointNode* sfn, bool throws_exc = false);
  std::vector<llvm::Value*> stackmap_scope(const ScopeInfo* si);
private:
  LlvmCodeGen* _cg;
  Compile* C;
  std::vector<std::unique_ptr<ScopeInfo>> _scope_info;
  const int DEOPT_CNT_OFFSET = 2;
  const int DEOPT_OFFSET = 3;

  void fill_loc_array(GrowableArray<ScopeValue*> *array, const std::vector<std::unique_ptr<NodeInfo>>& src, SafePointDebugInfo* di, int& la_idx);
  bool fill_loc_array_helper(GrowableArray<ScopeValue*> *array, NodeInfo* ni, SafePointDebugInfo* di, int& la_idx);
  ScopeValue* con_value(const Type *t, bool& largeType);
  int describe_scope(SafePointDebugInfo* di);
  std::unique_ptr<NodeInfo> init_node_info(ScopeInfo* si, Node* n);
  void add_statepoint_arg(std::vector<llvm::Value*>& args, NodeInfo* ni);
  bool empty_loc(Node* n) const;
  bool con_loc(Node* n) const;
};

#endif //CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
