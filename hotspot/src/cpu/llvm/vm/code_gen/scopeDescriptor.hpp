#ifndef CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
#define CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP

#include <vector>
#include <memory>
#include "utilities/growableArray.hpp"

#include "llvmHeaders.hpp"

class LlvmCodeGen;
class DebugInfo;
class MachSafePointNode;
class MachCallNode;
class MachCallJavaNode;
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
struct ScalarObjectInfo;

struct NodeInfo {
  Node* node;
  NodeInfo(Node* n) : node(n) {}
  virtual ScalarObjectInfo* asScalarObjectInfo() { return nullptr; }
};

struct ScalarObjectInfo : public NodeInfo {
  ScalarObjectInfo(Node* n) : NodeInfo(n) {}
  GrowableArray<ScopeValue*>* dest;
  ScopeValue* sc_val;
  std::vector<std::unique_ptr<NodeInfo>> field_values;

  ScalarObjectInfo* asScalarObjectInfo() override { return (ScalarObjectInfo*)this; }
};

struct ScopeValueInfo {
  std::vector<std::unique_ptr<NodeInfo>> locs, exps, mons;
};

struct ScopeInfo {
  union {
    MachSafePointNode* sfn;
    MachCallNode* cn;
    MachCallJavaNode* cjn;
  };
  uint64_t stackmap_id;
  GrowableArray<ScopeValue*> *objs;
  std::vector<ScopeValueInfo> sv_info;
};

class ScopeDescriptor {
  
public:
  ScopeDescriptor(LlvmCodeGen* code_gen);
  LlvmCodeGen* cg() const { return _cg; }

  std::vector<std::unique_ptr<ScopeInfo>>& scope_info() { return _scope_info; }
  ScopeInfo* register_scope(MachSafePointNode* sfn);
  int describe_scope(SafePointDebugInfo* di, int& la_idx);
  std::vector<llvm::Value*> stackmap_scope(const ScopeInfo* si);
private:
  LlvmCodeGen* _cg;
  Compile* C;
  std::vector<std::unique_ptr<ScopeInfo>> _scope_info;

  void fill_loc_array(GrowableArray<ScopeValue*> *array, const std::vector<std::unique_ptr<NodeInfo>>& src, SafePointDebugInfo* di, int& la_idx);
  bool fill_loc_array_helper(GrowableArray<ScopeValue*> *array, NodeInfo* ni, SafePointDebugInfo* di, int& la_idx);
  ScopeValue* con_value(const Type *t, bool& largeType);
  std::unique_ptr<NodeInfo> create_node_info(ScopeInfo* si, Node* n);
  void add_statepoint_arg(std::vector<llvm::Value*>& args, NodeInfo* ni);
  bool empty_loc(Node* n) const;
  bool con_loc(Node* n) const;
};

#endif //CPU_LLVM_VM_CODE_GEN_SCOPEDESCRIPTOR_HPP
