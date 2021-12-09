#ifndef CPU_LLVM_VM_CODE_GEN_SCOPEINFO_LLVM_HPP
#define CPU_LLVM_VM_CODE_GEN_SCOPEINFO_LLVM_HPP

#include <vector>
#include <memory>

#include "utilities/growableArray.hpp"

struct ScalarObjectInfo;
class Node;
class MachSafePointNode;
class MachCallNode;
class MachCallJavaNode;

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

#endif // CPU_LLVM_VM_CODE_GEN_SCOPEINFO_LLVM_HPP