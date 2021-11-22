#ifndef CPU_LLVM_VM_CODE_GEN_DEBUGINFO_HPP
#define CPU_LLVM_VM_CODE_GEN_DEBUGINFO_HPP

#include <vector>
#include "llvm/IR/Value.h"
#include "utilities/globalDefinitions.hpp"

struct ScalarObjectInfo;

struct NodeInfo {
  Node* node;
  virtual bool is_sc_obj() { return false; }
  ScalarObjectInfo* as_sc_obj() {
    assert(is_sc_obj(), "invalid NodeInfo cast");
    return (ScalarObjectInfo*)this; 
  }
};

struct ScalarObjectInfo : public NodeInfo {
  GrowableArray<ScopeValue*>* dest;
  ScopeValue* sc_val;
  std::vector<std::unique_ptr<NodeInfo>> field_values;
  virtual bool is_sc_obj() { return true; }
};

struct MonitorInfo {
  std::shared_ptr<NodeInfo> ni;
};

struct ScopeInfo {
  std::vector<Node*> locs, exps;
  std::vector<MonitorInfo> mons;
};

struct DebugInfo {
  OopMap* oopmap;
  address call_addr = 0;
  uint64_t sfn_id;
  std::vector<ScopeInfo> scope_info;
  GrowableArray<ScopeValue*> *objs;
};

#endif // CPU_LLVM_VM_CODE_GEN_DEBUGINFO_HPP