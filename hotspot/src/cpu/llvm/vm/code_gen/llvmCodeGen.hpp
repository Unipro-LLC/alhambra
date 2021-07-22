#ifndef SHARE_VM_LLVM_LLVMCODEGEN_HPP
#define SHARE_VM_LLVM_LLVMCODEGEN_HPP

#include "compiler/compileBroker.hpp"
#include "llvmGlobals.hpp"
#include "llvm/Support/TargetSelect.h"


class LlvmContext;

class LlvmCodeGen {
 public:
  // Creation
  LlvmCodeGen();
  ~LlvmCodeGen() { 
    if (builder)  { delete builder; }
  }
  // Initialization
  void initialize_module();

 public:
  void llvm_code_gen(Compile* comp, const char* target_name,  const char* target_holder_name);

 private:
  LlvmContext* _normal_context;
  std::unique_ptr<llvm::Module> _normal_owner;
  llvm::Module* _normal_module;
  llvm::EngineBuilder* builder;

 public:
  LlvmContext* context() const {
    return _normal_context;
  }

 private:
  static const char* method_name(const char* klass, const char* method);
};
 #endif
