#ifndef SHARE_VM_LLVM_LLVMCODEGEN_HPP
#define SHARE_VM_LLVM_LLVMCODEGEN_HPP

#include "compiler/compileBroker.hpp"
#include "llvmMemoryManager.hpp"
#include "llvmGlobals.hpp"
#include "llvm/Support/TargetSelect.h"


class LlvmContext;

class LlvmCodeGen {
 public:
  // Creation
  LlvmCodeGen();
  // Initialization
  void initialize_module();

 public:
  void llvm_code_gen(Compile* comp, const char* target_name,  const char* target_holder_name);

 private:
  LlvmContext* _normal_context;
  std::unique_ptr<llvm::Module> _normal_owner;
  llvm::Module* _normal_module;

 public:
  LlvmContext* context() const {
    return _normal_context;
  }

 private:
  LlvmMemoryManager*    _memory_manager;
  llvm::ExecutionEngine* _execution_engine = NULL;

 private:
  LlvmMemoryManager* memory_manager() const {
    return _memory_manager;
  }
  llvm::ExecutionEngine* execution_engine() const {
    return _execution_engine;
  }

 private:
  static const char* method_name(const char* klass, const char* method);
};
 #endif
