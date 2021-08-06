#ifndef SHARE_VM_LLVM_LLVMCODEGEN_HPP
#define SHARE_VM_LLVM_LLVMCODEGEN_HPP

#include "compiler/compileBroker.hpp"
#include "llvmGlobals.hpp"
#include "llvm/Support/TargetSelect.h"


class LlvmContext;

class LlvmCodeGen {
 public:
  LlvmCodeGen();
  void llvm_code_gen(Compile* comp, const char* target_name,  const char* target_holder_name);

 private:
  llvm::LLVMContext _normal_context;
  std::unique_ptr<llvm::Module> _normal_owner;
  llvm::Module* _normal_module;
  llvm::EngineBuilder builder;

  static const char* method_name(const char* klass, const char* method);
  void run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV, llvm::Function& F);
  address write_to_codebuffer(Compile* comp, const void* src, uintptr_t code_size);
};
 #endif
