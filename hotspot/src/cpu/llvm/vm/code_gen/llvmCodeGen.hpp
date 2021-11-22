#ifndef CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP
#define CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP

#include "llvm/Support/Endian.h"
#include "compiler/compileBroker.hpp"
#include "llvmGlobals.hpp"

class LlvmCodeGen {
 public:
  LlvmCodeGen();
  void llvm_code_gen(Compile* comp, const char* target_name,  const char* target_holder_name);
  uint frame_size() { return _frame_size; }
 private:
  Compile* C;
  llvm::LLVMContext _normal_context;
  std::unique_ptr<llvm::Module> _normal_owner;
  llvm::Module* _normal_module;
  llvm::EngineBuilder _builder;
  llvm::TargetMachine* TM;
  uint _frame_size;

  static const char* method_name(const char* klass, const char* method);
  void run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV, llvm::Function& F);
};

#endif // CPU_LLVM_VM_CODE_GEN_LLVMCODEGEN_HPP
