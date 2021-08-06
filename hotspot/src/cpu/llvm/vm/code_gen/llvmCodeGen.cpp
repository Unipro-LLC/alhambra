#include "llvmCodeGen.hpp"
#include "llvm_globals.hpp"
#include "selector_llvm.hpp"
#include <memory>


namespace {
  llvm::cl::opt<std::string>
  MCPU("mcpu");

  llvm::cl::list<std::string>
  MAttrs("mattr",
         llvm::cl::CommaSeparated);
}


LlvmCodeGen::LlvmCodeGen() :
  _normal_owner(llvm::make_unique<llvm::Module>("normal", _normal_context)),
  _normal_module(_normal_owner.get()), builder(std::move(_normal_owner)) {
  // Create the JIT
  std::string ErrorMsg;

  builder = new llvm::EngineBuilder(std::move(_normal_owner));
  builder->setMCPU(MCPU);
  builder->setMAttrs(MAttrs);
  builder->setEngineKind(llvm::EngineKind::JIT);
  builder->setErrorStr(&ErrorMsg);
  builder->setOptLevel(llvm::CodeGenOpt::Aggressive);
}

void LlvmCodeGen::llvm_code_gen(Compile* comp, const char* target_name, const char* target_holder_name) {
  const char* name = method_name(target_holder_name, target_name);
  Selector sel(comp, _normal_context, _normal_module , name);
  llvm::Function& F = *(sel.func());

  NOT_PRODUCT( if (PrintLLVMIR) { F.dump(); } )

  llvm::SmallVector<char, 4096> ObjBufferSV;
  run_passes(ObjBufferSV, F);

  llvm::SmallVectorMemoryBuffer ObjectToLoad(std::move(ObjBufferSV));
  llvm::Expected<std::unique_ptr<llvm::object::ObjectFile>> LoadedObject =
    llvm::object::ObjectFile::createObjectFile(ObjectToLoad.getMemBufferRef());
  assert(LoadedObject, "object is not loaded");
  llvm::object::ObjectFile& obj = *LoadedObject.get();

  uintptr_t code_size, offset;
  for (const llvm::object::SectionRef &S : obj.sections()) {
    if (S.isText()) {
      code_size = S.getSize();
      offset = static_cast<const llvm::object::ELFSectionRef&>(S).getOffset();
      break;
    }
  }

  address code_start = write_to_codebuffer(comp, ObjectToLoad.getBufferStart() + offset, code_size);
  
  F.deleteBody();

  if (JvmtiExport::should_post_dynamic_code_generated()) {
    JvmtiExport::post_dynamic_code_generated(name, code_start, code_start + code_size);
  }
}

void LlvmCodeGen::run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV, llvm::Function& F) {
  llvm::TargetMachine* TM = builder.selectTarget();
  _normal_module->setDataLayout(TM->createDataLayout());
  llvm::MCContext* Ctx = nullptr;
  llvm::raw_svector_ostream ObjStream(ObjBufferSV);
  cantFail(_normal_module->materializeAll());
  llvm::legacy::FunctionPassManager FPM(_normal_module);
  FPM.run(F);
  llvm::legacy::PassManager PM;
  TM->addPassesToEmitMC(PM, Ctx, ObjStream, false);
  PM.run(*_normal_module);
}

address LlvmCodeGen::write_to_codebuffer(Compile* comp, const void* src, uintptr_t code_size) {
  CodeBuffer* cb = comp->code_buffer();
  cb->initialize(256 * K, 64 * K);
  cb->initialize_oop_recorder(comp->env()->oop_recorder());
  MacroAssembler masm(cb);
  address code_start = masm.code()->insts()->start();
  memcpy(code_start, src, code_size);
  masm.code_section()->set_end((address)(code_start + code_size));
  return code_start;
}

const char* LlvmCodeGen::method_name(const char* klass, const char* method) {
  char* buf = NEW_RESOURCE_ARRAY(char, strlen(klass) + 2 + strlen(method) + 1);

  char* dst = buf;
  for (const char *c = klass; *c; c++) {
    if (*c == '/')
      *(dst++) = '.';
    else
      *(dst++) = *c;
  }
  *(dst++) = ':';
  *(dst++) = ':';
  for (const char *c = method; *c; c++) {
    *(dst++) = *c;
  }
  *(dst++) = '\0';
  return buf;
}

