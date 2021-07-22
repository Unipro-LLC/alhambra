#include "llvmCodeGen.hpp"
#include "llvmContext.hpp"
#include "llvm_globals.hpp"
#include "selector_llvm.hpp"


namespace {
  llvm::cl::opt<std::string>
  MCPU("mcpu");

  llvm::cl::list<std::string>
  MAttrs("mattr",
         llvm::cl::CommaSeparated);
}


LlvmCodeGen::LlvmCodeGen() {
  // Initialize the native target
  llvm::InitializeNativeTarget();
  // MCJIT require a native AsmPrinter
  llvm::InitializeNativeTargetAsmPrinter();

  // Create contexts which we'll use
  _normal_context = new LlvmContext("normal");
  initialize_module();

  // Finetune LLVM for the current host CPU.
  llvm::StringMap<bool> Features;
  bool gotCpuFeatures = llvm::sys::getHostCPUFeatures(Features);
  std::string cpu("-mcpu=" + std::string(llvm::sys::getHostCPUName()));
  std::vector<const char*> args;
  args.push_back(""); // program name
  args.push_back(cpu.c_str());

  std::string mattr("-mattr=");
  if(gotCpuFeatures){
    for(llvm::StringMap<bool>::iterator I = Features.begin(),
      E = Features.end(); I != E; ++I){
      if(I->second){
        std::string attr(I->first());
        mattr+="+"+attr+",";
      }
    }
  args.push_back(mattr.c_str());
  }
  if (llvmFastSelect) {
    args.push_back("-fast-isel=true");
  }

  if (llvmPrintLLVM) {
    args.push_back("-print-after-all");
  }

  args.push_back(0);  // terminator
  llvm::cl::ParseCommandLineOptions(args.size() - 1, (char **) &args[0], "", &llvm::errs());

  // Create the JIT
  std::string ErrorMsg;

  builder = new llvm::EngineBuilder(std::move(_normal_owner));
  builder->setMCPU(MCPU);
  builder->setMAttrs(MAttrs);
  builder->setEngineKind(llvm::EngineKind::JIT);
  builder->setErrorStr(&ErrorMsg);
  builder->setOptLevel(llvm::CodeGenOpt::Aggressive);
}

void LlvmCodeGen::initialize_module() {
  _normal_owner = llvm::make_unique<llvm::Module>("normal", *_normal_context);
  _normal_module = _normal_owner.get();
}

void LlvmCodeGen::llvm_code_gen(Compile* comp, const char* target_name, const char* target_holder_name) {
  const char* name = method_name(target_holder_name, target_name);
  initialize_module();
  Selector sel(comp, *_normal_context, _normal_module , name);
  llvm::Function& F = *(sel.func());
  llvm::TargetMachine* TM = builder->selectTarget();
  _normal_owner->setDataLayout(TM->createDataLayout());
  CodeBuffer* cb = comp->code_buffer();
  cb->initialize(256 * K, 64 * K);
  cb->initialize_oop_recorder(comp->env()->oop_recorder());
  MacroAssembler *masm = new MacroAssembler(cb);
  void* code_start = masm->code()->insts()->start();
  llvm::MCContext* Ctx = nullptr;
  llvm::SmallVector<char, 4096> ObjBufferSV;
  llvm::raw_svector_ostream ObjStream(ObjBufferSV);
  cantFail(_normal_module->materializeAll());
  llvm::legacy::FunctionPassManager FPM(_normal_module);
  FPM.run(F);
  llvm::legacy::PassManager PM;
  TM->addPassesToEmitMC(PM, Ctx, ObjStream, false);
  PM.run(*_normal_module);
  std::unique_ptr<llvm::MemoryBuffer> ObjectToLoad(
    new llvm::SmallVectorMemoryBuffer(std::move(ObjBufferSV)));
  llvm::Expected<std::unique_ptr<llvm::object::ObjectFile>> LoadedObject =
    llvm::object::ObjectFile::createObjectFile(ObjectToLoad->getMemBufferRef());
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
  memcpy(code_start, ObjectToLoad->getBufferStart() + offset, code_size);
  F.deleteBody();
  masm->code_section()->set_end((address)(code_start + code_size));
  if (JvmtiExport::should_post_dynamic_code_generated()) {
    JvmtiExport::post_dynamic_code_generated(name, code_start, code_start + code_size);
  }
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

