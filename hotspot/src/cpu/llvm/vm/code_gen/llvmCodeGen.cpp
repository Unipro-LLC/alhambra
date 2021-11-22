#include "llvm/Support/SmallVectorMemoryBuffer.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/CodeGen/BuiltinGCs.h"
#include "code/compiledIC.hpp"

#include "llvmCodeGen.hpp"
#include "llvm_globals.hpp"
#include "selector_llvm.hpp"

namespace {
  llvm::cl::opt<std::string>
  MCPU("mcpu");

  llvm::cl::list<std::string>
  MAttrs("mattr",
         llvm::cl::CommaSeparated);
}


LlvmCodeGen::LlvmCodeGen() :
  _normal_owner(std::make_unique<llvm::Module>("normal", _normal_context)),
  _normal_module(_normal_owner.get()), _builder(std::move(_normal_owner)) {
  // Create the JIT
  std::string ErrorMsg;

  _builder.setMCPU(MCPU);
  _builder.setMAttrs(MAttrs);
  _builder.setEngineKind(llvm::EngineKind::JIT);
  _builder.setErrorStr(&ErrorMsg);
  _builder.setOptLevel(llvm::CodeGenOpt::Aggressive);
  llvm::linkAllBuiltinGCs();

  TM = _builder.selectTarget();
  _normal_module->setDataLayout(TM->createDataLayout());
}

void LlvmCodeGen::llvm_code_gen(Compile* comp, const char* target_name, const char* target_holder_name) {
  C = comp;
  const char* name = method_name(target_holder_name, target_name);
  Selector sel(comp, _normal_context, _normal_module , name);
  llvm::Function& F = *(sel.func());

  NOT_PRODUCT( if (PrintLLVMIR) { _normal_module->dump(); } )

  llvm::SmallVector<char, 4096> ObjBufferSV;
  run_passes(ObjBufferSV, F);

  llvm::SmallVectorMemoryBuffer ObjectToLoad(std::move(ObjBufferSV));
  llvm::Expected<std::unique_ptr<llvm::object::ObjectFile>> LoadedObject =
    llvm::object::ObjectFile::createObjectFile(ObjectToLoad.getMemBufferRef());
  assert(LoadedObject, "object is not loaded");
  llvm::object::ObjectFile& obj = *LoadedObject.get();

  address code_start;
  uintptr_t code_size;
  llvm::ArrayRef<uint8_t> stackmap;
  for (const llvm::object::SectionRef &sec : obj.sections()) {
    if (sec.isText()) {
      code_size = sec.getSize();
      auto elf_sec = static_cast<const llvm::object::ELFSectionRef&>(sec);
      code_start = (address)ObjectToLoad.getBufferStart() + elf_sec.getOffset();
    } else {
      llvm::Expected<llvm::StringRef> sec_name_tmp = sec.getName();
      assert(sec_name_tmp, "null section name");
      llvm::StringRef sec_name = sec_name_tmp.get();
      if (sec_name == ".llvm_stackmaps") {
        uint64_t stackmap_size = sec.getSize();
        auto elf_sec = static_cast<const llvm::object::ELFSectionRef&>(sec);
        uint8_t* stackmap_start = (uint8_t*)ObjectToLoad.getBufferStart() + elf_sec.getOffset();
        stackmap = llvm::ArrayRef<uint8_t>(stackmap_start, stackmap_size);
      }
    }
  }
  if (!stackmap.empty()) {
    sel.init_sm_parser(stackmap);
  }

  CodeBuffer* cb = C->code_buffer();
  cb->initialize(256 * K, 64 * K);
  cb->initialize_oop_recorder(C->env()->oop_recorder());
  MacroAssembler masm(cb);

  address src = code_start;
  code_start = masm.code()->insts()->start();
  if (sel.sm_parser()) {
    memcpy(code_start, src, code_size);

    masm.code_section()->set_end(code_start + code_size);
    sel.scope_descriptor()->describe_scopes();
    sel.relocator().apply_relocs(&masm);

    cb->initialize_stubs_size(Compile::MAX_stubs_size);
    for (auto di : sel.debug_info()) {
      if (!di.second.call_addr) continue;
      if (static_cast<MachCallJavaNode*>(di.first)->_method) {
        cb->insts()->set_mark(di.second.call_addr);
        address stub = CompiledStaticCall::emit_to_interp_stub(*cb);
        assert(stub != NULL, "CodeCache is full");
      }
    }
  }
  else {
    memcpy(code_start, src, code_size);
    masm.code_section()->set_end(code_start + code_size);
  }
  F.deleteBody();

  if (JvmtiExport::should_post_dynamic_code_generated()) {
    JvmtiExport::post_dynamic_code_generated(name, code_start, code_start + code_size);
  }
  _frame_size = sel.frame_size();
}

void LlvmCodeGen::run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV, llvm::Function& F) {
  llvm::MCContext* Ctx = nullptr;
  llvm::raw_svector_ostream ObjStream(ObjBufferSV);
  llvm::cantFail(_normal_module->materializeAll());
  llvm::legacy::FunctionPassManager FPM(_normal_module);
  FPM.run(F);
  llvm::legacy::PassManager PM;
  TM->addPassesToEmitMC(PM, Ctx, ObjStream, false);
  TM->setFastISel(false);
  PM.run(*_normal_module);
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
