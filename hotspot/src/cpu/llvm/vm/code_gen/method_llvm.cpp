#include "llvmHeaders.hpp"

#include "method_llvm.hpp"

#include "llvmCodeGen.hpp"
#include "llvm_globals.hpp"
#include "adfiles/ad_llvm.hpp"

LlvmMethod::LlvmMethod(Compile* C, const char* target_name) {
  LlvmCodeGen code_gen(this, C, target_name);
  Selector& sel = code_gen.selector();

  sel.run();
  NOT_PRODUCT( if (PrintLlvmIR) { code_gen.mod()->dump(); } )

  llvm::SmallVector<char, 4096> ObjBufferSV;
  code_gen.run_passes(ObjBufferSV);

  llvm::SmallVectorMemoryBuffer ObjectToLoad(std::move(ObjBufferSV));
  llvm::Expected<std::unique_ptr<llvm::object::ObjectFile>> LoadedObject =
    llvm::object::ObjectFile::createObjectFile(ObjectToLoad.getMemBufferRef());
  assert(LoadedObject, "object is not loaded");
  llvm::object::ObjectFile& obj = *LoadedObject.get();
  address code_start;
  uint64_t code_size;
  _vep_offset = C->has_method() && !C->method()->get_Method()->is_static() ? 24 : 0;
  code_gen.process_object_file(obj, ObjectToLoad.getBufferStart(), code_start, code_size);

  if (code_gen.sm_parser()) {
    _frame_size = wordSize + code_gen.sm_parser()->getFunction(0).getStackSize() + sel.max_spill();
  }
  code_gen.fill_code_buffer(code_start, code_size, _exc_offset, _deopt_offset);
  _orig_pc_offset = code_gen.stack().unext_orig_pc_offset();

  if (JvmtiExport::should_post_dynamic_code_generated()) {
    JvmtiExport::post_dynamic_code_generated(target_name, code_gen.code_start(), code_gen.code_end());
  }
}

const char* LlvmMethod::method_name(const char* klass, const char* method) {
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