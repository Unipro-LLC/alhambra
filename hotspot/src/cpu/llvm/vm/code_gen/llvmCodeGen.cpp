#include "llvm/Object/ELFObjectFile.h"
#include "llvm/CodeGen/BuiltinGCs.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/MC/MCContext.h"

#include "llvmCodeGen.hpp"

#include "code/compiledIC.hpp"
#include "opto/compile.hpp"
#include "opto/cfgnode.hpp"

#include "llvm_globals.hpp"
#include "method_llvm.hpp"
#include "adfiles/ad_llvm.hpp"

LlvmCodeGen::LlvmCodeGen(LlvmMethod* method, Compile* c, const char* name) :
  C(c),
  _cb(C->code_buffer()),
  _ctx(),
  _mod_owner(std::make_unique<llvm::Module>("normal", ctx())),
  _bbs_info(std::make_unique<llvm::BBSInfo>()),
  _mod(_mod_owner.get()),
  _method(method),
  _selector(this, name),
  _scope_descriptor(this),
  _relocator(this),
  _stack(this)
{
  for (size_t i = 0; i < C->cfg()->number_of_blocks(); ++i) {
    Block* b = C->cfg()->get_block(i);
    for (size_t j = 0; j < b->number_of_nodes(); ++j) {
      Node* n = b->get_node(j);
      if (n->is_MachSafePoint()) {
        _nof_safepoints++;
        JVMState* jvms = n->as_MachSafePoint()->jvms();
        if (jvms) {
          _nof_monitors = MAX(_nof_monitors, jvms->monitor_depth());
        }
        if (n->is_MachCallJava()) {
          _nof_Java_calls++;
          if (n->is_MachCallStaticJava() && n->as_MachCallJava()->_method) {
            _nof_to_interp_stubs++;
          }
        }
      } else if (n->is_Catch()) {
        _nof_exceptions++;
      } else if (cmp_ideal_Opcode(n, Op_TailJump)) {
        _has_tail_jump = true;
      }
    }
  }
  scope_descriptor().scope_info().reserve(nof_safepoints()); 
}

void LlvmCodeGen::run_passes(llvm::SmallVectorImpl<char>& ObjBufferSV) {
  _builder = std::make_unique<llvm::EngineBuilder>(std::move(_mod_owner));
  _builder
    ->setEngineKind(llvm::EngineKind::JIT)
    .setOptLevel(llvm::CodeGenOpt::Aggressive);
  llvm::linkAllBuiltinGCs();
  llvm::TargetMachine* TM = _builder->selectTarget();
  mod()->setDataLayout(TM->createDataLayout());
  llvm::MCContext* ctx = nullptr;
  llvm::raw_svector_ostream ObjStream(ObjBufferSV);
  llvm::cantFail(mod()->materializeAll());

  llvm::legacy::FunctionPassManager FPM(mod());
  FPM.run(*selector().func());

  llvm::legacy::PassManager PM;
  PM.add(llvm::createRewriteStatepointsForGCLegacyPass());
  TM->addPassesToEmitMC(PM, ctx, ObjStream, false);
  ctx->bbs_info = bbs_info();
  TM->setFastISel(false);
  PM.run(*mod());
}

void LlvmCodeGen::process_object_file(const llvm::object::ObjectFile& obj_file, const char *obj_file_start, address& code_start, uint64_t& code_size) {
  for (const llvm::object::SectionRef &sec : obj_file.sections()) {
    auto elf_sec = static_cast<const llvm::object::ELFSectionRef&>(sec);
    if (sec.isText()) {
      code_size = sec.getSize();
      code_start = (address)obj_file_start + elf_sec.getOffset();
    } else {
      llvm::Expected<llvm::StringRef> sec_name_tmp = sec.getName();
      assert(sec_name_tmp, "null section name");
      llvm::StringRef sec_name = sec_name_tmp.get();
      if (sec_name == ".llvm_stackmaps") {
        uint64_t stackmap_size = sec.getSize();
        uint8_t* stackmap_start = (uint8_t*)obj_file_start + elf_sec.getOffset();
        llvm::ArrayRef<uint8_t> stackmap(stackmap_start, stackmap_size);
        _sm_parser = std::make_unique<StackMapParser>(stackmap);
      } else if (sec_name == ".llvm_faultmaps") {
        const uint8_t* fm_start = (const uint8_t*)obj_file_start + elf_sec.getOffset();
        llvm::FaultMapParser fm_parser(fm_start, fm_start + sec.getSize());
        auto func_info = fm_parser.getFirstFunctionInfo();
        uint32_t n = func_info.getNumFaultingPCs();
        C->inc_table()->set_size(n);
        for (size_t i = 0; i < n; ++i) {
          auto ff_info = func_info.getFunctionFaultInfoAt(i);
          int vep_offset = method()->vep_offset();
          C->inc_table()->append(vep_offset + ff_info.getFaultingPCOffset(), vep_offset + ff_info.getHandlerPCOffset());
        }
      } else if (sec_name == ".rela.text") {
        for (const llvm::object::ELFRelocationRef &Reloc : sec.relocations()) {
          llvm::object::symbol_iterator SI = Reloc.getSymbol();
          llvm::Expected<llvm::object::section_iterator> SymSI = SI->getSection();
          assert(SymSI, "section not found");
          llvm::Expected<llvm::StringRef> SecData = (*SymSI)->getName();
          assert(SecData, "invalid section name");
          llvm::Expected<llvm::StringRef> Value = (*SymSI)->getContents();
          assert(Value, "invalid section contents");
          llvm::Expected<int64_t> Addend = Reloc.getAddend();
          assert(Addend, "addend not found");
          size_t offset = method()->vep_offset() + Reloc.getOffset() - 2;
          if (*SecData == ".rodata.cst16") {
            double con = *(double*)(Value->data() + *Addend);
            relocator().add_double(offset, con, true);
            _nof_consts += 2;
          } else if (*SecData == ".rodata.cst8") {
            double con = *(double*)(Value->data() + *Addend);
            relocator().add_double(offset, con, false);
            _nof_consts++;
          } else if (*SecData == ".rodata.cst4") {
            float con = *(float*)(Value->data() + *Addend);
            relocator().add_float(offset, con);
            _nof_consts++;
          }
        }
      }
    }
  }
}

void LlvmCodeGen::fill_code_buffer(address src, uint64_t size, int& exc_offset, int& deopt_offset) {
  int vep_offset = method()->vep_offset();
  size_t stubs_size = CompiledStaticCall::to_interp_stub_size() * nof_to_interp_stubs() + HandlerImpl::size_exception_handler() + HandlerImpl::size_deopt_handler();
  size_t consts_size = nof_consts() * wordSize;
  size_t code_size = size + 1; // in case the last instruction is a call, a nop will be inserted in the very end
  size_t cb_size = vep_offset + code_size + stubs_size + consts_size;
  size_t locs_size = 1 + nof_Java_calls() + (vep_offset ? 1 : 0);
  cb()->initialize(cb_size, locs_size * sizeof(relocInfo));
  cb()->initialize_consts_size(consts_size);
  cb()->initialize_oop_recorder(C->env()->oop_recorder());
  _code_start = cb()->insts()->start();

  MacroAssembler masm(cb());
  if (vep_offset != 0) {
    masm.generate_unverified_entry();
  }
  address verified_entry_point = masm.pc();
  assert(verified_entry_point - code_start() == vep_offset, "expected equal offsets");

  assert(verified_entry_point + size < cb()->insts()->limit(), "cannot memcpy");
  memcpy(verified_entry_point, src, size);
  masm.code_section()->set_end(verified_entry_point + code_size);
  _code_end = verified_entry_point + size;
  *code_end() = NativeInstruction::nop_instruction_code;

  stack().set_frame_size(method()->frame_size());
  debug_info().reserve(sm_parser()->getNumRecords() + bbs_info()->BasicBlockSizes.size());
  unsigned record_idx = 0;
  for (RecordAccessor record: sm_parser()->records()) {
    uint64_t id = record.getID();
    std::unique_ptr<DebugInfo> di = DebugInfo::create(id, this);
    di->pc_offset = vep_offset + record.getInstructionOffset();

    SafePointDebugInfo* spdi = di->asSafePoint();
    if (spdi) {
      spdi->oopmap = new OopMap(stack().frame_size() / BytesPerInt, C->has_method() ? C->method()->arg_size() : 0);
      spdi->record_idx = record_idx;
      spdi->scope_info = scope_descriptor().scope_info()[DebugInfo::idx(id)].get();
      assert(spdi->scope_info->stackmap_id == id, "different ids");
    }

    record_idx++;
    debug_info().push_back(std::move(di));
  }

  count_block_offsets(vep_offset);

  // sorted vector is convenient for patching
  std::sort(debug_info().begin(), debug_info().end(),
    [&](const std::unique_ptr<DebugInfo>& a, const std::unique_ptr<DebugInfo>& b) {
      return a->pc_offset == b->pc_offset ? a->less(b.get()) : a->pc_offset < b->pc_offset;
    });
  
  for (size_t i = 0; i < debug_info().size(); ++i) {
    debug_info()[i]->handle(i, this);
  }

  scope_descriptor().describe_scopes();
  relocator().apply_relocs(&masm);
  cb()->initialize_stubs_size(stubs_size);
  add_stubs(exc_offset, deopt_offset);
  assert(code_start() == cb()->insts()->start(), "CodeBuffer was reallocated");
}

void LlvmCodeGen::count_block_offsets(int vep_offset) {
  block_offsets().reserve(bbs_info()->BasicBlockSizes.size());
  auto& RelaxSizes = bbs_info()->RelaxSizes;
  auto& AlignSizes = bbs_info()->AlignSizes;
  std::sort(RelaxSizes.begin(), RelaxSizes.end());
  std::sort(AlignSizes.begin(), AlignSizes.end());
  size_t offset = vep_offset;
  size_t rel_idx = 0, al_idx = 0;

  for (auto& pair : bbs_info()->BasicBlockSizes) {
    if (pair.second == 0) continue;
    // these DebugInfo-s may come in handy during patching 
    std::unique_ptr<DebugInfo> di = DebugInfo::create(DebugInfo::id(DebugInfo::BlockStart), this);
    di->pc_offset = offset;
    debug_info().push_back(std::move(di));
    if (pair.first) {
      block_offsets().emplace(pair.first, offset); // basic block pointers are dangling at this point
    }
    offset += pair.second;
    if (rel_idx < RelaxSizes.size() && offset > RelaxSizes[rel_idx].first + vep_offset) {
      offset += RelaxSizes[rel_idx++].second - llvm::BBSInfo::JCC_SIZE;
    }
    if (al_idx < AlignSizes.size() && offset > AlignSizes[al_idx].first + vep_offset) {
      offset += AlignSizes[al_idx++].second;
    }
  }
}

void LlvmCodeGen::add_stubs(int& exc_offset, int& deopt_offset) {
  if (C->has_method()) {
    for (const std::unique_ptr<DebugInfo>& di : debug_info()) {
      StaticCallDebugInfo* scdi = di->asStaticCall();
      if (!scdi) continue;
      MachCallJavaNode* cjn = scdi->scope_info->cjn;
      if (cjn->_method) {
        address call_site = code_start() + scdi->pc_offset - NativeCall::instruction_size;
        cb()->insts()->set_mark(call_site);
        address stub = CompiledStaticCall::emit_to_interp_stub(*cb());
        assert(stub != NULL, "CodeCache is full");
      }
    }
    exc_offset = HandlerImpl::emit_exception_handler(*cb());
    deopt_offset = HandlerImpl::emit_deopt_handler(*cb());
  }
}