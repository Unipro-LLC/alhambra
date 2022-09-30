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
  _asm_info(std::make_unique<llvm::AsmInfo>()),
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
  ctx->AI = asm_info();
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
          llvm::object::section_iterator& SecIt = *SymSI;
          llvm::Expected<llvm::StringRef> SecData = SecIt->getName();
          assert(SecData, "invalid section name");
          llvm::Expected<llvm::StringRef> Value = SecIt->getContents();
          assert(Value, "invalid section contents");
          llvm::Expected<int64_t> Addend = Reloc.getAddend();
          assert(Addend, "addend not found");
          size_t offset = method()->vep_offset() + Reloc.getOffset() - NativeMovConstReg::data_offset;
          if (*SecData == ".rodata.cst16") {
            double con = *(double*)(Value->data() + *Addend);
            relocator().add_double(offset, con, true);
            _nof_consts += 2;
            _nof_locs++;
          } else if (*SecData == ".rodata.cst8") {
            double con = *(double*)(Value->data() + *Addend);
            relocator().add_double(offset, con, false);
            _nof_consts++;
            _nof_locs++;
          } else if (*SecData == ".rodata.cst4") {
            float con = *(float*)(Value->data() + *Addend);
            relocator().add_float(offset, con);
            _nof_consts++;
            _nof_locs++;
          }
        }
      }
    }
  }
}

void LlvmCodeGen::fill_code_buffer(address src, uint64_t size, int& exc_offset, int& deopt_offset) {
  int vep_offset = method()->vep_offset();
  process_asm_info(vep_offset);

  size_t stubs_size = CompiledStaticCall::to_interp_stub_size() * nof_to_interp_stubs() + HandlerImpl::size_exception_handler() + HandlerImpl::size_deopt_handler();
  size_t consts_size = nof_consts() * wordSize;
  size_t code_size = size + 1; // in case the last instruction is a call, a nop will be inserted in the very end
  size_t cb_size = vep_offset + code_size + stubs_size + consts_size;
  _nof_locs += nof_Java_calls() + (vep_offset ? 1 : 0);
  cb()->initialize(cb_size, nof_locs() * sizeof(relocInfo));
  cb()->initialize_consts_size(consts_size);
  cb()->initialize_oop_recorder(C->env()->oop_recorder());
  _code_start = cb()->insts()->start();

  MacroAssembler ma(cb());
  _masm = &ma;
  if (C->is_osr_compilation()) {
    masm()->generate_osr_entry();
    relocator().add(new CallReloc());
  } else if (vep_offset != 0) {
    masm()->generate_unverified_entry();
  }
  address verified_entry_point = masm()->pc();
  assert(verified_entry_point - code_start() == vep_offset, "expected equal offsets");

  assert(verified_entry_point + size < cb()->insts()->limit(), "cannot memcpy");
  memcpy(verified_entry_point, src, size);
  masm()->code_section()->set_end(verified_entry_point + code_size);
  _code_end = verified_entry_point + size;
  *code_end() = NativeInstruction::nop_instruction_code;

  relocator().floats_to_cb();

  stack().set_frame_size(method()->frame_size());
  unsigned record_idx = 0;
  if (sm_parser()) {
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
  }

  // sorted vector is convenient for patching
  std::sort(debug_info().begin(), debug_info().end(),
    [&](const std::unique_ptr<DebugInfo>& a, const std::unique_ptr<DebugInfo>& b) {
      return a->pc_offset == b->pc_offset ? a->less(b.get()) : a->pc_offset < b->pc_offset;
    });
  
  for (size_t i = 0; i < debug_info().size(); ++i) {
    debug_info()[i]->handle(i, this);
  }

  scope_descriptor().describe_scopes();
  relocator().apply_relocs();
  cb()->initialize_stubs_size(stubs_size);
  add_stubs(exc_offset, deopt_offset);
  assert(code_start() == cb()->insts()->start(), "CodeBuffer was reallocated");
}

void LlvmCodeGen::process_asm_info(int vep_offset) {
  auto& EOI = asm_info()->EOI;
  auto& LOI = asm_info()->LOI;
  std::sort(LOI.begin(), LOI.end(), 
    [&](const std::unique_ptr<llvm::LateOffsetInfo>& a, const std::unique_ptr<llvm::LateOffsetInfo>& b) {
      return a->Offset < b->Offset;
    });
  size_t addend = vep_offset, loi_idx = 0;
  for (auto& info : EOI) {
    while ((loi_idx < LOI.size()) && (info->Offset + addend >= LOI[loi_idx]->Offset + vep_offset)) {
      addend += LOI[loi_idx++]->Addend();
    }
    std::unique_ptr<DebugInfo> di;
    size_t offset = info->Offset + addend;
    if (llvm::BlockOffsetInfo* block_info = info->asBlock()) {
      di = std::make_unique<BlockStartDebugInfo>();
      const llvm::BasicBlock* bb = block_info->Block;
      if (bb) {
        di->asBlockStart()->bb = bb;
        block_offsets().emplace(bb, offset);
      }
    } else if (llvm::ConstantOffsetInfo* constant_info = info->asConstant()) {
      if (!selector().consts().count(constant_info->Constant)) continue;
      DebugInfo::Type ty = selector().consts().at(constant_info->Constant);
      di = DebugInfo::create(DebugInfo::id(ty), this);
      inc_nof_consts();
      _nof_locs++;
    } else if (llvm::SwitchOffsetInfo* switch_info = info->asSwitch()) {
      di = std::make_unique<SwitchDebugInfo>(switch_info->Cases);
      _nof_consts += switch_info->Cases.size();
      _nof_locs += 1 + switch_info->Cases.size();
    }
    di->pc_offset = offset;
    debug_info().push_back(std::move(di));
  }
}

void LlvmCodeGen::add_stubs(int& exc_offset, int& deopt_offset) {
  if (C->has_method()) {
    for (const std::unique_ptr<DebugInfo>& di : debug_info()) {
      StaticCallDebugInfo* scdi = di->asStaticCall();
      if (!scdi) continue;
      MachCallJavaNode* cjn = scdi->scope_info->cjn;
      if (cjn->_method) {
        address call_site = addr(scdi->pc_offset) - NativeCall::instruction_size;
        cb()->insts()->set_mark(call_site);
        address stub = CompiledStaticCall::emit_to_interp_stub(*cb());
        assert(stub != NULL, "CodeCache is full");
      }
    }
    exc_offset = HandlerImpl::emit_exception_handler(*cb());
    deopt_offset = HandlerImpl::emit_deopt_handler(*cb());
  }
}
