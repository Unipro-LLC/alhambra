#include "llvm/Object/ELFObjectFile.h"
#include "llvm/CodeGen/BuiltinGCs.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/MC/_BBSCounter.h"

#include "llvmCodeGen.hpp"

#include "code/compiledIC.hpp"
#include "opto/compile.hpp"
#include "opto/runtime.hpp"
#include "opto/cfgnode.hpp"

#include "llvm_globals.hpp"
#include "method_llvm.hpp"
#include "adfiles/ad_llvm.hpp"

LlvmCodeGen::LlvmCodeGen(LlvmMethod* method, Compile* c, const char* name) :
  C(c),
  _cb(C->code_buffer()),
  _ctx(),
  _mod_owner(std::make_unique<llvm::Module>("normal", ctx())),
  _mod(_mod_owner.get()),
  _method(method),
  _selector(this, name),
  _scope_descriptor(this),
  _relocator(this),
  _stack(this)
{
  _blocks.resize(C->cfg()->number_of_blocks());
  for (size_t i = 0; i < C->cfg()->number_of_blocks(); ++i) {
    Block* b = C->cfg()->get_block(i);
    _blocks[b->_pre_order - 1] = b; // 0th block is B1, 1st - B2 and so on
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
  llvm::EngineBuilder builder(std::move(_mod_owner));
  builder
    .setEngineKind(llvm::EngineKind::JIT)
    .setOptLevel(llvm::CodeGenOpt::Aggressive);
  llvm::linkAllBuiltinGCs();
  llvm::TargetMachine* TM = builder.selectTarget();
  mod()->setDataLayout(TM->createDataLayout());
  llvm::MCContext* ctx = nullptr;
  llvm::raw_svector_ostream ObjStream(ObjBufferSV);
  llvm::cantFail(mod()->materializeAll());

  llvm::legacy::FunctionPassManager FPM(mod());
  FPM.run(*selector().func());

  llvm::legacy::PassManager PM;
  PM.add(llvm::createRewriteStatepointsForGCLegacyPass());
  TM->addPassesToEmitMC(PM, ctx, ObjStream, false);
  TM->setFastISel(false);
  PM.run(*mod());

  selector().func()->deleteBody();
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
          if (*SecData == ".rodata.cst8") {
            double con = *(double*)(Value->data() + *Addend);
            relocator().add_double(offset, con);
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
  debug_info().reserve(sm_parser()->getNumRecords() + llvm::BasicBlockSizes.size());
  unsigned record_idx = 0;
  for (RecordAccessor record: sm_parser()->records()) {
    uint64_t id = record.getID();
    std::unique_ptr<DebugInfo> di = DebugInfo::create(id, this);
    di->pc_offset = vep_offset + record.getInstructionOffset();

    GCDebugInfo* gcdi = di->asGC();
    if (gcdi) {
      gcdi->oopmap = new OopMap(stack().frame_size() / BytesPerInt, C->has_method() ? C->method()->arg_size() : 0);
      gcdi->record_idx = record_idx;
      SafePointDebugInfo* spdi = di->asSafePoint();
      if (spdi) {
        spdi->scope_info = scope_descriptor().scope_info()[DebugInfo::idx(id)].get();
        assert(spdi->scope_info->stackmap_id == id, "different ids");
      }
    }

    record_idx++;
    debug_info().push_back(std::move(di));
  }

  auto block_offsets = count_block_offsets(vep_offset);

  // sorted vector is convenient for patching
  std::sort(debug_info().begin(), debug_info().end(),
    [&](const std::unique_ptr<DebugInfo>& a, const std::unique_ptr<DebugInfo>& b) {
      return a->pc_offset == b->pc_offset ? a->less(b.get()) : a->pc_offset < b->pc_offset;
    });
  
  for (auto it = debug_info().begin(); it != debug_info().end(); ++it) {
    switch ((*it)->type()) {
      case DebugInfo::Call:
      case DebugInfo::StaticCall:
      case DebugInfo::DynamicCall: {
        CallDebugInfo* cdi = (*it)->asCall();
        patch_call(cdi);
        add_exception(cdi, block_offsets);
        break;
      }
      case DebugInfo::Rethrow: {
        patch_rethrow_exception(it);
        break;
      }
      case DebugInfo::TailJump: {
        patch_tail_jump(it);
        break;
      }
      case DebugInfo::Constant: {
        reloc_const(it);
        break;
      }
    }
  }
  scope_descriptor().describe_scopes();
  relocator().apply_relocs(&masm);
  cb()->initialize_stubs_size(stubs_size);
  add_stubs(exc_offset, deopt_offset);
  assert(code_start() == cb()->insts()->start(), "CodeBuffer was reallocated");
}

std::unordered_map<const llvm::BasicBlock*, size_t> LlvmCodeGen::count_block_offsets(int vep_offset) {
  std::unordered_map<const llvm::BasicBlock*, size_t> block_offsets;
  block_offsets.reserve(llvm::BasicBlockSizes.size());
  std::sort(llvm::RelaxSizes.begin(), llvm::RelaxSizes.end());
  std::sort(llvm::AlignSizes.begin(), llvm::AlignSizes.end());
  size_t offset = vep_offset;
  size_t rel_idx = 0, al_idx = 0;

  for (auto& pair : llvm::BasicBlockSizes) {
    if (pair.second == 0) continue;
    // these DebugInfo-s may come in handy during patching 
    std::unique_ptr<DebugInfo> di = DebugInfo::create(DebugInfo::id(DebugInfo::BlockStart), this);
    di->pc_offset = offset;
    debug_info().push_back(std::move(di));
    if (pair.first) {
      block_offsets.emplace(pair.first, offset); // basic block pointers are dangling at this point
    }
    offset += pair.second;
    if (rel_idx < llvm::RelaxSizes.size() && offset > llvm::RelaxSizes[rel_idx].first + vep_offset) {
      offset += llvm::RelaxSizes[rel_idx++].second - llvm::JCC_SIZE;
    }
    if (al_idx < llvm::AlignSizes.size() && offset > llvm::AlignSizes[al_idx].first + vep_offset) {
      offset += llvm::AlignSizes[al_idx++].second;
    }
  }
  llvm::BasicBlockSizes.clear();
  llvm::RelaxSizes.clear();
  llvm::AlignSizes.clear();
  return block_offsets;
}

void LlvmCodeGen::patch_call(CallDebugInfo* di) {
  PatchInfo* pi = di->patch_info;
  if (pi->size == 0) return;
  JavaCallDebugInfo* jcdi = di->asJavaCall();
  MachCallNode* cn = di->scope_info->cn;
  address next_inst = code_start() + di->pc_offset;
  SpillPatchInfo* spi = pi->asSpill();
  size_t max_spill = selector().max_spill(), spill_size = spi ? max_spill - spi->spill_size : max_spill;
  bool patch_spill = max_spill && spill_size;
  address call_site = next_inst - sizeof(uint32_t);

  if (patch_spill) {
    call_site -= PatchInfo::ADD_RSP_SIZE;
  }

  if (jcdi) {
    call_site = (address)((intptr_t)call_site & -BytesPerInt); // should be aligned by BytesPerInt
  }

  address pos, nop_end = call_site - NativeCall::displacement_offset, call_start = nop_end;

  if (di->asDynamicCall()) {
    pos = nop_end -= NativeMovConstReg::instruction_size;
    const byte movabs = 0x48, rax = 0xb8;
    *(pos++) = movabs;
    *(pos++) = rax;
    *(uintptr_t*)pos = (uintptr_t)Universe::non_oop_word();
  }

  if (patch_spill) {
    std::vector<byte> SUB_RSP = PatchInfo::SUB_x_RSP(spill_size);
    pos = nop_end -= SUB_RSP.size();
    patch(pos, SUB_RSP);
  }

  pos = next_inst - pi->size;
  while (pos < nop_end) {
    *(pos++) = NativeInstruction::nop_instruction_code;
  }

  pos = call_start;
  address ret_addr = pos + NativeCall::return_address_offset;
  if (jcdi) {
    jcdi->call_offset = pos - code_start();
  }
  *(pos++) = NativeCall::instruction_code;
  *(uint32_t*)pos = cn->entry_point() - ret_addr;
  pos += sizeof(uint32_t);
  di->pc_offset = pos - code_start();

  if (patch_spill) {
    std::vector<byte> ADD_RSP = PatchInfo::ADD_x_RSP(spill_size);
    patch(pos, ADD_RSP);
  }

  while (pos < next_inst) {
    *(pos++) = NativeInstruction::nop_instruction_code;
  }

  if (jcdi) {
    relocator().add(jcdi, jcdi->call_offset);
  }
}


void LlvmCodeGen::patch_rethrow_exception(std::vector<std::unique_ptr<DebugInfo>>::iterator it) {
  // [nop*4|add rsp, pop rbp, etc. |retq|
  // [add rsp, pop rbp, etc.| jmpq dest |
  RethrowDebugInfo* di = (*it)->asRethrow();
  size_t pb = di->patch_info->size;

  address retq_addr = code_end();
  auto next_it = it + 1;
  if (next_it != debug_info().end()) {
    assert((*next_it)->asBlockStart(), "should be BlockStart");
    retq_addr = code_start() + (*next_it)->pc_offset;
  }
  retq_addr -= NativeReturn::instruction_size;
  assert(*retq_addr == NativeReturn::instruction_code, "not retq");

  address pos = code_start() + di->pc_offset - pb;
  do {
    pos[0] = pos[pb];
  } while (++pos != (retq_addr - pb));
  size_t rel_off = pos - code_start();
  *(pos++) = NativeJump::instruction_code;
  *(uint32_t*)pos = OptoRuntime::rethrow_stub() - (pos + sizeof(uint32_t));

  relocator().add(di, rel_off);
}

void LlvmCodeGen::patch_tail_jump(std::vector<std::unique_ptr<DebugInfo>>::iterator it) {
  // |                  nop*8                 |   nop*6   |  add rsp, pop rbp, etc.   |retq|
  // |mov rdx,[rbp - 0x8]|mov r10,[rbp - 0x10]|add rsp, pop rbp, etc.|add rsp, 0x8|jmpq r10|
  TailJumpDebugInfo* di = (*it)->asTailJump();
  size_t pb = di->patch_info->size;
  assert(it != debug_info().begin(), "there should be PatchBytes before");
  PatchBytesDebugInfo* pbdi = (*(it - 1))->asPatchBytes();
  assert(pbdi && di->pc_offset - pbdi->pc_offset == pb, "wrong distance");

  address pos = code_start() + pbdi->pc_offset, start_pos = pos;
  patch(pos, PatchInfo::MOV_RDX);
  patch(pos, PatchInfo::MOV_R10);

  address next_addr = code_end();
  auto next_it = it + 1;
  if (next_it != debug_info().end()) {
    assert((*next_it)->asBlockStart(), "should be BlockStart");
    next_addr = code_start() + (*next_it)->pc_offset;
  }
  assert(next_addr[-NativeReturn::instruction_size] == NativeReturn::instruction_code, "not retq");

  std::vector<byte> ADD_0x8_RSP = PatchInfo::ADD_x_RSP(0x8);
  size_t offset = pb - (pos - start_pos), footer_size = ADD_0x8_RSP.size() + PatchInfo::JMPQ_R10.size();
  do {
    pos[0] = pos[offset];
  } while (++pos != next_addr - footer_size);
  patch(pos, ADD_0x8_RSP);
  patch(pos, PatchInfo::JMPQ_R10);
}

void LlvmCodeGen::reloc_const(std::vector<std::unique_ptr<DebugInfo>>::iterator it) {
  // Constant ... MOVABS REG, IMM ... PatchBytes
  ConstantDebugInfo* di = (*it)->asConstant();
  address pos = code_start() + di->pc_offset;
  const size_t mov_reg_size = 3, size = NativeMovConstReg::instruction_size;
  auto mov = [](address pos) -> bool { return pos[0] == 0x48 || pos[0] == 0x49; };
  auto mov_mem = [](address pos) -> bool { return pos[1] == 0x8B; };
  auto movabs = [](address pos) -> bool { return pos[1] >= 0xB8 && pos[1] <= 0xBF; };
  auto mov_reg = [](address pos) -> bool { return pos[1] == 0x89; };
  if (mov(pos)) {
    if (mov_mem(pos)) return; // it's not the first load of this constant and there's already a relocation
    if (!movabs(pos)) { // try looking from the other end
      assert(mov_reg(pos), "expected MOV REG, REG");
      assert(it != debug_info().end(), "expected PatchBytes next");
      PatchBytesDebugInfo* pbdi = (*(it + 1))->asPatchBytes();
      assert(pbdi, "probably incorrect sorting");
      pos = code_start() + pbdi->pc_offset - (mov_reg_size + size);
      assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
      assert(mov(pos + size) && mov_mem(pos + size), "expected MOV REG, [REG]");
    }
  } else { // the constant is somewhere in between Constant and PatchBytes, so far we can only handle individual cases 
    Unimplemented();
    auto test_eax = [](address pos) -> bool { return pos[0] == 0x85 && pos[1] == 0xC0; };
    assert(test_eax(pos), "expected TEST EAX, EAX");
    size_t test_eax_size = 2;
    pos += test_eax_size;
    assert(mov(pos) && movabs(pos), "expected MOVABS REG, IMM");
  }
  di->con = *(uintptr_t*)(pos + size - wordSize);
  relocator().add(di, pos - code_start());
}

void LlvmCodeGen::patch(address& pos, const std::vector<byte>& inst) {
  for (size_t i = 0; i < inst.size(); ++i) {
    *(pos++) = inst[i];
  }
}

void LlvmCodeGen::add_stubs(int& exc_offset, int& deopt_offset) {
  if (C->has_method()) {
    for (const std::unique_ptr<DebugInfo>& di : debug_info()) {
      StaticCallDebugInfo* scdi = di->asStaticCall();
      if (!scdi) continue;
      MachCallJavaNode* cjn = scdi->scope_info->cjn;
      if (cjn->_method) {
        address call_site = code_start() + scdi->call_offset;
        cb()->insts()->set_mark(call_site);
        address stub = CompiledStaticCall::emit_to_interp_stub(*cb());
        assert(stub != NULL, "CodeCache is full");
      }
    }
    exc_offset = HandlerImpl::emit_exception_handler(*cb());
    deopt_offset = HandlerImpl::emit_deopt_handler(*cb());
  }
}

void LlvmCodeGen::add_exception(CallDebugInfo* di, const std::unordered_map<const llvm::BasicBlock*, size_t>& block_offsets) {
  ThrowScopeInfo* tsi = di->scope_info->asThrow();
  if (!tsi) return;
  ExceptionInfo& ei = selector().exception_info().at(tsi->bb);
  GrowableArray<intptr_t> handler_bcis(ei.size());
  GrowableArray<intptr_t> handler_pcos(ei.size());
  for (const auto& pair : ei) {
    handler_bcis.append(pair.second);
    handler_pcos.append(block_offsets.at(pair.first));
  }
  C->handler_table()->add_subtable(di->pc_offset, &handler_bcis, NULL, &handler_pcos);
}
