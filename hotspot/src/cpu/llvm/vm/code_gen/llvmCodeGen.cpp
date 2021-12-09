#include "llvm/Object/ELFObjectFile.h"
#include "llvm/CodeGen/BuiltinGCs.h"
#include "llvm/CodeGen/FaultMaps.h"

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
        _has_exceptions = true;
      } else if (cmp_ideal_Opcode(n, Op_TailJump)) {
        _has_tail_jump = true;
      }
    }
  }
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
        llvm::ArrayRef<uint8_t> stackmap;
        uint64_t stackmap_size = sec.getSize();
        uint8_t* stackmap_start = (uint8_t*)obj_file_start + elf_sec.getOffset();
        stackmap = llvm::ArrayRef<uint8_t>(stackmap_start, stackmap_size);
        _sm_parser = std::make_unique<StackMapParser>(stackmap);
      } else if (sec_name == ".llvm_faultmaps") {
        const uint8_t* fm_start = (const uint8_t*)obj_file_start + elf_sec.getOffset();
        llvm::FaultMapParser fm_parser(fm_start, fm_start + sec.getSize());
        auto func_info = fm_parser.getFirstFunctionInfo();
        uint32_t n = func_info.getNumFaultingPCs();
        C->inc_table()->set_size(n);
        for (auto i = 0; i < n; ++i) {
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
            const double con = *(double*)(Value->data() + *Addend);
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
  size_t code_size = size + 1; // in case call is the last instruction, a nop will be inserted in the last byte
  size_t cb_size = vep_offset + code_size + stubs_size;
  size_t locs_size = 1 + nof_Java_calls() + (vep_offset ? 1 : 0);
  cb()->initialize(cb_size, locs_size * sizeof(relocInfo));
  cb()->initialize_consts_size(nof_consts());
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

  if (sm_parser()) {
    stack().set_frame_size(method()->frame_size());
    debug_info().reserve(sm_parser()->getNumRecords());
    unsigned record_idx = 0;
    for (RecordAccessor record: sm_parser()->records()) {
      uint64_t id = record.getID();
      std::unique_ptr<DebugInfo> di = DebugInfo::create(id);
      di->pc_offset = vep_offset + record.getInstructionOffset();
      BlockStartDebugInfo* bdi = di->asBlockStartDebugInfo();
      if (bdi) {
        bdi->block = blocks()[bdi->idx];
      }
      CallDebugInfo* cdi = di->asCallDebugInfo();
      if (cdi) {
        cdi->record_idx = record_idx;
        cdi->scope_info = &selector().scope_info()[cdi->idx];
        assert(cdi->scope_info->stackmap_id == id, "different ids");
      }
      record_idx++;
      debug_info().push_back(std::move(di));
    }

    std::sort(debug_info().begin(), debug_info().end(),
      [&](const std::unique_ptr<DebugInfo>& a, const std::unique_ptr<DebugInfo>& b) {
        if (a->pc_offset == b->pc_offset) {
          BlockStartDebugInfo* a_bl = a->asBlockStartDebugInfo();
          InblockDebugInfo* a_in = a->asInblockDebugInfo();
          BlockStartDebugInfo* b_bl = b->asBlockStartDebugInfo();
          InblockDebugInfo* b_in = b->asInblockDebugInfo();
          // a block or inblock starts after a call
          if (a->asCallDebugInfo()) {
            assert(b_bl || b_in, "should be BlockStart or Inblock");
            return true;
          }
          if (b->asCallDebugInfo()) {
            assert(a_bl || a_in, "should be BlockStart or Inblock");
            return false;
          }
          // a block starts after CreateException
          if (a->asExceptionDebugInfo()) {
            assert(b_bl, "should be BlockStart or Inblock");
            return true;
          } 
          if (b->asExceptionDebugInfo()) {
            assert(a_bl, "should be BlockStart or Inblock");
            return false;
          }
          // one block contains just a jump and is optimized out
          if (a_bl && b_bl) {
            size_t i;
            for (i = 1; a_bl->block->get_node(i)->is_Phi(); ++i);
            return a_bl->block->get_node(i)->is_MachGoto();
          }
          ShouldNotReachHere();
        }
        return a->pc_offset < b->pc_offset;
      });
    
    std::unordered_map<size_t, uint32_t> call_offsets;
    std::vector<size_t> block_offsets;
    if (has_exceptions()) {
      block_offsets.resize(C->cfg()->number_of_blocks());
      call_offsets.reserve(nof_Java_calls());
    }
    unsigned call_cnt = 0;
    for (auto it = debug_info().begin(); it != debug_info().end(); ++it) {
      switch ((*it)->type()) {
        case DebugInfo::StaticCall:
        case DebugInfo::DynamicCall: {
          call_cnt++;
          patch_call(it, call_offsets);
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
        case DebugInfo::BlockStart: {
          BlockStartDebugInfo* di = (*it)->asBlockStartDebugInfo();
          block_offsets[di->idx] = di->pc_offset;
        }
      }
    }
    assert(call_cnt <= nof_Java_calls(), "unexpected number of calls");
    scope_descriptor().describe_scopes();
    relocator().apply_relocs(&masm);
    fill_handler_table(block_offsets, call_offsets);
  }
  cb()->initialize_stubs_size(stubs_size);
  add_stubs(exc_offset, deopt_offset);
  assert(code_start() == cb()->insts()->start(), "CodeBuffer was reallocated");
}

void LlvmCodeGen::patch_call(std::vector<std::unique_ptr<DebugInfo>>::iterator it, std::unordered_map<size_t, uint32_t>& call_offsets) {
  CallDebugInfo* di = (*it)->asCallDebugInfo();
  MachCallNode* cn = di->scope_info->cn;
  address next_inst = code_start() + di->pc_offset;
  address call_site = next_inst - sizeof(uint32_t);
  call_site = (address)((intptr_t)call_site & -BytesPerInt); // should be aligned by BytesPerInt
  address pos, nop_end = call_site - NativeCall::displacement_offset, call_start = nop_end;

  if (di->asDynamicCallDebugInfo()) {
    pos = nop_end -= NativeMovConstReg::instruction_size;
    const byte movabs = 0x48, rax = 0xb8;
    *(pos++) = movabs;
    *(pos++) = rax;
    *(uintptr_t*)pos = (uintptr_t)Universe::non_oop_word();
  }

  pos = next_inst - DebugInfo::patch_bytes(di->type());
  while (pos < nop_end) {
    *(pos++) = NativeInstruction::nop_instruction_code;
  }

  pos = call_start;
  address ret_addr = pos + NativeCall::return_address_offset;
  di->call_offset = pos - code_start();
  *(pos++) = NativeCall::instruction_code;
  *(uint32_t*)pos = cn->entry_point() - ret_addr;
  pos += sizeof(uint32_t);
  di->pc_offset = pos - code_start();

  if (has_exceptions()) {
    assert(it != debug_info().begin(), "there should be BlockStart before");
    BlockStartDebugInfo* bdi = (*(it - 1))->asBlockStartDebugInfo();
    if (!bdi) {
      assert((*(it - 1))->asExceptionDebugInfo() && (it - 1 != debug_info().begin()), "only other option is Exception");
      bdi = (*(it - 2))->asBlockStartDebugInfo();
      assert(bdi, "should be BlockStart");
    }
    assert(call_offsets.count(bdi->idx) == 0, "there is already a call for this block");
    call_offsets.emplace(bdi->idx, di->pc_offset);
  }

  while (pos < next_inst) {
    *(pos++) = NativeInstruction::nop_instruction_code;
  }

  relocator().add(di, di->call_offset);
}

void LlvmCodeGen::patch_rethrow_exception(std::vector<std::unique_ptr<DebugInfo>>::iterator it) {
  // [nop*4|add rsp, pop rbp, etc. |retq|
  // [add rsp, pop rbp, etc.| jmpq dest |
  RethrowDebugInfo* di = (*it)->asRethrowDebugInfo();
  size_t pb = DebugInfo::patch_bytes(DebugInfo::Rethrow);

  address retq_addr = code_end();
  auto next_it = it + 1;
  if (next_it != debug_info().end()) {
    assert((*next_it)->asBlockStartDebugInfo() || (*next_it)->asInblockDebugInfo(), "should be Block or Inblock");
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
  TailJumpDebugInfo* di = (*it)->asTailJumpDebugInfo();
  size_t pb = DebugInfo::patch_bytes(DebugInfo::TailJump);
  assert(it != debug_info().begin(), "there should be PatchBytes before");
  PatchBytesDebugInfo* pbdi = (*(it - 1))->asPatchBytesDebugInfo();
  assert(pbdi && di->pc_offset - pbdi->pc_offset == pb, "wrong distance");

  address pos = code_start() + pbdi->pc_offset, start_pos = pos;
  patch(pos, DebugInfo::MOV_RDX);
  patch(pos, DebugInfo::MOV_R10);

  address next_addr = code_end();
  auto next_it = it + 1;
  if (next_it != debug_info().end()) {
    assert((*next_it)->asBlockStartDebugInfo() || (*next_it)->asInblockDebugInfo(), "should be BlockStart or Inblock");
    next_addr = code_start() + (*next_it)->pc_offset;
  }
  assert(next_addr[-NativeReturn::instruction_size] == NativeReturn::instruction_code, "not retq");

  size_t offset = pb - (pos - start_pos), footer_size = DebugInfo::ADD_0x8_RSP.size() + DebugInfo::JMPQ_R10.size();
  do {
    pos[0] = pos[offset];
  } while (++pos != next_addr - footer_size);
  patch(pos, DebugInfo::ADD_0x8_RSP);
  patch(pos, DebugInfo::JMPQ_R10);
}

void LlvmCodeGen::patch(address& pos, const std::vector<byte>& inst) {
  for (size_t i = 0; i < inst.size(); ++i) {
    *(pos++) = inst[i];
  }
}

void LlvmCodeGen::add_stubs(int& exc_offset, int& deopt_offset) {
  if (C->has_method()) {
    for (const std::unique_ptr<DebugInfo>& di : debug_info()) {
      CallDebugInfo* cdi = di->asCallDebugInfo();
      if (!cdi) continue;
      MachCallJavaNode* cjn = cdi->scope_info->cjn;
      if (cjn->is_MachCallStaticJava() && cjn->_method) {
        address call_site = code_start() + cdi->call_offset;
        cb()->insts()->set_mark(call_site);
        address stub = CompiledStaticCall::emit_to_interp_stub(*cb());
        assert(stub != NULL, "CodeCache is full");
      }
    }
    exc_offset = HandlerImpl::emit_exception_handler(*cb());
    deopt_offset = HandlerImpl::emit_deopt_handler(*cb());
  }
}

void LlvmCodeGen::fill_handler_table(const std::vector<size_t>& block_offsets, const std::unordered_map<size_t, uint32_t>& call_offsets) {
  for (const auto& pair : selector().handler_table()) {
    size_t size = pair.second.size();
    GrowableArray<intptr_t> handler_bcis(size);
    GrowableArray<intptr_t> handler_pcos(size);
    CatchNode* c = pair.first->end()->as_Catch();  
    for (size_t i = 0, j = 0; j < size; ++i) {
      CatchProjNode* cp = c->raw_out(i)->as_CatchProj();
      if (cp->_con != CatchProjNode::fall_through_index) {
        handler_bcis.append(cp->handler_bci());
        handler_pcos.append(block_offsets[pair.second[j]->_pre_order - 1]);
        j++;
      }
    }
    C->handler_table()->add_subtable(call_offsets.at(pair.first->_pre_order - 1), &handler_bcis, NULL, &handler_pcos);
  }
}