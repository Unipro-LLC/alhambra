#include "opto/cfgnode.hpp"
#include "opto/locknode.hpp"
#include "opto/runtime.hpp"

#include "adfiles/ad_llvm.hpp"
#include "selector_llvm.hpp"
#include "code_gen/llvmCodeGen.hpp"

llvm::Value* tlsLoadPNode::select(Selector* sel) {                                          
  return sel->thread();
}

llvm::Value* storePNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value *addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  sel->store(value, addr);
  return NULL;
}

llvm::Value* MachProjNode::select(Selector* sel) {
  if (bottom_type()->isa_oopptr() != NULL) {
    sel->oops().push_back(this);
  }
  if (in(0)->is_Start()) {
    if (_con == TypeFunc::FramePtr) {
      // In this case the node is used in stubs to set last_Java_sp
      // which should satisfy JavaFrameAnchor::capture_last_Java_pc
      LlvmStack& stack = sel->cg()->stack();
      int sp_offset = -2 * wordSize;
      return sel->gep(stack.FP(), sp_offset);
    }
    if (_con == TypeFunc::ReturnAdr) {
      return sel->ret_addr(sel->cg()->is_rethrow_stub());
    }
    if (_con < TypeFunc::Parms) {
      return NULL;
    }
    int arg_num = sel->param_to_arg(_con);
    llvm::Value* arg = sel->func()->arg_begin() + arg_num;
    assert(bottom_type()->isa_narrowoop() == NULL, "unexpected narrow ptr");
    return arg;
  }
  if (ideal_reg() == 0 || ideal_reg() == 999) {
    return NULL;
  } else {
    llvm::Value* res = sel->select_node(in(0));
    assert(res, "We expect return value from a call");
    return res;
  }
}

llvm::Value* CallRuntimeDirectNode::select(Selector* sel) {
  llvm::Type* retType = sel->type(tf()->return_type());
  return sel->call(this, retType, sel->call_args(this));
}

llvm::Value* CallLeafDirectNode::select(Selector* sel) {
  BasicType ret_type = tf()->return_type();
  assert(ret_type != T_NARROWOOP, "unexpected behavior check");
  llvm::Value* ret =  sel->call_C(entry_point(), sel->type(ret_type), sel->call_args(this));
  if (ret_type == T_OBJECT || ret_type == T_ARRAY) {
    sel->oops().push_back(this);
  }
  return ret;
}

llvm::Value* storeImmP0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_ADDRESS), addr);
  return NULL;
}

llvm::Value* loadPNode::select(Selector* sel) {
  bool is_oop = bottom_type()->isa_oopptr() != NULL;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, is_oop ? T_OBJECT : T_ADDRESS);
  if (is_oop) {
    sel->oops().push_back(this);
  }
  return res;
}

llvm::Value* cmpP_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  a = sel->builder().CreatePointerCast(a, b->getType());
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* jmpConUNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  sel->select_if(pred, this);
  return NULL;
}

llvm::Value* loadConPNode::select(Selector* sel) {
  llvm::Value* con = sel->select_oper(opnd_array(1));
  if (bottom_type()->isa_oopptr() != NULL) {
    sel->oops().push_back(this);
  }
  return con;
}

llvm::Value* TailCalljmpIndNode::select(Selector* sel) {
  address target = sel->cg()->is_rethrow_stub() ? StubRoutines::forward_exception_compiler_rethrow_entry() : StubRoutines::forward_exception_compiler_entry();
  llvm::Value* jump_target = sel->get_ptr(target, T_ADDRESS);
  sel->builder().CreateIndirectBr(jump_target);
  return NULL;
}

llvm::Value* RetNode::select(Selector* sel) {
  llvm::Type* retType = sel->func()->getReturnType();
  if (!retType->isVoidTy()) {
    Node* ret_node = in(TypeFunc::Parms);
    assert(ret_node != NULL, "check");
    llvm::Value* ret_value = sel->select_node(ret_node);
    ret_value = sel->builder().CreatePointerCast(ret_value, retType);
    sel->builder().CreateRet(ret_value);
  }
  else {
    sel->builder().CreateRetVoid();
  }
  return NULL;
}

llvm::Value* loadConINode::select(Selector* sel) {
  return sel->select_oper(opnd_array(1));
}

llvm::Value* loadConFNode::select(Selector* sel) {
  return sel->select_oper(opnd_array(1));
}

llvm::Value* tailjmpIndNode::select(Selector* sel) {
  llvm::Type* retType = sel->func()->getReturnType();
  std::vector<llvm::Value*> args = {
    sel->builder().getInt64(MacroAssembler::COMPILER_CC),
    retType->isVoidTy() ? sel->null(T_ADDRESS) : sel->select_node(in(TypeFunc::Parms + 1)), // exception oop
    sel->ret_addr(true),
  };
  uint64_t id = DebugInfo::id(DebugInfo::PatchBytes);
  // fake call to pass arguments to exception handler
  llvm::FunctionCallee callee = sel->callee(OptoRuntime::exception_blob(), sel->type(T_VOID), args);
  sel->builder().CreateGCStatepointCall(id, 1, callee.getCallee(), args, llvm::None, {});
  llvm::Value* target_pc = sel->select_node(in(TypeFunc::Parms));
  sel->builder().CreateIndirectBr(target_pc);
  return NULL;
}

llvm::Value* loadTLABtopNode::select(Selector* sel) {
  return sel->load(sel->tlab_top(), T_ADDRESS);
}

llvm::Value* loadTLABendNode::select(Selector* sel) {
  return sel->load(sel->tlab_end(), T_ADDRESS);
}

llvm::Value* addP_rReg_immNode::select(Selector* sel) {
  llvm::Value* base = sel->select_node(in(2));
  llvm::Value* offset = sel->select_oper(opnd_array(2));
  return sel->gep(base, offset);
}


llvm::Value* cmpP_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  a = sel->builder().CreatePointerCast(a, b->getType());
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* storeTLABtopNode::select(Selector* sel) {
  sel->store(sel->select_node(in(MemNode::ValueIn)), sel->tlab_top());
  return NULL;
}

llvm::Value* prefetchAllocNTANode::select(Selector* sel) {
  llvm::Value *addr = sel->select_address(this),
    *fetch_read = sel->builder().getInt32(0),
    *locality_none = sel->builder().getInt32(0),
    *cache_data = sel->builder().getInt32(1);

  sel->builder().CreateIntrinsic(llvm::Intrinsic::prefetch, { sel->type(T_ADDRESS) }, { addr, fetch_read, locality_none, cache_data });
  return NULL;
}

llvm::Value* prefetchAllocNode::select(Selector* sel) {
  llvm::Value *addr = sel->select_address(this),
    *fetch_read = sel->builder().getInt32(0),
    *locality_L1 = sel->builder().getInt32(1),
    *cache_data = sel->builder().getInt32(1);

  sel->builder().CreateIntrinsic(llvm::Intrinsic::prefetch, { sel->type(T_ADDRESS) }, { addr, fetch_read, locality_L1, cache_data });
  return NULL;
}

llvm::Value* loadConNKlassNode::select(Selector* sel) {
  assert(opnd_array(1)->type()->basic_type() == T_NARROWKLASS,"type check");
  return sel->select_oper(opnd_array(1));
}

llvm::Value* decodeKlass_not_nullNode::select(Selector* sel) {
  llvm::Value* narrow_klass = sel->select_node(in(1));
  return sel->decodeKlass_not_null(narrow_klass);
}

llvm::Value* storeNKlassNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_NARROWKLASS), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* storeImmI0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_INT), addr);
  return NULL;
}

llvm::Value* jmpDirNode::select(Selector* sel) {
  Block* target = sel->block()->non_connector_successor(0);
  sel->builder().CreateBr(sel->basic_block(target));
  return NULL;
}

llvm::Value* CallStaticJavaDirectNode::select(Selector* sel) {
  std::vector<llvm::Value*> args = sel->call_args(this);
  sel->callconv_adjust(args);
  BasicType ret_type = tf()->return_type();
  assert(ret_type != T_NARROWOOP, "unexpected behavior check");
  llvm::Type* retType = sel->type(ret_type);
  llvm::Value* ret = sel->call(this, retType, args);

  if (ret_type == T_OBJECT || ret_type == T_ARRAY) {
    sel->oops().push_back(this);
  }
  return ret;
}

llvm::Value* CallDynamicJavaDirectNode::select(Selector* sel) {
  std::vector<llvm::Value*> args = sel->call_args(this);
  sel->callconv_adjust(args);
  BasicType ret_type = tf()->return_type();
  assert(ret_type != T_NARROWOOP, "unexpected behavior check");
  llvm::Type* retType = sel->type(ret_type);
  llvm::Value* ret = sel->call(this, retType, args);

  if (ret_type == T_OBJECT || ret_type == T_ARRAY) {
    sel->oops().push_back(this);
  }
  return ret;
}

llvm::Value* membar_storestoreNode::select(Selector* sel) {
  // this barrier is used for cpu self-visibility of store ordering
  return NULL;
}

llvm::Value* checkCastPPNode::select(Selector* sel) {
  sel->oops().push_back(this);
  llvm::Value* ptr = sel->select_node(in(1));
  return sel->builder().CreatePointerCast(ptr, sel->type(T_OBJECT));
}

llvm::Value* PhiNode::select(Selector* sel) {
  assert(sel->C->cfg()->get_block_for_node(region())->non_connector() == sel->block(), "sanity check");
  BasicType bt = type()->basic_type();
  bool is_narrow_oop = type()->isa_narrowoop() != NULL;
  assert(UseCompressedOops || !is_narrow_oop, "sanity check");
  if (bt == T_ILLEGAL) return NULL;
  llvm::Type* data_type = sel->type(bt);
  llvm::PHINode* phi = sel->builder().CreatePHI(data_type, sel->block()->num_preds());
  sel->map_phi_nodes(this, phi);
  
  if (type()->isa_oopptr() != NULL) {
    if (type()->is_oopptr()->offset() == 0) {
      sel->oops().push_back(this);
    }
  } else if (is_narrow_oop) {
    sel->narrow_oops().push_back(llvm::cast<llvm::Instruction>(phi));
  }
  return phi;
}

llvm::Value* CreateExceptionNode::select(Selector* sel) {
  // on x86 in the exception blob exc_oop is put into a register and the corresponding thread's field is cleared
  // we can't do that so we delay the extraction and clearance until runtime enters this node
  // it should happen just after jumping from the exception blob
  llvm::Value* eo_offset = sel->builder().getInt32(in_bytes(JavaThread::exception_oop_offset()));
  llvm::Value* eo_addr = sel->gep(sel->thread(), eo_offset);
  llvm::Value* exc_oop = sel->load(eo_addr, T_OBJECT);
  // now we can finally clear the exception oop
  sel->store(sel->null(T_OBJECT), eo_addr);
  sel->oops().push_back(this);
  return exc_oop;
}

llvm::Value* RethrowExceptionNode::select(Selector* sel) {
  llvm::Value* exc_oop = sel->select_node(in(TypeFunc::Parms));
  std::vector<llvm::Value*> args = { exc_oop, sel->ret_addr() };
  sel->callconv_adjust(args);
  uint64_t id = DebugInfo::id(DebugInfo::PatchBytes);
  // fake call to pass arguments to rethrow_Java
  llvm::FunctionCallee callee = sel->callee(OptoRuntime::rethrow_stub(), sel->type(T_VOID), args);
  sel->builder().CreateGCStatepointCall(id, 1, callee.getCallee(), args, llvm::None, {});
  llvm::Value* jump_target = sel->builder().getInt64((uintptr_t)OptoRuntime::rethrow_stub());
  llvm::Value* ret_addr_slot = sel->builder().CreateIntrinsic(llvm::Intrinsic::addressofreturnaddress, { sel->type(T_ADDRESS) }, {});
  sel->store(jump_target, ret_addr_slot);
  llvm::Type* retType = sel->func()->getReturnType();
  if (!retType->isVoidTy()) {
    sel->builder().CreateRet(sel->null(retType));
  }
  else {
    sel->builder().CreateRetVoid();
  }
  return NULL;
}

llvm::Value* storeImmL0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_LONG), addr);
  return NULL;
}

llvm::Value* loadNNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_NARROWOOP);
  sel->narrow_oops().push_back(llvm::cast<llvm::Instruction>(res));
  return res;
}

llvm::Value* decodeHeapOopNode::select(Selector* sel) {
  llvm::Value* narrow_oop = sel->select_node(in(1));
  if (sel->is_fast_compression()) return narrow_oop;
  sel->oops().push_back(this);
  return sel->decode_heap_oop(narrow_oop, false);
}

llvm::Value* ShouldNotReachHereNode::select(Selector* sel) {
  sel->builder().CreateUnreachable();
  return NULL;
}

llvm::Value* addI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAdd(a, b);
}

llvm::Value* addI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateAdd(a, b);
}

llvm::Value* addL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAdd(a, b);
}

llvm::Value* addL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateAdd(a, b);
}

llvm::Value* addF_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFAdd(a, b);
}

llvm::Value* subI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateSub(a, b);
}

llvm::Value* subI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateSub(a, b);
  }

llvm::Value* subI_rReg_I1Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->builder().getInt32(1);
  return sel->builder().CreateSub(a, b);
  }

llvm::Value* subL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateSub(a, b);
}

llvm::Value* subF_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFSub(a, b);
}

llvm::Value* subF_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFSub(a, b);
}

llvm::Value* mulI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateMul(a, b);
}

llvm::Value* mulL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateMul(a, b);
}

llvm::Value* mulL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateMul(a, b);
  }
  
llvm::Value* mulF_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFMul(a, b);
  }

llvm::Value* mulF_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFMul(a, b);
}

llvm::Value* divI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateSDiv(a, b);
  }

llvm::Value* divF_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFDiv(a, b);
}

llvm::Value* divF_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFDiv(a, b);
}

llvm::Value* convI2L_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateSExt(a, sel->builder().getInt64Ty());
  return res;
  }

llvm::Value* convI2D_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateSIToFP(a, sel->builder().getDoubleTy());
  return res;
  }

llvm::Value* convI2F_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateSIToFP(a, sel->builder().getFloatTy());
  return res;
}

llvm::Value* convL2I_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateTrunc(a, sel->builder().getInt32Ty());
  return res;
}

llvm::Value* convL2D_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateSIToFP(a, sel->builder().getDoubleTy());
  return res;
  }

llvm::Value* convF2D_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateFPExt(a, sel->builder().getDoubleTy());
  return res;
}

llvm::Value* modI_rRegNode::select(Selector* sel) {
  llvm::Value* divident = sel->select_node(in(1));
  llvm::Value* diviser = sel->select_node(in(2));
  llvm::Value* tmp1 = sel->builder().CreateSDiv(divident,diviser);
  llvm::Value* tmp2 = sel->builder().CreateMul(tmp1,diviser);
  return sel->builder().CreateSub(divident,tmp2);
}

llvm::Value* andI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* andI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* andL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* andL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* orI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateOr(a, b);
}

llvm::Value* orI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateOr(a, b);
}

llvm::Value* orL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateOr(a, b);
}

llvm::Value* orL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateOr(a, b);
}

llvm::Value* xorI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateXor(a, b);
  }

llvm::Value* xorI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateXor(a, b);
  }

llvm::Value* xorL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateXor(a, b);
}

llvm::Value* xorL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateXor(a, b);
}

llvm::Value* salI_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateShl(a, b);
}

llvm::Value* salI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateShl(a, b);
}

llvm::Value* salL_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  b = sel->builder().CreateIntCast(b, sel->type(T_LONG), true);
  return sel->builder().CreateShl(a, b);
}

llvm::Value* salL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Type* longTy = sel->type(T_LONG);
  if(b->getType() != longTy) {
    b = sel->builder().CreateSExt(b, longTy);
  }
  return sel->builder().CreateShl(a, b);
  }
  
llvm::Value* sarI_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAShr(a, b);
  }

llvm::Value* sarI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateAShr(a, b);
}

llvm::Value* sarL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Type* longTy = sel->type(T_LONG);
  if(b->getType() != longTy) {
    b = sel->builder().CreateSExt(b, longTy);
  }
  return sel->builder().CreateAShr(a, b);
  }

llvm::Value* shrI_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateLShr(a, b);
}

llvm::Value* shrI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateLShr(a, b);
}

llvm::Value* shrL_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  b = sel->builder().CreateIntCast(b, a->getType(), true);
  return sel->builder().CreateLShr(a, b);
}

llvm::Value* shrL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  b = sel->builder().CreateIntCast(b, a->getType(), true);
  return sel->builder().CreateLShr(a, b);
}

llvm::Value* cmpI_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  assert(a->getType() == sel->type(T_INT) && b->getType() == sel->type(T_INT), "operands must be int");
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* cmpI_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Type* intTy = sel->type(T_INT);
  assert(a->getType() == intTy && b->getType() == intTy, "operands must be int");
  return sel->select_condition(this, a, b, false, false);
  }


llvm::Value* cmpL_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  assert(a->getType() == sel->type(T_LONG) && b->getType() == sel->type(T_LONG), "operands must be long");
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* jmpConNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  sel->select_if(pred, this);
  return NULL;
}

llvm::Value* addD_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFAdd(a, b);
}

llvm::Value* addD_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFAdd(a, b);
}

llvm::Value* subD_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFSub(a, b);
}

llvm::Value* subD_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFSub(a, b);
}

llvm::Value* mulD_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFMul(a, b);
}

llvm::Value* mulD_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFMul(a, b);
  }

llvm::Value* divD_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateFDiv(a, b);
}

llvm::Value* divD_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateFDiv(a, b);
}

llvm::Value* loadConDNode::select(Selector* sel) {
  return sel->select_oper(opnd_array(1));
}

llvm::Value* storeBNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  value = sel->builder().CreateIntCast(value, sel->type(T_BYTE), true);
  sel->store(value, addr);
  return NULL;
}

llvm::Value* loadLNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_LONG);
}

llvm::Value* loadNKlassNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_NARROWKLASS);
}

llvm::Value* castP2XNode::select(Selector* sel) {
  llvm::Value* res = sel->select_node(in(1));
  assert(res->getType()->isPointerTy(), "not pointer");
  return sel->builder().CreatePtrToInt(res, sel->type(T_LONG));
}

llvm::Value* cmpandL_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  assert(a->getType() == sel->type(T_LONG) && b->getType() == sel->type(T_LONG), "operands must be long");
  return sel->select_condition(this, a, b, true, false);
}

llvm::Value* storeLConditionalNode::select(Selector* sel) {
  int op_index = MemNode::Address;
  llvm::Value* addr = sel->select_node(in(op_index));
  llvm::Value* check = sel->select_node(in(op_index+1));
  llvm::Value* value = sel->select_node(in(op_index+2));
  Node* out = raw_out(0);
  int ccode = out->is_Mach() ? out->as_Mach()->_opnds[0]->ccode() : -1;
  assert(!out->is_Mach() || ccode == 0x0 || ccode == 0x1, "check condition");
  llvm::Value* res = sel->cmpxchg(addr, check, value);
  return sel->builder().CreateExtractValue(res, 1);
}

llvm::Value* if_fastlockNode::select(Selector* sel) {
  BoxLockNode* box_n = in(2)->as_BoxLock();
  LlvmStack& stack = sel->cg()->stack();
  int mon_number = box_n->stack_slot() / 2;

  Block* slow_block = sel->block()->non_connector_successor(0);
  Block* ok_block = sel->block()->non_connector_successor(1);
  llvm::BasicBlock* bb = sel->builder().GetInsertBlock();
  llvm::BasicBlock* recr_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_recr", sel->func());
  llvm::BasicBlock* slow_bb = sel->basic_block(slow_block);
  llvm::BasicBlock* ok_bb = sel->basic_block(ok_block);

  llvm::Value* obj = sel->select_node(in(1));
  sel->oops().push_back(this);

  llvm::Value* frame_top = stack.FP();
  llvm::Value* mark_offset = sel->builder().getInt64(oopDesc::mark_offset_in_bytes());
  llvm::Value* mon_object_offset = sel->builder().getInt64(stack.mon_obj_offset(mon_number));
  llvm::Value* mon_header_offset = sel->builder().getInt64(stack.mon_header_offset(mon_number));
  llvm::Value* mon_header_addr = sel->gep(frame_top, mon_header_offset);
  llvm::Value* unlock_mask = sel->builder().getInt64(markOopDesc::unlocked_value);
  llvm::Value* zero = sel->null(T_LONG);

  MachOper* cond = opnd_array(1);

  // float cur_freq = sel->cur_block()->freq();
  // recr_bb->setFreq(1 * cur_freq / 3.0f);
  // ok_bb->setFreq(2 * cur_freq / 3.0f);

  llvm::Value* mark_addr = sel->gep(obj, mark_offset);
  llvm::Value* mark = sel->load(mark_addr, T_LONG);
  llvm::BasicBlock* cas_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CAS", sel->func());
  if (!UseOptoBiasInlining) {
    sel->store(obj, sel->gep(frame_top, mon_object_offset));
#if 0
    if (UseBiasedLocking) {
      llvm::BasicBlock* owner_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckBiasOwner", sel->func());
      llvm::BasicBlock* revoke_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckRevokeBias", sel->func());
      llvm::BasicBlock* rebias_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckReBias", sel->func());
      llvm::BasicBlock* acquire_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_TryAcquireBias", sel->func());
      llvm::BasicBlock* try_rebias_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_TryReBias", sel->func());
      llvm::BasicBlock* try_revoke_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_TryRevokeBias", sel->func());

      llvm::Value* biased_mask = sel->builder().getInt64(markOopDesc::biased_lock_mask_in_place);
      llvm::Value* biased_pattern = sel->builder().getInt64(markOopDesc::biased_lock_pattern);
      llvm::Value* prototype_offset = sel->builder().getInt64(in_bytes(Klass::prototype_header_offset()));
      llvm::Value* owner_mask = sel->builder().getInt64(~((int) markOopDesc::age_mask_in_place));
      llvm::Value* epoch_mask = sel->builder().getInt64(markOopDesc::epoch_mask_in_place);
      llvm::Value* acquire_mask = sel->builder().getInt64(markOopDesc::biased_lock_mask_in_place | markOopDesc::age_mask_in_place | markOopDesc::epoch_mask_in_place);

      llvm::Value* pattern_tmp = sel->builder().CreateAnd(mark, biased_mask);
      llvm::Value* pattern_pred = sel->builder().CreateICmpNE(pattern_tmp, biased_pattern);
      sel->builder().CreateCondBr(pattern_pred, owner_bb, cas_bb);

      sel->builder().SetInsertPoint(owner_bb);
      
      llvm::Value* owner_tmp3 = sel->loadKlass_not_null(obj);
      llvm::Value* klass_header = sel->load(sel->gep(owner_tmp3, prototype_offset), T_ADDRESS);
      llvm::Value* owner_tmp1 = sel->builder().CreateOr(sel->thread(), klass_header);
      llvm::Value* owner_tmp2 = sel->builder().CreateXor(mark, owner_tmp1);
      llvm::Value* _and_ = sel->builder().CreateAnd(owner_tmp2, owner_mask);
      llvm::Value* owner_pred = sel->builder().CreateICmpEQ(_and_, zero);
      sel->builder().CreateCondBr(owner_pred, revoke_bb, cond->ccode() != 1 ? slow_bb : ok_bb);

      sel->builder().SetInsertPoint(revoke_bb);
      _and_ = sel->builder().CreateAnd(owner_tmp2, biased_mask);
      llvm::Value* revoke_pred = sel->builder().CreateICmpNE(_and_, zero);
      sel->builder().CreateCondBr(revoke_pred, rebias_bb, try_revoke_bb);

      sel->builder().SetInsertPoint(rebias_bb);
      _and_ = sel->builder().CreateAnd(owner_tmp2, epoch_mask);
      llvm::Value* rebias_pred = sel->builder().CreateICmpNE(_and_, zero);
      sel->builder().CreateCondBr(rebias_pred, acquire_bb, try_rebias_bb);

      sel->builder().SetInsertPoint(acquire_bb);
      llvm::Value* acquire_tmp1 = sel->builder().CreateAnd(mark, acquire_mask);
      llvm::Value* acquire_tmp2 = sel->builder().CreateOr(acquire_tmp1, sel->thread());
      llvm::Value* acquire_pred = sel->cmpxchg(mark_addr, acquire_tmp1, acquire_tmp2);
      acquire_pred = sel->builder().CreateExtractValue(acquire_pred, 1);
      if (cond->ccode() == 1) {
        sel->builder().CreateCondBr(acquire_pred, slow_bb, ok_bb);
      } else {
        sel->builder().CreateCondBr(acquire_pred, ok_bb, slow_bb);
      }

      sel->builder().SetInsertPoint(try_rebias_bb);
      llvm::Value* try_rebias_tmp = sel->builder().CreateOr(klass_header, sel->thread());
      llvm::Value* try_rebias_pred = sel->cmpxchg(mark_addr, mark, try_rebias_tmp);
      try_rebias_pred = sel->builder().CreateExtractValue(try_rebias_pred, 1);
      if (cond->ccode() == 1) {
        sel->builder().CreateCondBr(try_rebias_pred, slow_bb, ok_bb);
      } else {
        sel->builder().CreateCondBr(try_rebias_pred, ok_bb, slow_bb);
      }

      sel->builder().SetInsertPoint(try_revoke_bb);
      sel->cmpxchg(mark_addr, mark, klass_header);
      sel->builder().CreateBr(cas_bb);

      sel->builder().SetInsertPoint(cas_bb);
    }
#endif
  }

  llvm::BasicBlock* infl_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_Infl", sel->func());
  llvm::Value* monitor_value = sel->builder().getInt64(markOopDesc::monitor_value);
  llvm::Value* mark_is_infl = sel->builder().CreateAnd(mark, monitor_value);
  llvm::Value* pr_is_infl = sel->builder().CreateICmpEQ(mark_is_infl, zero);
  sel->builder().CreateCondBr(pr_is_infl, cas_bb, infl_bb);

  sel->builder().SetInsertPoint(cas_bb);
  llvm::Value* disp = sel->builder().CreateOr(mark, unlock_mask);
  sel->store(disp, mon_header_addr);
  llvm::Value* pred = sel->cmpxchg(mark_addr, disp, mon_header_addr);
  pred = sel->builder().CreateExtractValue(pred, 1);
  sel->builder().CreateCondBr(pred, ok_bb, recr_bb);

  sel->builder().SetInsertPoint(recr_bb);
  llvm::MDString* md_string = llvm::MDString::get(sel->ctx(), "rsp\00");
  llvm::MDNode* md_node = llvm::MDNode::get(sel->ctx(), md_string);
  llvm::Value* md = llvm::MetadataAsValue::get(sel->ctx(), md_node);
  llvm::Value* SP = sel->builder().CreateIntrinsic(llvm::Intrinsic::read_register, { sel->type(T_LONG) }, md);
  disp = sel->builder().CreateSub(disp, SP);
  llvm::Value* lock_mask = sel->builder().getInt64(7 - os::vm_page_size());
  llvm::Value* mark_lock = sel->builder().CreateAnd(disp, lock_mask);
  sel->store(mark_lock, mon_header_addr);
  llvm::Value* pr_res = sel->builder().CreateICmpEQ(mark_lock, zero);
  sel->builder().CreateCondBr(pr_res, ok_bb, slow_bb);

  sel->builder().SetInsertPoint(infl_bb);
  llvm::Value* unused_mark = sel->builder().getInt64(intptr_t(markOopDesc::unused_mark()));
  sel->store(unused_mark, mon_header_addr);
  llvm::Value* infl_offset = sel->builder().getInt32(ObjectMonitor::owner_offset_in_bytes()-2);
  llvm::Value* mark_as_ptr = sel->builder().CreateIntToPtr(mark, sel->type(T_ADDRESS));
  llvm::Value* infl_addr = sel->gep(mark_as_ptr, infl_offset);
  llvm::Value* infl_tmp = sel->load(infl_addr, T_LONG);
  llvm::Value* pr_infl = sel->builder().CreateICmpEQ(infl_tmp, zero);
  llvm::BasicBlock* infl_cas_bb = llvm::BasicBlock::Create(sel->ctx(), infl_bb->getName() + "_CAS", sel->func());
  sel->builder().CreateCondBr(pr_infl, infl_cas_bb, slow_bb);

  sel->builder().SetInsertPoint(infl_cas_bb);
  llvm::Value* pr_infl_cas = sel->cmpxchg(infl_addr, infl_tmp, sel->thread());
  pr_infl_cas = sel->builder().CreateExtractValue(pr_infl_cas, 1);
  sel->builder().CreateCondBr(pr_infl_cas, ok_bb, slow_bb);

  return NULL;
}

llvm::Value* if_fastunlockNode::select(Selector* sel) {
  BoxLockNode* box_n = in(2)->as_BoxLock();
  LlvmStack& stack = sel->cg()->stack();
  int mon_number = box_n->stack_slot() / 2;

  llvm::Value* obj = sel->select_node(in(1));
  llvm::Value* frame_top = stack.FP();
  llvm::Value* mon_object_offset = sel->builder().getInt64(stack.mon_obj_offset(mon_number));
  llvm::Value* mon_header_offset = sel->builder().getInt64(stack.mon_header_offset(mon_number));
  llvm::Value* mon_header_addr = sel->gep(frame_top, mon_header_offset);
  llvm::Value* mark_offset = sel->builder().getInt64(oopDesc::mark_offset_in_bytes());
  llvm::Value* mark_addr = sel->gep(obj, mark_offset);
  llvm::Value* zero = sel->null(T_LONG);

  Block* slow_block = sel->block()->non_connector_successor(0);
  Block* ok_block = sel->block()->non_connector_successor(1);
  llvm::BasicBlock* bb = sel->builder().GetInsertBlock();
  llvm::BasicBlock* slow_bb = sel->basic_block(slow_block);
  llvm::BasicBlock* ok_bb = sel->basic_block(ok_block);

  MachOper* cond = opnd_array(1);
  
  // float cur_freq = sel->cur_block()->freq();
  // fast_bb->setFreq(2 * cur_freq / 3.0f);
  // ok_bb->setFreq(1 * cur_freq / 3.0f);

#if 0
  if (UseBiasedLocking && !UseOptoBiasInlining) {
    llvm::BasicBlock* head_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_FastUnlockHeader", sel->func());
    llvm::BasicBlock* pattern_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_UnlockBiasPattern", sel->func());
    llvm::Value* biased_mask = sel->builder().getInt64(markOopDesc::biased_lock_mask_in_place);
    llvm::Value* biased_pattern = sel->builder().getInt64(markOopDesc::biased_lock_pattern);
    llvm::Value* mark = sel->load(mark_addr, T_LONG);
    llvm::Value* pattern_tmp = sel->builder().CreateAnd(mark, biased_mask);
    llvm::Value* pattern_pred = sel->builder().CreateICmpEQ(pattern_tmp, biased_pattern);

    sel->builder().CreateCondBr(pattern_pred, head_bb, cond->ccode() == 1 ? ok_bb: slow_bb);
    sel->builder().SetInsertPoint(head_bb);
  }
#endif
  llvm::Value* disp = sel->load(mon_header_addr, T_INT);
  llvm::Value* pred = sel->builder().CreateICmpEQ(disp, sel->null(T_INT));
  llvm::BasicBlock* is_infl_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_IsInfl", sel->func());
  sel->builder().CreateCondBr(pred, slow_bb, is_infl_bb);

  sel->builder().SetInsertPoint(is_infl_bb);
  llvm::Value* monitor_value = sel->builder().getInt64(markOopDesc::monitor_value);
  llvm::Value* mark = sel->load(mark_addr, T_LONG);
  llvm::Value* mark_is_infl = sel->builder().CreateAnd(mark, monitor_value);
  llvm::Value* pr_is_infl = sel->builder().CreateICmpEQ(mark_is_infl, zero);
  llvm::BasicBlock* infl_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_Infl1", sel->func());
  llvm::BasicBlock* fast_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_FastUnlock", sel->func());
  sel->builder().CreateCondBr(pr_is_infl, fast_bb, infl_bb);

  sel->builder().SetInsertPoint(fast_bb);
  disp = sel->load(mon_header_addr, T_INT);
  llvm::Value* pred2 = sel->cmpxchg(mark_addr, mon_header_addr, disp);
  pred2 = sel->builder().CreateExtractValue(pred2, 1);
  sel->builder().CreateCondBr(pred2, ok_bb, slow_bb);

  sel->builder().SetInsertPoint(infl_bb);
  llvm::Value* infl_offset1 = sel->builder().getInt32(ObjectMonitor::owner_offset_in_bytes()-2);
  llvm::Value* infl_addr1 = sel->gep(mark_addr, infl_offset1);
  llvm::Value* infl_tmp1 = sel->load(infl_addr1, T_LONG);
  llvm::Value* thread = sel->builder().CreatePtrToInt(sel->thread(), sel->type(T_LONG));
  llvm::Value* infl_xor = sel->builder().CreateXor(infl_tmp1, thread);
  llvm::Value* infl_offset2 = sel->builder().getInt32(ObjectMonitor::recursions_offset_in_bytes()-2);
  llvm::Value* infl_addr2 = sel->gep(mark_addr, infl_offset2);
  llvm::Value* infl_tmp2 = sel->load(infl_addr2, T_LONG);
  llvm::Value* infl_or = sel->builder().CreateOr(infl_xor, infl_tmp2);
  llvm::Value* infl_pred = sel->builder().CreateICmpEQ(infl_or, sel->null(T_LONG));
  llvm::BasicBlock* infl2_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_Infl2", sel->func());
  llvm::BasicBlock* check_succ_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckSucc", sel->func());
  sel->builder().CreateCondBr(infl_pred, infl2_bb, slow_bb);

  sel->builder().SetInsertPoint(infl2_bb);
  llvm::Value* infl2_offset1 = sel->builder().getInt32(ObjectMonitor::cxq_offset_in_bytes()-2);
  llvm::Value* infl2_addr1 = sel->gep(mark_addr, infl2_offset1);
  llvm::Value* infl2_tmp1 = sel->load(infl2_addr1, T_LONG);
  llvm::Value* infl2_offset2 = sel->builder().getInt32(ObjectMonitor::EntryList_offset_in_bytes()-2);
  llvm::Value* infl2_addr2 = sel->gep(mark_addr, infl2_offset2);
  llvm::Value* infl2_tmp2 = sel->load(infl2_addr2, T_LONG);
  llvm::Value* infl2_or = sel->builder().CreateOr(infl2_tmp1, infl2_tmp2);
  llvm::Value* infl2_pred = sel->builder().CreateICmpEQ(infl2_or, sel->null(T_LONG));
  llvm::BasicBlock* infl3_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_Infl3", sel->func());
  sel->builder().CreateCondBr(infl2_pred, infl3_bb, check_succ_bb);
  
  sel->builder().SetInsertPoint(infl3_bb);
  llvm::Value* infl3_offset = sel->builder().getInt32(ObjectMonitor::owner_offset_in_bytes()-2);
  llvm::Value* infl3_addr = sel->gep(mark_addr, infl3_offset);
  sel->store(sel->null(T_INT), infl3_addr);
  sel->builder().CreateBr(slow_bb);

  sel->builder().SetInsertPoint(check_succ_bb);
  llvm::Value* check_succ_offset = sel->builder().getInt32(ObjectMonitor::succ_offset_in_bytes()-2);
  llvm::Value* check_succ_addr = sel->gep(mark_addr, check_succ_offset);
  llvm::Value* check_succ_tmp = sel->load(check_succ_addr, T_INT);
  llvm::Value* check_succ_pred = sel->builder().CreateICmpEQ(check_succ_tmp, sel->null(T_INT));
  llvm::BasicBlock* check_succ2_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckSucc2", sel->func());
  sel->builder().CreateCondBr(check_succ_pred, slow_bb, check_succ2_bb);

  sel->builder().SetInsertPoint(check_succ2_bb);
  llvm::Value* check_succ2_offset = sel->builder().getInt32(ObjectMonitor::owner_offset_in_bytes()-2);
  llvm::Value* check_succ2_addr = sel->gep(mark_addr, check_succ2_offset);
  sel->store(sel->null(T_INT), check_succ2_addr);
  llvm::Value* check_succ2_tmp = sel->load(check_succ_addr, T_INT);
  llvm::Value* check_succ2_pred = sel->builder().CreateICmpEQ(check_succ2_tmp, sel->null(T_INT));
  llvm::BasicBlock* check_succ3_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_CheckSucc3", sel->func());
  sel->builder().CreateCondBr(check_succ2_pred, ok_bb, check_succ3_bb);

  sel->builder().SetInsertPoint(check_succ3_bb);
  llvm::Value* check_succ3_offset = sel->builder().getInt32(ObjectMonitor::owner_offset_in_bytes()-2);
  llvm::Value* check_succ3_addr = sel->gep(mark_addr, check_succ3_offset);
  llvm::Value* check_succ3_pred = sel->cmpxchg(check_succ3_addr, sel->null(T_ADDRESS), sel->thread());
  check_succ3_pred = sel->builder().CreateExtractValue(check_succ3_pred, 1);
  sel->builder().CreateCondBr(check_succ3_pred, ok_bb, slow_bb);

  return NULL;
}

llvm::Value* BoxLockNode::select(Selector* sel) {
  LlvmStack& stack = sel->cg()->stack();
  return sel->gep(stack.FP(), stack.mon_offset(stack_slot() / 2));
}

llvm::Value* membar_acquire_lockNode::select(Selector* sel) {
  return NULL;
}

llvm::Value* membar_release_lockNode::select(Selector* sel) {
  return NULL;
}

llvm::Value* MachNullCheckNode::select(Selector* sel) {
  llvm::BasicBlock* bb = sel->builder().GetInsertBlock();
  // find the instruction (load or store) for null checking
  llvm::Instruction* last_mem = nullptr;
  llvm::Value* addr;
  for (llvm::BasicBlock::reverse_iterator it = bb->rbegin(); it != bb->rend(); ++it) {
    llvm::Instruction& inst = *it;
    if (inst.getOpcode() == llvm::Instruction::Load) {
      last_mem = &inst;
      addr = llvm::cast<llvm::LoadInst>(last_mem)->getPointerOperand();
      break;
    } else if (inst.getOpcode() == llvm::Instruction::Store) {
      last_mem = &inst;
      addr = llvm::cast<llvm::StoreInst>(last_mem)->getPointerOperand();
      break;
    }
  }
  assert(last_mem, "can't find the instruction for null checking");
  addr = addr->stripPointerCasts();
  if (llvm::cast<llvm::Instruction>(addr)->getOpcode() == llvm::Instruction::GetElementPtr) {
    addr = llvm::cast<llvm::GetElementPtrInst>(addr)->getPointerOperand();
  }
  // put a null check conditional branch after last_mem
  sel->builder().SetInsertPoint(last_mem);
  llvm::Value* pred = sel->builder().CreateICmpEQ(addr, sel->null(addr->getType()));
  // determine the two blocks for the conditional branch
  Node* if_node = raw_out(0);
  size_t true_idx = 0, false_idx = 1;
  if (if_node->Opcode() == Op_IfFalse) {
    std::swap(true_idx, false_idx);
  } else {
    assert(if_node->Opcode() == Op_IfTrue, "illegal Node type");
  }
  Block* handler_block = sel->C->cfg()->get_block_for_node(raw_out(true_idx)->raw_out(0))->non_connector();
  Block* next_block = sel->C->cfg()->get_block_for_node(raw_out(false_idx)->raw_out(0))->non_connector();
  llvm::BasicBlock* handler_bb = sel->basic_block(handler_block);
  llvm::BasicBlock* next_bb = sel->basic_block(next_block);
  llvm::BasicBlock* bb_not_null = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_not_null", sel->func());
  // create conditional branch and add metadata for making this null check implicit later on
  llvm::Instruction* cond_br = sel->builder().CreateCondBr(pred, handler_bb, bb_not_null);
  llvm::MDNode* metadata = llvm::MDNode::get(sel->ctx(), {});
  cond_br->setMetadata(llvm::LLVMContext::MD_make_implicit, metadata);
  // connect bb_not_null block and the next block
  sel->builder().SetInsertPoint(bb_not_null);
  llvm::Instruction* br = sel->builder().CreateBr(next_bb);
  // move the remaining instructions from bb to bb_not_null
  for (auto it = ++cond_br->getIterator(); it != bb->end(); it = ++cond_br->getIterator()) {
    llvm::Instruction& inst = *it;
    inst.moveBefore(br);
  }
  return NULL;
}

llvm::Value* cmpU_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* addP_rRegNode::select(Selector* sel) {
  bool is_managed = bottom_type()->isa_oopptr() != NULL;

  llvm::Value* base_op = NULL;
  llvm::Value* op = sel->gep(sel->select_node(in(2)), sel->select_node(in(3)));
  if (is_managed) {
    // Node* base = sel->find_derived_base(this);
    // base_op = base == this ? op : sel->select_node(base);
    // assert(base_op != NULL, "check");
    // sel->mark_dptr(op, base_op);
  }

  return op;
}

llvm::Value* decodeHeapOop_not_nullNode::select(Selector* sel) {
  llvm::Value* narrow_oop = sel->select_node(in(1));
  if (sel->is_fast_compression()) return narrow_oop;
  sel->oops().push_back(this);
  return sel->decode_heap_oop(narrow_oop, true);
}

llvm::Value* storeINode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_INT), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* membar_acquireNode::select(Selector* sel) {
  sel->builder().CreateFence(llvm::AtomicOrdering::Acquire);
  return NULL;
}

llvm::Value* membar_releaseNode::select(Selector* sel) {
  sel->builder().CreateFence(llvm::AtomicOrdering::Release);
  return NULL;
}

llvm::Value* membar_volatileNode::select(Selector* sel) {
  sel->builder().CreateFence(llvm::AtomicOrdering::SequentiallyConsistent);
  return NULL;
}

llvm::Value* loadINode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_INT);
}

llvm::Value* cmpandI_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->select_condition(this, a, b, true, false);
}

llvm::Value* encodeHeapOopNode::select(Selector* sel) {
  return sel->encode_heap_oop(sel->select_node(in(1)), false);
}

llvm::Value* encodeHeapOop_not_nullNode::select(Selector* sel) {
  return sel->encode_heap_oop(sel->select_node(in(1)), true);
}

llvm::Value* storeNNode::select(Selector* sel) {
  assert(in(MemNode::Address)->is_BoxLock() == false, "check");
  Node* val_n = in(MemNode::Address + 1);
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(val_n); 
  assert(value->getType() == sel->type(T_NARROWOOP), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* storeImmB0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->builder().getInt8(CardTableModRefBS::dirty_card_val());
  sel->store(value, addr);
  return NULL;
}

llvm::Value* convI2L_z_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  return sel->builder().CreateZExt(a, sel->type(T_LONG));
}

llvm::Value* clear_memoryNode::select(Selector* sel) {
  llvm::Value* arr_size = sel->select_node(in(2));
  arr_size = sel->builder().CreateIntCast(arr_size, sel->type(T_INT), false);
  arr_size = sel->builder().CreateShl(arr_size, LogBytesPerLong);
  llvm::Value* arr_base = sel->select_node(in(3));
  llvm::Value* zero = sel->builder().getInt32(0);
  sel->call_C((void*)std::memset, sel->type(T_VOID), {arr_base, zero, arr_size});
  return NULL;
}

llvm::Value* loadRangeNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_INT);
}

llvm::Value* mergeI_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  llvm::Value* v2 = sel->select_node(in(3));
  return sel->builder().CreateSelect(pred, v2, v1);
}

llvm::Value* cmpU_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* CallLeafNoFPDirectNode::select(Selector* sel) {
  BasicType ret_type = tf()->return_type();
  assert(ret_type != T_NARROWOOP, "unexpected behavior check");
  llvm::Value* ret =  sel->call_C(entry_point(), sel->type(ret_type), sel->call_args(this));
  if (ret_type == T_OBJECT || ret_type == T_ARRAY) {
    sel->oops().push_back(this);
  }
  return ret;
}

llvm::Value* salL_index_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Type* longTy = sel->type(T_LONG);
  if (a->getType() != longTy) {
    a = sel->builder().CreateZExt(a, longTy);
  }
  llvm::Value* b = sel->select_oper(opnd_array(2));
  if (b->getType() != longTy) {
    b = sel->builder().CreateZExt(b, longTy);
  }
  return sel->builder().CreateShl(a, b);
}

llvm::Value* loadConNNode::select(Selector* sel) {
  assert(opnd_array(1)->type()->basic_type() == T_NARROWOOP,"type check");
  llvm::Value* con = sel->select_oper(opnd_array(1));
  if (opnd_array(1)->type()->is_narrowoop()->get_con() != 0) {
    sel->narrow_oops().push_back(llvm::cast<llvm::Instruction>(con));
  }
  return con;
}

llvm::Value* cmpN_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, false, false);
}

jboolean strequal_C(jchar *s1, jchar *s2, jint l) {
  int k = 0;
  while (k < l) {
    jchar c1 = s1[k];
    jchar c2 = s2[k];
    if (c1 != c2) {
      return 0x0;
    }
    ++k;
  }
  return 0x1;
}

llvm::Value* string_equalsNode::select(Selector* sel) {
  llvm::Value* s1 = sel->select_node(in(2));
  llvm::Value* s2 = sel->select_node(in(3));
  llvm::Value* length = sel->select_node(in(4));
  return sel->call_C((void *)strequal_C, sel->type(T_INT), { s1, s2, length });
}

llvm::Value* safePoint_pollNode::select(Selector* sel) {
  ScopeDescriptor& sd = sel->cg()->scope_descriptor();
  ScopeInfo* si = sd.register_scope(this);
  llvm::FunctionCallee f = sel->callee(StubRoutines::poll_stub_entry(), sel->type(T_VOID), {});
  std::vector<llvm::Value*> deopt = sd.stackmap_scope(si);
  llvm::OperandBundleDef deopt_ob("deopt", deopt);
  llvm::CallInst* call = sel->builder().CreateCall(f, {}, { deopt_ob });
  call->addAttribute(llvm::AttributeList::FunctionIndex, llvm::Attribute::get(sel->ctx(), "statepoint-id", std::to_string(si->stackmap_id)));
  return NULL;
}

llvm::Value* loadUSNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res =  sel->load(addr, T_SHORT);
  return sel->builder().CreateZExt(res, sel->type(T_INT));
}

llvm::Value* jmpLoopEndNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));;
  sel->select_if(pred, this);
  return NULL;
}

llvm::Value* castIINode::select(Selector* sel) {
  return sel->select_node(in(1)); 
}

llvm::Value* xaddINode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* val = sel->select_node(in(op_index));
  addr = sel->builder().CreatePointerCast(addr, llvm::PointerType::getUnqual(val->getType()));

  llvm::Value* res = sel->builder().CreateAtomicRMW(llvm::AtomicRMWInst::Add, addr, val, llvm::AtomicOrdering::SequentiallyConsistent);
  return res;
}

llvm::Value* convP2BNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  llvm::Value* zero = sel->null(val->getType());
  llvm::Value* pred = sel->builder().CreateICmpEQ(val, zero);
  llvm::Value* res = sel->builder().CreateSelect(pred, sel->builder().getInt32(0), sel->builder().getInt32(1));

  return res;
}

llvm::Value* loadUBNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_BYTE);
  return sel->builder().CreateZExt(res, sel->type(T_INT));
}

llvm::Value* storeLNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_LONG), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* compareAndSwapNNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* check = sel->select_node(in(op_index++));
  llvm::Value* value = sel->select_node(in(op_index++));

  llvm::Value* res = sel->cmpxchg(addr, check, value);
  res = sel->builder().CreateExtractValue(res, 1);
  res = sel->builder().CreateZExt(res, sel->type(T_INT));
  return res;
}

llvm::Value* cmpL_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* convI2BNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  llvm::Value* pred = sel->builder().CreateICmpEQ(val, sel->null(T_INT));
  llvm::Value* res = sel->builder().CreateSelect(pred, sel->builder().getInt32(0), sel->builder().getInt32(1));

  return res;
}

llvm::Value* i2bNode::select(Selector* sel) {
  return sel->select_node(in(1));
}

llvm::Value* mergeUI_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  llvm::Value* v2 = sel->select_node(in(3));
  return sel->builder().CreateSelect(pred, v2, v1);
}

llvm::Value* storeImmN0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_NARROWOOP), addr);
  return NULL;
}

llvm::Value* loadConLNode::select(Selector* sel) {
  return sel->select_oper(opnd_array(1));;
}

llvm::Value* maxI_rReg_imm_0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Value* pred = sel->builder().CreateICmpSLE(a, b);
  return sel->builder().CreateSelect(pred, b, a);
}

llvm::Value* loadKlassNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_METADATA);
}

llvm::Value* loadFNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_FLOAT);
}

llvm::Value* convD2I_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateFPToSI(val, sel->type(T_INT));
}

llvm::Value* minI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Value* pred = sel->builder().CreateICmpSLE(a, b);
  return sel->builder().CreateSelect(pred, a, b);
}

llvm::Value* loadBNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_BYTE);
  return sel->builder().CreateSExt(res, sel->type(T_INT));
}

llvm::Value* storeCNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  value = sel->builder().CreateIntCast(value, sel->type(T_CHAR), true);
  sel->store(value, addr);
  return NULL;
}

llvm::Value* minI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));

  llvm::Value* pred = sel->builder().CreateICmpSLE(a, b);
  return sel->builder().CreateSelect(pred, a, b);
}

llvm::Value* andI_rReg_imm65535Node::select(Selector* sel) {
  llvm::Value* i_op = sel->select_node(in(1));
  return sel->builder().CreateZExt(i_op, sel->type(T_INT));
}

llvm::Value* cmpN_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* loadV8Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_LONG);
}

llvm::Value* storeV8Node::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_LONG), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* compareAndSwapINode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* check = sel->select_node(in(op_index++));
  llvm::Value* value = sel->select_node(in(op_index++));

  llvm::Value* res = sel->cmpxchg(addr, check, value);
  res = sel->builder().CreateExtractValue(res, 1);
  res = sel->builder().CreateZExt(res, sel->type(T_INT));
  return res;
}

llvm::Value* unnecessary_membar_volatileNode::select(Selector* sel) {
  sel->builder().CreateFence(llvm::AtomicOrdering::SequentiallyConsistent);
  return NULL;
}

llvm::Value* compareAndSwapLNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* check = sel->select_node(in(op_index++));
  llvm::Value* value = sel->select_node(in(op_index++));

  llvm::Value* res = sel->cmpxchg(addr, check, value);
  res = sel->builder().CreateExtractValue(res, 1);
  res = sel->builder().CreateZExt(res, sel->type(T_INT));
  return res;
}

llvm::Value* jumpXtndNode::select(Selector* sel) {
  uint size = outcnt();

  llvm::Value* addr_offset = sel->select_node(in(1));
  llvm::Value* shift = llvm::ConstantInt::get(addr_offset->getType(), LogBytesPerWord);
  addr_offset = sel->builder().CreateAShr(addr_offset, shift);
  llvm::BasicBlock* bb = sel->basic_block();
  llvm::BasicBlock* bb_default = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_default", sel->func());
  sel->builder().SetInsertPoint(bb_default);
  sel->builder().CreateUnreachable();
  sel->builder().SetInsertPoint(bb);
  llvm::SwitchInst* switch_inst = sel->builder().CreateSwitch(addr_offset, bb_default, size);

  for (uint i = 0; i < size; ++i) {
    Node* switch_case = NULL;
    JumpProjNode *jproj = NULL;

    // Matcher messed up the order of cases so we need to find the one that we need
    for (uint j = 0; j < size; ++j) {
      assert(raw_out(j)->Opcode() == Op_JumpProj, "All outs from a switch should be JumpProj nodes");
      jproj = raw_out(j)->as_JumpProj();
      if (jproj->switch_val() == i) {
        for (uint k = 0; k < jproj->outcnt(); ++k) {
          Node* n = jproj->raw_out(k);
          if (n->is_CFG()) {
            switch_case = n;
            break;
          }
        }
      }
    }

    assert(switch_case != NULL, "Some switch cases are missing");
    Block *b_dest = sel->C->cfg()->get_block_for_node(switch_case);
    llvm::BasicBlock *bb_dest = sel->basic_block(b_dest);
    llvm::ConstantInt* switch_val = llvm::cast<llvm::ConstantInt>(llvm::ConstantInt::get(addr_offset->getType(), i));
    switch_inst->addCase(switch_val, bb_dest);
  }
  return NULL;
}

llvm::Value* castPPNode::select(Selector* sel) {
  return sel->select_node(in(1));
}

llvm::Value* subI_rReg_imm0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  return sel->builder().CreateNeg(a);
}

jint strcmp_C(jchar *s1, jchar *s2, jint l1, jint l2) {
  int n = MIN(l1, l2);

  int k = 0;
  while (k < n) {
    jchar c1 = s1[k];
    jchar c2 = s2[k];
    if (c1 != c2) {
      return c1 - c2;
    }
    ++k;
  }
  return l1 - l2;
}

llvm::Value* string_compareNode::select(Selector* sel) {
  llvm::Value* str1_ptr = sel->select_node(in(2));
  llvm::Value* str1_length = sel->select_node(in(3));
  llvm::Value* str2_ptr = sel->select_node(in(4));
  llvm::Value* str2_length = sel->select_node(in(5));
  return sel->call_C((void *)strcmp_C, sel->type(T_INT), {str1_ptr, str2_ptr, str1_length, str2_length});
}

llvm::Value* cmpF_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, false, true);
}

llvm::Value* convF2I_reg_regNode::select(Selector* sel) {
  llvm::Value* value = sel->select_node(in(1));
  return sel->builder().CreateFPToSI(value, sel->type(T_INT));
}

llvm::Value* cmpandI_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, true, false);
}

jint indexOf_C(jchar* source, jint sourceOffset, jint sourceCount,
        jchar* target, jint targetOffset, jint targetCount,
        jint fromIndex) {
    if (fromIndex >= sourceCount) {
        return (targetCount == 0 ? sourceCount : -1);
    }
    if (fromIndex < 0) {
        fromIndex = 0;
    }
    if (targetCount == 0) {
        return fromIndex;
    }

    jchar first = target[targetOffset];
    jint max = sourceOffset + (sourceCount - targetCount);

    for (jint i = sourceOffset + fromIndex; i <= max; i++) {
        /* Look for first character. */
        if (source[i] != first) {
            while (++i <= max && source[i] != first);
        }

        /* Found first character, now look at the rest of v2 */
        if (i <= max) {
            jint j = i + 1;
            jint end = j + targetCount - 1;
            for (jint k = targetOffset + 1; j < end && source[j]
                    == target[k]; j++, k++);

            if (j == end) {
                /* Found whole string. */
                return i - sourceOffset;
            }
        }
    }
    return -1;
}

llvm::Value* string_indexof_conNode::select(Selector* sel) {
  llvm::Value* str1 = sel->select_node(in(2));
  llvm::Value* str2 = sel->select_node(in(4));
  llvm::Value* cnt1 = sel->select_node(in(3));
  llvm::Value* cnt2 = sel->select_oper(opnd_array(4));

  return sel->call_C((void*)indexOf_C, sel->type(T_INT), 
  { str1, sel->null(T_INT), cnt1, str2, sel->null(T_INT), cnt2, sel->null(T_INT) });
}

llvm::Value* string_indexofNode::select(Selector* sel) {
  llvm::Value* str1 = sel->select_node(in(2));
  llvm::Value* str2 = sel->select_node(in(4));
  llvm::Value* cnt1 = sel->select_node(in(3));
  llvm::Value* cnt2 = sel->select_node(in(5));

  return sel->call_C((void*)indexOf_C, sel->type(T_INT), 
  { str1, sel->null(T_INT), cnt1, str2, sel->null(T_INT), cnt2, sel->null(T_INT) });
}

llvm::Value* cmpandL_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, true, false);
}

bool is_subtype_of_C(Klass* check_klass, Klass* object_klass) {
  //assert(object_klass->is_oop(), "some GC problems occured");
  return object_klass->is_subtype_of(check_klass);
}

llvm::Value* partialSubtypeCheckNode::select(Selector* sel) {
  // this node has not been tested yet
  llvm::Value* subklass = sel->select_node(in(1));
  llvm::Value* superklass = sel->select_node(in(2));
  llvm::Value* is_subtype_of = sel->call_C((void *)is_subtype_of_C, sel->type(T_BOOLEAN), { superklass, subklass });
  return sel->builder().CreateSelect(is_subtype_of, sel->null(T_METADATA), subklass);
}

llvm::Value* castX2PNode::select(Selector* sel) {
  llvm::Value* res = sel->select_node(in(1));
  assert(res->getType()->isIntegerTy(), "not integer");
  res = sel->builder().CreateIntToPtr(res, sel->type(T_OBJECT));
  if (bottom_type()->isa_oopptr() != NULL) {
    sel->oops().push_back(this);
  }
  return res;
}

llvm::Value* storeFNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_FLOAT), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* MoveF2I_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateBitCast(val, sel->type(T_INT));
}

llvm::Value* mergeF_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  llvm::Value* v2 = sel->select_node(in(3));
  return sel->builder().CreateSelect(pred, v2, v1);
}

llvm::Value* maxI_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  llvm::Value* pred = sel->builder().CreateICmpSLE(a, b);
  return sel->builder().CreateSelect(pred, b, a);
}

llvm::Value* countLeadingZerosINode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  assert(val->getType() == sel->type(T_INT), "wrong type");
  return sel->builder().CreateIntrinsic(llvm::Intrinsic::ctlz, { val->getType() }, { val, sel->builder().getFalse() });
}

llvm::Value* mergeP_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  unsigned as1 = llvm::cast<llvm::PointerType>(v1->getType())->getAddressSpace();
  llvm::Value* v2 = sel->select_node(in(3));
  unsigned as2 = llvm::cast<llvm::PointerType>(v2->getType())->getAddressSpace();
  // as = 1 if oop, 0 raw pointer
  // we cast rawptr to oop, otherwise oop may die here
  if (as2 < as1) {
    v2 = sel->builder().CreatePointerCast(v2, v1->getType());
  } else {
    v1 = sel->builder().CreatePointerCast(v1, v2->getType());
  }
  llvm::Value* res = sel->builder().CreateSelect(pred, v2, v1);

  if (bottom_type()->isa_oopptr() != NULL) {
    if (bottom_type()->isa_oopptr()->offset() == 0) {
      sel->oops().push_back(this);
    }
  }

  return res;
}

llvm::Value* mulI_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateMul(a, b);
}

llvm::Value* compareAndSwapPNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* check = sel->select_node(in(op_index++));
  llvm::Value* value = sel->select_node(in(op_index++));

  llvm::Value* res = sel->cmpxchg(addr, check, value);
  res = sel->builder().CreateExtractValue(res, 1);
  res = sel->builder().CreateZExt(res, sel->type(T_INT));
  return res;
}

llvm::Value* subL_rReg_imm0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  return sel->builder().CreateNeg(a);
}

llvm::Value* zerox_long_reg_regNode::select(Selector* sel) {
  llvm::Value* i_op = sel->select_node(in(1));
  return sel->builder().CreateZExt(i_op, sel->type(T_LONG));
}

llvm::Value* storeDNode::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  assert(value->getType() == sel->type(T_DOUBLE), "wrong type");
  sel->store(value, addr);
  return NULL;
}

llvm::Value* modL_rRegNode::select(Selector* sel) {
  llvm::Value* divident = sel->select_node(in(1));
  llvm::Value* diviser = sel->select_node(in(2));
  return sel->builder().CreateSRem(divident, diviser);
}

llvm::Value* cmpD_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->select_condition(this, a, b, false, true);
}

llvm::Value* negD_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateFNeg(val);
}

llvm::Value* loadDNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_DOUBLE);
}

llvm::Value* mergeL_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  llvm::Value* v2 = sel->select_node(in(3));
  return sel->builder().CreateSelect(pred, v2, v1);
}

llvm::Value* MoveD2L_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  assert(val->getType() == sel->type(T_DOUBLE), "wrong type");
  return sel->builder().CreateBitCast(val, sel->type(T_LONG));
}

llvm::Value* countLeadingZerosLNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  assert(val->getType() == sel->type(T_LONG), "wrong type");
  llvm::Value* res = sel->builder().CreateIntrinsic(llvm::Intrinsic::ctlz, { val->getType() }, { val, sel->builder().getFalse() });
  return sel->builder().CreateTrunc(res, sel->type(T_INT));
}

llvm::Value* countTrailingZerosLNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  assert(val->getType() == sel->type(T_LONG), "wrong type");
  llvm::Value* res = sel->builder().CreateIntrinsic(llvm::Intrinsic::cttz, { val->getType() }, { val, sel->builder().getFalse() });
  return sel->builder().CreateTrunc(res, sel->type(T_INT));
}

llvm::Value* convI2L_reg_reg_zexNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  return sel->builder().CreateZExt(a, sel->type(T_LONG));
}

llvm::Value* MoveL2D_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  assert(val->getType() == sel->type(T_LONG), "wrong type");
  return sel->builder().CreateBitCast(val, sel->type(T_DOUBLE));
}

llvm::Value* sarL_rReg_CLNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  llvm::Type* longTy = sel->type(T_LONG);
  if(b->getType() != longTy) {
    b = sel->builder().CreateSExt(b, longTy);
  }
  return sel->builder().CreateAShr(a, b);
}

llvm::Value* divL_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateSDiv(a, b);
}

llvm::Value* and_cmpLTMaskNode::select(Selector* sel) {
  llvm::Value* p = sel->select_node(in(1));
  llvm::Value* q = sel->select_node(in(2));
  llvm::Value* y = sel->select_node(in(3));
  llvm::Value* pred = sel->builder().CreateICmpSLT(p, q);
  return sel->builder().CreateSelect(pred, y, sel->null(y->getType()));
}

llvm::Value* i2sNode::select(Selector* sel) {
  llvm::Value* i_op = sel->select_node(in(1));
  llvm::Value* res = sel->builder().CreateTrunc(i_op, sel->type(T_SHORT));
  return sel->builder().CreateSExt(res, sel->type(T_INT));
}

llvm::Value* minI_rReg_imm_0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  llvm::Value* pred = sel->builder().CreateICmpSLE(a, b);
  return sel->builder().CreateSelect(pred, a, b);
}

llvm::Value* convD2F_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  return sel->builder().CreateFPCast(a, sel->type(T_FLOAT));
}

llvm::Value* negF_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateFNeg(val);
}

llvm::Value* storeImmF0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_FLOAT), addr);
  return NULL;
}

llvm::Value* absF_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateIntrinsic(llvm::Intrinsic::fabs, val->getType(), val);
}

llvm::Value* sqrtF_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateIntrinsic(llvm::Intrinsic::sqrt, val->getType(), val);
}

llvm::Value* tanD_regNode::select(Selector* sel) {
  llvm::Value* x = sel->select_node(in(1));
  auto tan = static_cast<double (*) (double)>(std::tan);
  return sel->call_C((void *)tan, sel->type(T_DOUBLE), { x });
}

llvm::Value* loadI2USNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* ret = sel->load(addr, T_SHORT);
  return sel->builder().CreateZExt(ret, sel->type(T_INT));
}

llvm::Value* storeImmC0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_CHAR), addr);
  return NULL;
}

llvm::Value* Repl2FNode::select(Selector* sel) {
  llvm::Value* input = sel->select_node(in(1));
  input = sel->builder().CreateBitCast(input, sel->type(T_INT));
  input = sel->builder().CreateZExt(input, sel->type(T_LONG));
  llvm::Value* tmp = sel->builder().CreateShl(input, 32);
  llvm::Value* tmp2 = sel->builder().CreateLShr(tmp, 32);
  return sel->builder().CreateAdd(tmp, tmp2);
}

llvm::Value* loadSNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_SHORT);
  return sel->builder().CreateSExt(res, sel->type(T_INT));  
}

llvm::Value* andnL_rReg_rReg_rReg_0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  a = sel->builder().CreateNot(a);
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* mergeD_reg_regNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  llvm::Value* v1 = sel->select_node(in(2));
  llvm::Value* v2 = sel->select_node(in(3));
  return sel->builder().CreateSelect(pred, v2, v1);
}

llvm::Value* powD_regNode::select(Selector* sel) {
  llvm::Value* x = sel->select_node(in(1));
  llvm::Value* y = sel->select_node(in(2));
  auto pow = static_cast<double (*) (double,double)>(std::pow);
  return sel->call_C((void *)pow, sel->type(T_DOUBLE), { x, y });
}

long vadd2f(long l1, long l2) {
  long r;
  float *rp = (float*)&r, *l1p = (float*)&l1, *l2p = (float*)&l2;
  *rp++ = (*l1p++) + (*l2p++);
  *rp = (*l1p) + (*l2p);
  return r;
}

llvm::Value* vadd2FNode::select(Selector* sel) {
  llvm::Value* src1 = sel->select_node(in(1));
  llvm::Value* src2 = sel->select_node(in(2));
  return sel->call_C((void *)vadd2f, sel->type(T_LONG), { src1, src2 });
}

llvm::Value* MoveI2F_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateBitCast(val, sel->type(T_FLOAT));
}

llvm::Value* andnI_rReg_rReg_rRegNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  b = sel->builder().CreateNot(b);
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* storeImmD0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(sel->null(T_DOUBLE), addr);
  return NULL;
}

llvm::Value* convD2L_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateFPToSI(val, sel->type(T_LONG));
}

llvm::Value* convF2L_reg_regNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
  return sel->builder().CreateFPToSI(val, sel->type(T_LONG));
}

llvm::Value* divL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  return sel->builder().CreateSDiv(a, b);
}

llvm::Value* cmpL3_reg_regNode::select(Selector* sel) {
  llvm::Value* left = sel->select_node(in(1));
  llvm::Value* right = sel->select_node(in(2));
  llvm::Value* eq = sel->builder().CreateICmpEQ(left, right);
  llvm::Value* less = sel->builder().CreateICmpSLT(left, right);
  llvm::Value* merge = sel->builder().CreateSelect(eq, sel->null(T_INT), sel->builder().getInt32(1));
  return sel->builder().CreateSelect(eq, sel->builder().getInt32(-1), merge);
}

llvm::Value* cmpF3_regNode::select(Selector* sel) {
  llvm::Value* left = sel->select_node(in(1));
  llvm::Value* right = sel->select_node(in(2));
  llvm::Value* eq = sel->builder().CreateFCmpUEQ(left, right);
  llvm::Value* less = sel->builder().CreateFCmpULT(left, right);
  llvm::Value* merge = sel->builder().CreateSelect(eq, sel->null(T_INT), sel->builder().getInt32(1));
  return sel->builder().CreateSelect(eq, sel->builder().getInt32(-1), merge);
}

llvm::Value* cmpF3_immNode::select(Selector* sel) {
  llvm::Value* left = sel->select_node(in(1));
  llvm::Value* right = sel->select_oper(opnd_array(2));
  llvm::Value* eq = sel->builder().CreateFCmpUEQ(left, right);
  llvm::Value* less = sel->builder().CreateFCmpULT(left, right);
  llvm::Value* merge = sel->builder().CreateSelect(eq, sel->null(T_INT), sel->builder().getInt32(1));
  return sel->builder().CreateSelect(eq, sel->builder().getInt32(-1), merge);
}

llvm::Value* rolI_rReg_i8_0Node::select(Selector* sel) {
  llvm::Value* arg = sel->select_node(in(1));
  llvm::Value* shift = sel->select_oper(opnd_array(3));
  return sel->left_circular_shift(arg, shift, 32);
}

llvm::Value* rolI_rReg_i8Node::select(Selector* sel) {
  llvm::Value* arg = sel->select_node(in(1));
  llvm::Value* shift = sel->select_oper(opnd_array(2));
  return sel->left_circular_shift(arg, shift, 32);
}

llvm::Value* andnI_rReg_rReg_rReg_0Node::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  a = sel->builder().CreateNot(a);
  llvm::Value* b = sel->select_node(in(2));
  return sel->builder().CreateAnd(a, b);
}

llvm::Value* loadV4Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_LONG);
}

llvm::Value* storeV4Node::select(Selector* sel) {
  int op_index = MemNode::Address + 1;
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = sel->select_node(in(op_index++));
  sel->store(value, addr);
  return NULL;
}

llvm::Value* logD_regNode::select(Selector* sel) {
  llvm::Value* x = sel->select_node(in(1));
  auto log = static_cast<double (*) (double)>(std::log);
  return sel->call_C((void *)log, sel->type(T_DOUBLE), { x });
}

llvm::Value* loadI2UBNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConI1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConI0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConL0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConUL32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConL32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConP0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConN0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConF0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConD0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchrNTANode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchrT0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchrT2Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchwNTANode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT2Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeTLABendNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmCM0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* countTrailingZerosINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* popCountINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* popCountLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_loadfenceNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_storefenceNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convP2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convN2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* encodeKlass_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUP_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeN_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUN_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rReg_L1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadPLockedNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storePConditionalNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeIConditionalNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xaddLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xchgINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xchgLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xchgPNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xchgNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subP_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulX_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulX_reg_reg_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* modI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* modL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i1_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_imm_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_imm_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_Var_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_Var_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_imm_C32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_imm_C32_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_Var_C32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_Var_C32_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_i1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_i1_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_i8Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_i8_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_imm_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_imm_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_Var_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_Var_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_imm_C32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_imm_C32_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_Var_C32Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorI_rReg_Var_C32_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_i1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_i1_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_i8Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_i8_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_imm_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_imm_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_Var_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_Var_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_imm_C64Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_imm_C64_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_Var_C64Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolL_rReg_Var_C64_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_i1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_i1_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_i8Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_i8_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_imm_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_imm_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_Var_C0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_Var_C0_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_imm_C64Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_imm_C64_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_Var_C64Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rorL_rReg_Var_C64_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andI2L_rReg_imm255Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andI2L_rReg_imm65535Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* ornI_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* ornI_rReg_rReg_rReg_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xornI_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xornI_rReg_rReg_rReg_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andnL_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* ornL_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* ornL_rReg_rReg_rReg_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xornL_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xornL_rReg_rReg_rReg_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpLTMaskNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpLTMask0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cadd_cmpLTMaskNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cadd_cmpLTMask_1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cadd_cmpLTMask_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cadd_cmpLTMask_2Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* and_cmpLTMask_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpD3_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpD3_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cosD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sinD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* log10D_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* expD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* roundFloat_nopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* roundDouble_nopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convL2F_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* dummy_convI2L2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convL2I2LNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* array_equalsNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowAddI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowAddI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowAddL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowAddL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowSubI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowSubI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowSubL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowSubL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowNegI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* overflowNegL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* maxI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpLoopEndUNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* if_fastlock_rtmNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* safePoint_poll_farNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divF_F1_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* absD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}


llvm::Value* rsqrtF1_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rsqrtD1_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sqrtF_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sqrtD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sqrtD_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* Repl2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* Repl4SNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* Repl4BNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* Repl8BNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd2I_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd4SNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd4S_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd8BNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd8B_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vsub2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vsub2I_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vmul2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vmul2I_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vadd2F_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vsub2FNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vsub2F_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vmul2FNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* vmul2F_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

