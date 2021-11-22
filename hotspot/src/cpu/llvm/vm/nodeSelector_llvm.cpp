#include "opto/cfgnode.hpp"
#include "opto/locknode.hpp"
#include "adfiles/ad_llvm.hpp"

#include "selector_llvm.hpp"

llvm::Value* tlsLoadPNode::select(Selector* sel) {                                          
  return sel->thread();
}

llvm::Value* storePNode::select(Selector* sel) {
  int op_index;
  llvm::Value *addr = sel->select_address(this, op_index);
  llvm::Value* value = sel->select_node(in(op_index++));
  sel->store(value, addr);
  sel->mark_mptr(value);
  return NULL;
}

llvm::Value* MachProjNode::select(Selector* sel) {
  if (in(0)->is_Start()) {
    if (_con == TypeFunc::FramePtr) {
      return sel->FP();
    }
    if (_con == TypeFunc::ReturnAdr) {
      llvm::Type* retType = llvm::Type::getInt8PtrTy(sel->ctx());
      std::vector<llvm::Value*> args { sel->builder().getInt32(0) };
      return sel->call_intrinsic("llvm.returnaddress", retType, args);
    }
    if (_con < TypeFunc::Parms) {
      return NULL;
    }
    int arg_num = sel->param_to_arg(_con);
    llvm::Value* arg = sel->func()->arg_begin() + arg_num;
    if (bottom_type()->isa_oopptr() != NULL) {
      sel->mark_mptr(arg);
    }
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
  const TypeTuple* d = tf()->domain();
  std::vector<llvm::Value*> args;
  for (uint i = TypeFunc::Parms; i < d->cnt(); ++i) {
    const Type* at = d->field_at(i);
    if (at->base() == Type::Half) continue;
    llvm::Value* arg = sel->select_node_or_const(in(i));
    args.push_back(arg);
  }
  sel->callconv_adjust(args);
  llvm::Type* retType = sel->type(tf()->return_type());
  return sel->call_external(entry_point(), retType, args);
}

llvm::Value* CallLeafDirectNode::select(Selector* sel) {
  const TypeTuple* d = tf()->domain();
  std::vector<llvm::Value*> args;
  for (uint i = TypeFunc::Parms; i < d->cnt(); ++i) {
    const Type* at = d->field_at(i);
    if (at->base() == Type::Half) continue;
    llvm::Value* arg = sel->select_node_or_const(in(i));
    args.push_back(arg);
  }
  sel->callconv_adjust(args);
  llvm::Type* retType = sel->type(tf()->return_type());
  return sel->call_external(entry_point(), retType, args);
}

llvm::Value* storeImmP0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* value = llvm::Constant::getNullValue(
    llvm::Type::getInt8PtrTy(sel->ctx()));
  sel->store(value, addr);
  return NULL;
}

llvm::Value* loadPNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_ADDRESS);
  if (bottom_type()->isa_oopptr() != NULL) {
    sel->mark_mptr(res);
  }
  return res;
}

llvm::Value* cmpP_reg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  assert(a->getType()->isPointerTy() && b->getType()->isPointerTy(), "not pointer(s)");
  a = sel->builder().CreatePointerCast(a, b->getType());
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* jmpConUNode::select(Selector* sel) {
  llvm::Value* pred = sel->select_node(in(1));
  sel->select_if(pred, this);
  return NULL;
}

llvm::Value* loadConPNode::select(Selector* sel) {
  ///TODO: handle managed pointer
  return sel->select_oper(opnd_array(1));
}

llvm::Value* TailCalljmpIndNode::select(Selector* sel) {
  sel->epilog();
  llvm::Value* target_pc = sel->select_node(in(TypeFunc::Parms));
  sel->replace_return_address(target_pc);
  ///TODO: there should be jump instead of return, as the return address should be preserved on stack
  llvm::Type* retType = sel->func()->getReturnType();
  if (retType->isVoidTy()) { 
    sel->builder().CreateRetVoid(); 
  }
  else { 
    sel->builder().CreateRet(llvm::Constant::getNullValue(retType)); 
  }
  return NULL;
 }

llvm::Value* RetNode::select(Selector* sel) {
  sel->epilog();
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
  sel->epilog();
  llvm::Value* target_pc = sel->select_node(in(TypeFunc::Parms));
  sel->replace_return_address(target_pc);
  llvm::Type* retType = sel->func()->getReturnType();
  if (retType->isVoidTy()) {
    sel->builder().CreateRetVoid();
  }
  else {
    llvm::Value* x_oop = sel->select_node(in(TypeFunc::Parms + 1));
    x_oop = sel->builder().CreatePointerCast(x_oop, retType); 
    sel->builder().CreateRet(x_oop);
  }
  return NULL;
}

llvm::Value* loadTLABtopNode::select(Selector* sel) {
  return sel->load(sel->tlab_top(), T_ADDRESS);
}

llvm::Value* loadTLABendNode::select(Selector* sel) {
  return sel->load(sel->tlab_end(), T_ADDRESS);
}

llvm::Value* addP_rReg_immNode::select(Selector* sel) {
  ///TODO: handle managed pointer
  return sel->gep(sel->select_node(in(2)), sel->select_oper(opnd_array(2)));
}


llvm::Value* cmpP_reg_regNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_node(in(2));
  assert(a->getType()->isPointerTy() && b->getType()->isPointerTy(), "not pointer(s)");
  a = sel->builder().CreatePointerCast(a, b->getType());
  return sel->select_condition(this, a, b, false, false);
}

llvm::Value* storeTLABtopNode::select(Selector* sel) {
  sel->store(sel->select_node(in(MemNode::ValueIn)), sel->tlab_top());
  return NULL;
}

llvm::Value* prefetchAllocNTANode::select(Selector* sel) {
  llvm::Type* ptrTy = llvm::Type::getInt8PtrTy(sel->ctx());
  llvm::Value* addr = sel->select_address(this);
  addr = sel->builder().CreatePointerCast(addr, ptrTy);
  std::vector<llvm::Value*> args {
    addr, sel->builder().getInt32(0),
    sel->builder().getInt32(0), sel->builder().getInt32(1) };
  sel->call_intrinsic("llvm.prefetch.p0i8", sel->type(T_VOID), args);
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
  int op_index;
  llvm::Value* addr = sel->select_address(this, op_index);
  llvm::Value* value = sel->select_node(in(op_index++));
  sel->store(value, addr);
  return NULL;
}

llvm::Value* storeImmI0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(llvm::Constant::getNullValue(sel->type(T_INT)), addr);
  return NULL;
}

llvm::Value* jmpDirNode::select(Selector* sel) {
  Block* target = sel->block()->non_connector_successor(0);
  sel->builder().CreateBr(sel->basic_block(target));
  return NULL;
}

llvm::Value* CallStaticJavaDirectNode::select(Selector* sel) {
  const TypeTuple* d = tf()->domain();
  std::vector<llvm::Value*> args;
  for (uint i = TypeFunc::Parms; i < d->cnt(); ++i) {
    const Type* at = d->field_at(i);
    if (at->base() == Type::Half) continue;
    llvm::Value* arg = sel->select_node_or_const(in(i));
    args.push_back(arg);
  }
  sel->callconv_adjust(args);
  BasicType ret_type = tf()->return_type();
  assert(ret_type != T_NARROWOOP, "unexpected behavior check");
  llvm::Type* retType = sel->type(ret_type);

  llvm::Value* ret = sel->call(this, retType, args);
  auto c_id = sel->C->cfg()->get_block_for_node(this)->end()->class_id();
  if (c_id != Class_MachReturn && c_id != Class_MachGoto) {
    Block* target = sel->block()->non_connector_successor(0);
    sel->builder().CreateBr(sel->basic_block(target));
  }
  return ret;
}

llvm::Value* membar_storestoreNode::select(Selector* sel) {
  // this barrier is used for cpu self-visibility of store ordering
  return NULL;
}

llvm::Value* checkCastPPNode::select(Selector* sel) {
  llvm::Value* val = sel->select_node(in(1));
#ifdef ASSERT
  ///TODO: handle managed pointer
#endif
  sel->mark_mptr(val);
  return val;
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
  ///TODO: mark pointers
  return phi;
}

llvm::Value* CreateExceptionNode::select(Selector* sel) {
  llvm::Value* val = llvm::Constant::getNullValue(sel->type(T_OBJECT));
  sel->mark_mptr(val);
  return val;
}

llvm::Value* RethrowExceptionNode::select(Selector* sel) {
  // llvm::Value* ex = sel->select_node(in(TypeFunc::Parms));
  // llvm::Value* addr = sel->builder().CreateGEP(sel->thread(), sel->builder().getInt32(in_bytes(Thread::pending_exception_offset())));
  // sel->store(ex, addr);
  sel->epilog();
  llvm::Type* retType = sel->func()->getReturnType();
  if (!retType->isVoidTy()) {
    sel->builder().CreateRet(llvm::Constant::getNullValue(retType));
  }
  else {
    sel->builder().CreateRetVoid();
  }
  return NULL;
}

llvm::Value* storeImmL0Node::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  sel->store(llvm::Constant::getNullValue(sel->type(T_LONG)), addr);
  return NULL;
}

llvm::Value* loadNNode::select(Selector* sel) {
  llvm::Value* addr = sel->select_address(this);
  llvm::Value* res = sel->load(addr, T_NARROWOOP);
  assert(bottom_type()->isa_narrowoop(), "check");
  if (bottom_type()->isa_narrowoop() != NULL) {
    sel->mark_nptr(res);
  }
  return res;
}

llvm::Value* decodeHeapOopNode::select(Selector* sel) {
  return sel->decode_heap_oop(sel->select_node(in(1)), false);
}

llvm::Value* ShouldNotReachHereNode::select(Selector *sel) {
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

llvm::Value* andL_rRegNode::select(Selector* sel){
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
  return sel->builder().CreateShl(a, b);
}

llvm::Value* salL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
  if(!b->getType()->isIntegerTy(64))
    b = sel->builder().CreateSExt(b, sel->builder().getInt64Ty());
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
  if(!b->getType()->isIntegerTy(64))
    b = sel->builder().CreateSExt(b, sel->builder().getInt64Ty());
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
  return sel->builder().CreateLShr(a, b);
}

llvm::Value* shrL_rReg_immNode::select(Selector* sel) {
  llvm::Value* a = sel->select_node(in(1));
  llvm::Value* b = sel->select_oper(opnd_array(2));
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
  assert(a->getType() == sel->type(T_INT) && b->getType() == sel->type(T_INT), "operands must be int");
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

llvm::Value* storeBNode::select(Selector *sel) {
  int op_index;
  llvm::Value* addr = sel->select_address(this, op_index);
  llvm::Value* value = sel->select_node(in(op_index++));
  sel->store(value, addr);
  return NULL;
}

llvm::Value* loadLNode::select(Selector *sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_LONG);
}

llvm::Value* loadNKlassNode::select(Selector *sel) {
  llvm::Value* addr = sel->select_address(this);
  return sel->load(addr, T_NARROWKLASS);
}

llvm::Value* castP2XNode::select(Selector *sel) {
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

llvm::Value* storeLConditionalNode::select(Selector *sel) {
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

  int mon_number = box_n->stack_slot() / 2;

  Block* slow_block = sel->block()->non_connector_successor(0);
  Block* ok_block = sel->block()->non_connector_successor(1);
  llvm::BasicBlock* bb = sel->builder().GetInsertBlock();
  llvm::BasicBlock* recr_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_recr", sel->func());
  llvm::BasicBlock* slow_bb = sel->basic_block(slow_block);
  llvm::BasicBlock* ok_bb = sel->basic_block(ok_block);

  llvm::Value* obj = sel->select_node(in(1));
  sel->mark_mptr(obj);

  llvm::Value* frame_top = sel->SP();
  llvm::Value* mark_offset = sel->builder().getInt64(oopDesc::mark_offset_in_bytes());
  llvm::Value* mon_object_offset = sel->builder().getInt64(sel->mon_obj_offset(mon_number));
  llvm::Value* mon_header_offset = sel->builder().getInt64(sel->mon_header_offset(mon_number));
  llvm::Value* unlock_mask = sel->builder().getInt64(markOopDesc::unlocked_value);

  MachOper* cond = opnd_array(1);

  // float cur_freq = sel->cur_block()->freq();
  // recr_bb->setFreq(1 * cur_freq / 3.0f);
  // ok_bb->setFreq(2 * cur_freq / 3.0f);

  llvm::Value* mark_addr = sel->gep(obj, mark_offset);
  llvm::Value* mark = sel->load(mark_addr, T_LONG);

  if (!UseOptoBiasInlining) {
    sel->store(obj, sel->gep(frame_top, mon_object_offset));
    if (UseBiasedLocking) {
      llvm::BasicBlock* cas_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_cas", sel->func());
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
      
      llvm::Value* klass_offset = sel->builder().getInt64(oopDesc::klass_offset_in_bytes());
      llvm::Value* owner_tmp3;
      if (UseCompressedClassPointers) {
        llvm::Value* narrow_klass = sel->load(sel->gep(obj, klass_offset), T_NARROWKLASS);
        owner_tmp3 = sel->decodeKlass_not_null(narrow_klass);
      } else {
        owner_tmp3 = sel->load(sel->gep(obj, klass_offset), T_METADATA);
      }

      llvm::Value* klass_header = sel->load(sel->gep(owner_tmp3, prototype_offset), T_ADDRESS);
      llvm::Value* owner_tmp1 = sel->builder().CreateOr(sel->thread(), klass_header);
      llvm::Value* owner_tmp2 = sel->builder().CreateXor(mark, owner_tmp1);
      llvm::Value* _and_ = sel->builder().CreateAnd(owner_tmp2, owner_mask);
      llvm::Value* zero = llvm::ConstantInt::getNullValue(_and_->getType());
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
  }
  
  llvm::Value* disp = sel->builder().CreateOr(mark, unlock_mask);
  llvm::Value* mon_header_addr = sel->gep(frame_top, mon_header_offset);
  sel->store(disp, mon_header_addr);
  llvm::Value* pred = sel->cmpxchg(mark_addr, disp, mon_header_addr);
  pred = sel->builder().CreateExtractValue(pred, 1);
  if (cond->ccode() == 1) {
    sel->builder().CreateCondBr(pred, recr_bb, ok_bb);
  } else {
    sel->builder().CreateCondBr(pred, ok_bb, recr_bb);
  }

  sel->builder().SetInsertPoint(recr_bb);
  llvm::Value* sbase_offset = sel->builder().getInt64(in_bytes(Thread::stack_base_offset()));
  llvm::Value* ssize_offset = sel->builder().getInt64(in_bytes(Thread::stack_size_offset()));
  llvm::Value* lock_mask    = sel->builder().getInt64(~markOopDesc::lock_mask_in_place);
  llvm::Value* mark_lock = sel->builder().CreateAnd(disp, lock_mask);
  llvm::Value* stack_base = sel->load(sel->gep(sel->thread(), sbase_offset), T_ADDRESS);
  llvm::Value* stack_size = sel->load(sel->gep(sel->thread(), ssize_offset), T_LONG);
  llvm::Value* stack_top = sel->gep(stack_base, sel->builder().CreateNeg(stack_size));
  stack_base = sel->builder().CreatePtrToInt(stack_base, sel->type(T_LONG));
  stack_top = sel->builder().CreatePtrToInt(stack_top, sel->type(T_LONG));
  llvm::Value* pr_base = sel->builder().CreateICmpULE(mark_lock, stack_base);
  llvm::Value* pr_top = sel->builder().CreateICmpULE(stack_top, mark_lock);
  llvm::Value* pr_res = sel->builder().CreateAnd(pr_top, pr_base);

  sel->builder().CreateCondBr(pr_res, slow_bb, ok_bb);
  return NULL;
}

llvm::Value* if_fastunlockNode::select(Selector *sel) {
  BoxLockNode* box_n = in(2)->as_BoxLock();
  int mon_number = box_n->stack_slot() / 2;
  llvm::Value* obj = sel->select_node(in(1));
  llvm::Value* frame_top = sel->SP();
  llvm::Value* mon_object_offset = sel->builder().getInt64(sel->mon_obj_offset(mon_number));
  llvm::Value* mon_header_offset = sel->builder().getInt64(sel->mon_header_offset(mon_number));
  llvm::Value* mon_header_addr = sel->gep(frame_top, mon_header_offset);
  llvm::Value* mark_offset = sel->builder().getInt64(oopDesc::mark_offset_in_bytes());
  llvm::Value* mark_addr = sel->gep(obj, mark_offset);

  Block* slow_block = sel->block()->non_connector_successor(0);
  Block* ok_block = sel->block()->non_connector_successor(1);
  llvm::BasicBlock* bb = sel->builder().GetInsertBlock();
  llvm::BasicBlock* fast_bb = llvm::BasicBlock::Create(sel->ctx(), bb->getName() + "_FastUnlock", sel->func());
  llvm::BasicBlock* slow_bb = sel->basic_block(slow_block);
  llvm::BasicBlock* ok_bb = sel->basic_block(ok_block);

  MachOper* cond = opnd_array(1);
  
  // float cur_freq = sel->cur_block()->freq();
  // fast_bb->setFreq(2 * cur_freq / 3.0f);
  // ok_bb->setFreq(1 * cur_freq / 3.0f);

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

  llvm::Value* disp = sel->load(mon_header_addr, T_LONG);
  llvm::Value* pred = sel->builder().CreateICmpEQ(disp, llvm::Constant::getNullValue(disp->getType()));
  sel->builder().CreateCondBr(pred, fast_bb, ok_bb);

  sel->builder().SetInsertPoint(fast_bb);

  llvm::Value* pred2 = sel->cmpxchg(mark_addr, mon_header_addr, disp);
  pred2 = sel->builder().CreateExtractValue(pred2, 1);
  if (cond->ccode() == 1) {
    std::swap(ok_bb, slow_bb);
  }
  sel->builder().CreateCondBr(pred2, ok_bb, slow_bb);

  return NULL;
}

llvm::Value* BoxLockNode::select(Selector *sel) {
  return sel->gep(sel->SP(), sel->mon_offset(stack_slot() / 2));
}

llvm::Value* membar_acquire_lockNode::select(Selector* sel) {
  return NULL;
}

llvm::Value* membar_release_lockNode::select(Selector* sel) {
  return NULL;
}

llvm::Value* MachNullCheckNode::select(Selector *sel) {
  // llvm::Value* val = sel->select_node(in(1));
  // llvm::Value* pred = sel->builder().CreateICmpEQ(val, llvm::Constant::getNullValue(val->getType()));
  // sel->select_if(pred, this);
  Block* next_block = sel->block()->non_connector_successor(1);
  llvm::BasicBlock* next_bb = sel->basic_block(next_block);
  sel->builder().CreateBr(next_bb);
  return NULL;
}

llvm::Value* loadBNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadUBNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadSNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadUSNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadI2UBNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadI2USNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadRangeNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadKlassNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}


llvm::Value* loadFNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadDNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConI1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConI0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConLNode::select(Selector* sel){
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

llvm::Value* loadConNNode::select(Selector* sel){
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

llvm::Value* prefetchAllocNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT2Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeCNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeTLABendNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmN0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmC0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmB0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmCM0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeFNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmF0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeDNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmD0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* countLeadingZerosINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* countLeadingZerosLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* countTrailingZerosINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* countTrailingZerosLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* popCountINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* popCountLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_acquireNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_loadfenceNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_releaseNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_storefenceNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_volatileNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* unnecessary_membar_volatileNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* castX2PNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convP2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convN2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* encodeHeapOopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* encodeHeapOop_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* decodeHeapOop_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* encodeKlass_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jumpXtndNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeI_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUI_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeUD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mergeP_reg_regNode::select(Selector* sel){
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

llvm::Value* addP_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* castPPNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* castIINode::select(Selector* sel){
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

llvm::Value* compareAndSwapPNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* compareAndSwapNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* compareAndSwapLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* compareAndSwapINode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xaddINode::select(Selector* sel){
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

llvm::Value* subI_rReg_imm0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rReg_imm0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subP_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulI_rReg_immNode::select(Selector* sel){
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

llvm::Value* divL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* modI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* modL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* modL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* salL_index_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sarL_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* i2bNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* i2sNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i1_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i8Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* rolI_rReg_i8_0Node::select(Selector* sel){
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

llvm::Value* andI_rReg_imm65535Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andnI_rReg_rReg_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andnI_rReg_rReg_rReg_0Node::select(Selector* sel){
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

llvm::Value* andnL_rReg_rReg_rReg_0Node::select(Selector* sel){
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

llvm::Value* convI2BNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convP2BNode::select(Selector* sel){
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

llvm::Value* and_cmpLTMaskNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* and_cmpLTMask_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpF3_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpF3_immNode::select(Selector* sel){
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

llvm::Value* tanD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* log10D_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* logD_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* powD_regNode::select(Selector* sel){
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

llvm::Value* convD2F_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convF2I_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convF2L_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convD2I_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convD2L_reg_regNode::select(Selector* sel){
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

llvm::Value* convI2L_reg_reg_zexNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convI2L_z_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* zerox_long_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* MoveF2I_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* MoveD2L_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* MoveI2F_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* MoveL2D_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* clear_memoryNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* string_compareNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* string_indexof_conNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* string_indexofNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* string_equalsNode::select(Selector* sel){
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

llvm::Value* cmpL3_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* minI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* minI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* minI_rReg_imm_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* maxI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* maxI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* maxI_rReg_imm_0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpandI_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpandI_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpU_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpU_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpandL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpN_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpN_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpLoopEndUNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpLoopEndNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* if_fastlock_rtmNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* partialSubtypeCheckNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* safePoint_pollNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* safePoint_poll_farNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallDynamicJavaDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallLeafNoFPDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divF_F1_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* absF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* absD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* negF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* negD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sqrtF_regNode::select(Selector* sel){
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

llvm::Value* loadV4Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadV8Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeV4Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeV8Node::select(Selector* sel){
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

llvm::Value* Repl2FNode::select(Selector* sel){
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

llvm::Value* vadd2FNode::select(Selector* sel){
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

