#include "code_gen/llvmGlobals.hpp"
#include "adfiles/ad_llvm.hpp"
#include "selector_llvm.hpp"

class Selector;

llvm::Value* tlsLoadPNode::select(Selector* sel){
  llvm::Type* retType = llvm::Type::getInt8PtrTy(sel->ctx());
  std::vector<llvm::Type*> paramTypes;
  paramTypes.push_back(llvm::Type::getInt32Ty(sel->ctx()));
  llvm::FunctionType *funcTy = llvm::FunctionType::get(retType, 
                                                  paramTypes, 
                                                  false);
  llvm::IntegerType* intTy = llvm::Type::getIntNTy(sel->ctx(), 
    sel->mod()->getDataLayout().getPointerSize() * 8);
  llvm::Function *f = static_cast<llvm::Function*>(sel->builder().CreateIntToPtr(
    llvm::ConstantInt::get(intTy, (intptr_t) os::thread_local_storage_at, false),
    llvm::PointerType::getUnqual(funcTy)));                                                     
  std::vector<llvm::Value *> args;
  args.push_back(sel->builder().getInt32(ThreadLocalStorage::thread_index()));
  llvm::CallInst* ci = sel->builder().CreateCall(f, args);                                             
  return ci;
}

llvm::Value* RetNode::select(Selector* sel){
  bool has_value = TypeFunc::Parms < req();
  if (has_value) {
    Node* ret_node = in(TypeFunc::Parms);
    assert(ret_node != NULL, "check");
    llvm::Value* ret_value = sel->select_node(ret_node);
    sel->builder().CreateRet(ret_value);
  }
  else {
      sel->builder().CreateRetVoid();
  }
  return NULL;
}

llvm::Value* loadConINode::select(Selector* sel){
    BasicType btype = sel->comp()->tf()->return_type();
    llvm::Type* intTy = sel->convert_type(btype);
    llvm::Constant* cnst = llvm::ConstantInt::get(intTy, _opnd_array[1]->constant());
    return cnst;
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

llvm::Value* loadLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadRangeNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadTLABtopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadTLABendNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadPNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadKlassNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadNKlassNode::select(Selector* sel){
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

llvm::Value* loadConPNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConNKlassNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConP0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConN0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConFNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConF0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* loadConDNode::select(Selector* sel){
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

llvm::Value* prefetchAllocNTANode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* prefetchAllocT2Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeBNode::select(Selector* sel){
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

llvm::Value* storeTLABtopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeTLABendNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storePNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmP0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeNNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeNKlassNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmN0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmI0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* storeImmL0Node::select(Selector* sel){
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

llvm::Value* membar_acquire_lockNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_releaseNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_storefenceNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_release_lockNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_volatileNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* unnecessary_membar_volatileNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* membar_storestoreNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* castX2PNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* castP2XNode::select(Selector* sel){
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

llvm::Value* decodeHeapOopNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* decodeHeapOop_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* encodeKlass_not_nullNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* decodeKlass_not_nullNode::select(Selector* sel){
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

llvm::Value* addI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subI_rReg_I1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rReg_L1Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addP_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addP_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* checkCastPPNode::select(Selector* sel){
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

llvm::Value* storeLConditionalNode::select(Selector* sel){
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

llvm::Value* subI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subI_rReg_imm0Node::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subL_rRegNode::select(Selector* sel){
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

llvm::Value* mulI_rRegNode::select(Selector* sel){
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

llvm::Value* mulL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divI_rRegNode::select(Selector* sel){
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

llvm::Value* modI_rRegNode::select(Selector* sel){
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

llvm::Value* salI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* salI_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sarI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sarI_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* shrI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* shrI_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* salL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* salL_index_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* salL_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sarL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* sarL_rReg_CLNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* shrL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* shrL_rReg_CLNode::select(Selector* sel){
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

llvm::Value* andI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andI_rReg_immNode::select(Selector* sel){
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

llvm::Value* orI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* orI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xorI_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xorI_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* andL_rReg_immNode::select(Selector* sel){
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

llvm::Value* orL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* orL_rReg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xorL_rRegNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* xorL_rReg_immNode::select(Selector* sel){
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

llvm::Value* convF2D_reg_regNode::select(Selector* sel){
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

llvm::Value* convI2F_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convI2D_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convL2F_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convL2D_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* dummy_convI2L2INode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convL2I2LNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* convI2L_reg_regNode::select(Selector* sel){
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

llvm::Value* convL2I_reg_regNode::select(Selector* sel){
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

llvm::Value* cmpI_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpI_reg_immNode::select(Selector* sel){
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

llvm::Value* cmpL_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpandL_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpandL_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpP_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpP_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpN_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* cmpN_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpDirNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpConUNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* jmpConNode::select(Selector* sel){
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

llvm::Value* if_fastlockNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* if_fastunlockNode::select(Selector* sel){
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

llvm::Value* CallStaticJavaDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallDynamicJavaDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallRuntimeDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallLeafDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CallLeafNoFPDirectNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}


llvm::Value* TailCalljmpIndNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* tailjmpIndNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* CreateExceptionNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* RethrowExceptionNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* ShouldNotReachHereNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* addD_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* subD_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* mulD_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divF_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divF_reg_immNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divF_F1_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divD_reg_regNode::select(Selector* sel){
  NOT_PRODUCT(tty->print_cr("SELECT ME %s", Name())); Unimplemented(); return NULL;
}

llvm::Value* divD_reg_immNode::select(Selector* sel){
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

