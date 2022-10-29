#include "stack_llvm.hpp"

#include "llvmCodeGen.hpp"

size_t LlvmStack::calc_alloc() {
  size_t extra_alloc = 0;
  _ret_addr_offset = -(extra_alloc += wordSize);
  if (cg()->C->has_method()) {
    _orig_pc_offset = -(extra_alloc += wordSize);
  }
  _mon_offset = -extra_alloc;
  return cg()->nof_monitors() * monitor_size() + extra_alloc;
}

size_t LlvmStack::monitor_size() const { return BasicObjectLock::size() * wordSize; }

int32_t LlvmStack::mon_offset(int32_t index) const {
  assert(index >= 0 && index < cg()->nof_monitors(), "invalid monitor index");
  return _mon_offset - (index + 1) * monitor_size();
}

int32_t LlvmStack::mon_obj_offset(int32_t index) const {
  int32_t object_offset = BasicObjectLock::obj_offset_in_bytes();
  return mon_offset(index) + object_offset;
}

int32_t LlvmStack::mon_header_offset(int32_t index) const {
  int32_t lock_offset = BasicObjectLock::lock_offset_in_bytes();
  int32_t header_offset = BasicLock::displaced_header_offset_in_bytes();
  return mon_offset(index) + lock_offset + header_offset;
}

size_t LlvmStack::frame_size(MachSafePointNode* sfn) const {
  if (sfn && sfn->is_MachCall())
    return _frame_size - (max_spill() - spill_sizes.at(sfn->as_MachCall()));
  return _frame_size;
}

int32_t LlvmStack::unextended_mon_obj_offset(MachSafePointNode* sfn, int idx) const {
  return unextended_mon_offset(sfn, idx) + BasicObjectLock::obj_offset_in_bytes();
}

size_t LlvmStack::count_spills(MachCallNode* node, const std::vector<llvm::Value*>& args) {
  unsigned nf_cnt = 0;
  size_t spill_size = 0, first_spill_size = 0;
  for (llvm::Value* val : args) {
    llvm::Type* ty = val->getType();
    if (ty->isFloatingPointTy()) continue;
    nf_cnt++;
    if (nf_cnt > Selector::NF_REGS) {
      size_t size = ty->isPointerTy()
      ? cg()->mod()->getDataLayout().getIndexTypeSizeInBits(val->getType())
      : ty->getScalarSizeInBits();
      size >>= 3;
      spill_size += size == 8 ? 8 : 4;
      first_spill_size = first_spill_size ? first_spill_size : spill_size;
    }
  }
  if (spill_size == first_spill_size) {
    spill_size = 0;
  } else {
    const int ALIGNMENT = 16;
    spill_size = ((spill_size-1) & -ALIGNMENT) + ALIGNMENT;
  }
  _max_spill = MAX(max_spill(), spill_size);
  spill_sizes.insert({ node, spill_size });
  return spill_size;
}

int LlvmStack::offset(MachSafePointNode* sfn, LocationAccessor la) {
  const int RBP = 6, RSP = 7;
  assert(la.getKind() == LocationKind::Indirect, "these are values located on stack");
  if (la.getDwarfRegNum() == RSP) return la.getOffset();
  if (la.getDwarfRegNum() == RBP) return la.getOffset() + cg()->stack().unext_offset(sfn);
  Unimplemented();
}
