#include "stack_llvm.hpp"

#include "llvmCodeGen.hpp"

size_t LlvmStack::calc_alloc() {
  size_t extra_alloc = 0;
  _ret_addr_offset = -(extra_alloc += wordSize);
  _orig_pc_offset = -(extra_alloc += wordSize);
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

int32_t LlvmStack::unextended_mon_obj_offset(int idx) const {
  return unextended_mon_offset(idx) + BasicObjectLock::obj_offset_in_bytes();
}