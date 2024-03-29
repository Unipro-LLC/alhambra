/*
 * Copyright (c) 2003, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#ifndef CPU_LLVM_VM_STUBROUTINES_LLVM_64_HPP
#define CPU_LLVM_VM_STUBROUTINES_LLVM_64_HPP

// This file holds the platform specific parts of the StubRoutines
// definition. See stubRoutines.hpp for a description on how to
// extend it.

static bool    returns_to_call_stub(address return_pc)   { return return_pc == _call_stub_return_address; }

enum platform_dependent_constants {
  code_size1 = 19000,          // simply increase if too small (assembler will crash if too small)
  code_size2 = 23000           // simply increase if too small (assembler will crash if too small)
};

static address _forward_exception_compiler_entry;
static address _forward_exception_compiler_rethrow_entry;
static address _poll_stub_entry;
public:
static address forward_exception_compiler_entry()                 { return _forward_exception_compiler_entry; }
static address forward_exception_compiler_rethrow_entry()         { return _forward_exception_compiler_rethrow_entry; }
static address poll_stub_entry() { return _poll_stub_entry; }

class x86 {
 friend class StubGenerator;

 private:
  static address _get_previous_fp_entry;
  static address _get_previous_sp_entry;

  static address _f2i_fixup;
  static address _f2l_fixup;
  static address _d2i_fixup;
  static address _d2l_fixup;

  static address _float_sign_mask;
  static address _float_sign_flip;
  static address _double_sign_mask;
  static address _double_sign_flip;

 public:

  static address get_previous_fp_entry()
  {
    return _get_previous_fp_entry;
  }

  static address get_previous_sp_entry()
  {
    return _get_previous_sp_entry;
  }

  static address f2i_fixup()
  {
    return _f2i_fixup;
  }

  static address f2l_fixup()
  {
    return _f2l_fixup;
  }

  static address d2i_fixup()
  {
    return _d2i_fixup;
  }

  static address d2l_fixup()
  {
    return _d2l_fixup;
  }

  static address float_sign_mask()
  {
    return _float_sign_mask;
  }

  static address float_sign_flip()
  {
    return _float_sign_flip;
  }

  static address double_sign_mask()
  {
    return _double_sign_mask;
  }

  static address double_sign_flip()
  {
    return _double_sign_flip;
  }

#ifndef CPU_LLVM_VM_STUBROUTINES_LLVM_HPP
#define CPU_LLVM_VM_STUBROUTINES_LLVM_HPP

// This file holds the platform specific parts of the StubRoutines
// definition. See stubRoutines.hpp for a description on how to
// extend it.

 private:
  static address _verify_mxcsr_entry;
  // shuffle mask for fixing up 128-bit words consisting of big-endian 32-bit integers
  static address _key_shuffle_mask_addr;
  // masks and table for CRC32
  static uint64_t _crc_by128_masks[];
  static juint    _crc_table[];

 public:
  static address verify_mxcsr_entry()    { return _verify_mxcsr_entry; }
  static address key_shuffle_mask_addr() { return _key_shuffle_mask_addr; }
  static address crc_by128_masks_addr()  { return (address)_crc_by128_masks; }

#endif // CPU_LLVM_VM_STUBROUTINES_LLVM_32_HPP

};

#endif // CPU_LLVM_VM_STUBROUTINES_LLVM_64_HPP
