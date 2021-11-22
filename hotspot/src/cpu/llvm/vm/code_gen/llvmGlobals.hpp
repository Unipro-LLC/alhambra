/*
 * Copyright (c) 1999, 2011, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2008, 2009, 2010 Red Hat, Inc.
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

#ifndef SHARE_VM_LLVM_LLVMHEADERS_HPP
#define SHARE_VM_LLVM_LLVMHEADERS_HPP

#ifdef assert
  #undef assert
#endif

#ifdef DEBUG
  #define LLVM_DEBUG
  #undef DEBUG
#endif

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#include <llvm/ExecutionEngine/ExecutionEngine.h>

// includes specific to 6.0 version
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/Type.h>
#include "llvm/IR/LegacyPassManager.h"
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/MCJIT.h>
#include "llvm/ExecutionEngine/RTDyldMemoryManager.h"
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <llvm-c/Core.h>

// common includes
#include <llvm/Support/Threading.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Host.h>
#include <llvm/CodeGen/Passes.h>

#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Scalar/GVN.h"

#include "llvm/Object/StackMapParser.h"

using StackMapParser = llvm::StackMapParser<llvm::support::endianness::native>;
using RecordAccessor = StackMapParser::RecordAccessor;
using LocationAccessor = StackMapParser::LocationAccessor;
using ConstantAccessor = StackMapParser::ConstantAccessor;
using LocationKind = StackMapParser::LocationKind;

#ifdef assert
  #undef assert
#endif

// from hotspot/src/share/vm/utilities/debug.hpp
#ifdef ASSERT
#ifndef USE_REPEATED_ASSERTS
#define assert(p, msg)                                                       \
do {                                                                         \
  if (!(p)) {                                                                \
    report_vm_error(__FILE__, __LINE__, "assert(" #p ") failed", msg);       \
    BREAKPOINT;                                                              \
  }                                                                          \
} while (0)
#else // #ifndef USE_REPEATED_ASSERTS
#define assert(p, msg)
do {                                                                         \
  for (int __i = 0; __i < AssertRepeat; __i++) {                             \
    if (!(p)) {                                                              \
      report_vm_error(__FILE__, __LINE__, "assert(" #p ") failed", msg);     \
      BREAKPOINT;                                                            \
    }                                                                        \
  }                                                                          \
} while (0)
#endif // #ifndef USE_REPEATED_ASSERTS
#else
  #define assert(p, msg)
#endif

#ifdef DEBUG
  #undef DEBUG
#endif
#ifdef LLVM_DEBUG
  #define DEBUG
  #undef LLVM_DEBUG
#endif

#define FIELD_WITH_GETTER(type, field, getter) \
private: \
  type field; \
public: \
  type getter() { return field; }\

#define FIELD_WITH_REF_GETTER(type, field, getter) \
private: \
  type field; \
public: \
  type& getter() { return field; }\


#endif // SHARE_VM_LLVM_LLVMHEADERS_HPP
