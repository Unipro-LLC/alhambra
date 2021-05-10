/*
 * Copyright (c) 1999, 2012, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2009, 2010 Red Hat, Inc.
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

#ifndef SHARE_VM_LLVM_LLVMCONTEXT_HPP
#define SHARE_VM_LLVM_LLVMCONTEXT_HPP

#include "llvmGlobals.hpp"
#include "llvmCodeGen.hpp"


// The LLVMContext class allows multiple instances of LLVM to operate
// independently of each other in a multithreaded context.  We extend
// this here to store things in Llvm that are LLVMContext-specific.


class LlvmContext : public llvm::LLVMContext {
 public:
  LlvmContext(const char* name);

 private:
  llvm::Module* _module;

 public:
  llvm::Module* module() const {
    return _module;
  }
  // Module accessors
 public:
  void add_function(llvm::Function* function) const {
    module()->getFunctionList().push_back(function);
  }
  llvm::FunctionCallee get_external(const char*               name,
                               llvm::FunctionType* sig) {
    return module()->getOrInsertFunction(name, sig);
  }
};

#endif // SHARE_VM_LLVM_LLVMCONTEXT_HPP
