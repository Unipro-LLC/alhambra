/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2009 Red Hat, Inc.
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

#ifndef SHARE_VM_LLVM_LLVMMEMORYMANAGER_HPP
#define SHARE_VM_LLVM_LLVMMEMORYMANAGER_HPP

#include "llvmGlobals.hpp"
#include "llvmEntry.hpp"

// llvmMemoryManager wraps the LLVM JIT Memory Manager.  We could use
// this to run our own memory allocation policies, but for now all we
// use it for is figuring out where the resulting native code ended up.

class LlvmMemoryManager : public llvm::SectionMemoryManager {
 public:
  LlvmMemoryManager()   : llvm::SectionMemoryManager() {}

 private:
  std::map<const llvm::Function*, LlvmEntry*> _entry_map;

 public:
  void set_entry_for_function(const llvm::Function* function,
                              LlvmEntry*           entry) {
    _entry_map[function] = entry;
  }
  LlvmEntry* get_entry_for_function(const llvm::Function* function) {
    return _entry_map[function];
  }

 public:
  void *getPointerToNamedFunction(const std::string &Name, bool AbortOnFailure = true);

  uint8_t* allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, llvm::StringRef SectionName);
  uint8_t* allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, llvm::StringRef SectionName, bool IsReadOnly);
  bool finalizeMemory(std::string *ErrMsg = 0);
  void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr, size_t Size) override {}
  void deregisterEHFrames() override {}
};

#endif // SHARE_VM_LLVM_LLVMMEMORYMANAGER_HPP
