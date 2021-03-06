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

#include "precompiled.hpp"
#include "llvmGlobals.hpp"
#include "interpreter/interpreter.hpp"
#include "llvmEntry.hpp"
#include "llvmMemoryManager.hpp"


void* LlvmMemoryManager::getPointerToNamedFunction(const std::string &Name, bool AbortOnFailure) {
  llvm::SectionMemoryManager::getPointerToNamedFunction(Name, AbortOnFailure);
}

uint8_t* LlvmMemoryManager::allocateCodeSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, llvm::StringRef SectionName) {
    return llvm::SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID, SectionName);
}

uint8_t* LlvmMemoryManager::allocateDataSection(uintptr_t Size, unsigned Alignment, unsigned SectionID, llvm::StringRef SectionName, bool IsReadOnly) {
  return llvm::SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID, SectionName, IsReadOnly);
}

bool LlvmMemoryManager::finalizeMemory(std::string *ErrMsg) {
    llvm::SectionMemoryManager::finalizeMemory(ErrMsg);
}
