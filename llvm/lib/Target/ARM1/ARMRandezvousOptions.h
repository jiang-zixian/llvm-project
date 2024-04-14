//===- ARMRandezvousOptions.h - ARM Randezvous Command Line Options -------===//
//
// Copyright (c) 2021-2022, University of Rochester
//
// Part of the Randezvous Project, under the Apache License v2.0 with
// LLVM Exceptions.  See LICENSE.txt in the llvm directory for license
// information.
//
//===----------------------------------------------------------------------===//
//
// This file declares the command line options for ARM Randezvous passes.
//
//===----------------------------------------------------------------------===//

#ifndef ARM_RANDEZVOUS_OPTIONS
#define ARM_RANDEZVOUS_OPTIONS

#include <cstddef>
#include <cstdint>

//===----------------------------------------------------------------------===//
// Randezvous pass enablers
//===----------------------------------------------------------------------===//

extern bool EnableEncodeDecode;//jzx
extern bool EnableTrampoline;//jzx

//===----------------------------------------------------------------------===//
// Randezvous pass seeds
//===----------------------------------------------------------------------===//

extern uint64_t EncodeDecodeSeed;//jzx

//===----------------------------------------------------------------------===//
// Size options used by Randezvous passes
//===----------------------------------------------------------------------===//


//===----------------------------------------------------------------------===//
// Miscellaneous options used by Randezvous passes
//===----------------------------------------------------------------------===//
extern unsigned EncodeDecodeNumberLength;//jzx
extern uintptr_t EncodeDecodeRNGAddress;//jzx

#endif