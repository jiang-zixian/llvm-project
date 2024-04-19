//===- ARMRandezvousOptions.cpp - ARM Randezvous Command Line Options -----===//
//
// Copyright (c) 2021-2022, University of Rochester
//
// Part of the Randezvous Project, under the Apache License v2.0 with
// LLVM Exceptions.  See LICENSE.txt in the llvm directory for license
// information.
//
//===----------------------------------------------------------------------===//
//
// This file defines the command line options for ARM Randezvous passes.
//
//===----------------------------------------------------------------------===//

#include "ARMRandezvousOptions.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

//===----------------------------------------------------------------------===//
// Randezvous pass enablers
//===----------------------------------------------------------------------===//

//jzx
bool EnableEncodeDecode;
static cl::opt<bool, true>
EncodeDecode("arm-encode-decode",
            cl::Hidden,
            cl::desc("Enable ARM Encode and Decode"),
            cl::location(EnableEncodeDecode),
            cl::init(true));

bool EnableTrampoline;//jzx
static cl::opt<bool, true>
Trampoline("arm-trampoline",
            cl::Hidden,
            cl::desc("Enable ARM trampoline"),
            cl::location(EnableTrampoline),
            cl::init(true));


//===----------------------------------------------------------------------===//
// Randezvous pass seeds
//===----------------------------------------------------------------------===//
//jzx
uint64_t EncodeDecodeSeed;
static cl::opt<uint64_t, true>
XorSeed("encode-decode-seed",
                cl::Hidden,
                cl::desc("Seed for the RNG used in ARM Encode and Decode"),
                cl::location(EncodeDecodeSeed),
                cl::init(0));

//===----------------------------------------------------------------------===//
// Size options used by Randezvous passes
//===----------------------------------------------------------------------===//


//===----------------------------------------------------------------------===//
// Miscellaneous options used by Randezvous passes
//===----------------------------------------------------------------------===//
//jzx
unsigned EncodeDecodeNumberLength;
static cl::opt<unsigned, true>
XorNumLength("arm-xor-number-length",
                        cl::Hidden,
                        cl::desc("Number of bits for ARM Xor Number"),
                        cl::location(EncodeDecodeNumberLength),
                        cl::init(8));
//jzx
uintptr_t EncodeDecodeRNGAddress;
static cl::opt<uintptr_t, true>
XorRNGAddress("arm-encode-and-decode-rng-addr",
           cl::Hidden,
           cl::desc("Address of a dynamic RNG"),
           cl::location(EncodeDecodeRNGAddress),
           cl::init(0));
