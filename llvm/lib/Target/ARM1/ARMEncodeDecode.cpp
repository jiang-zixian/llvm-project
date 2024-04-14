//===- ARMRandezvousShadowStack.cpp - ARM Randezvous Shadow Stack ---------===//
//
// Copyright (c) 2021-2022, University of Rochester
//
// Part of the Randezvous Project, under the Apache License v2.0 with
// LLVM Exceptions.  See LICENSE.txt in the llvm directory for license
// information.
//
//===----------------------------------------------------------------------===//
//
// This file contains the implementation of a pass that instruments ARM machine
// code to save/load the return address to/from a randomized compact shadow
// stack.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "arm-randezvous-shadow-stack"

#include "ARMEncodeDecode.h"
#include "ARMRandezvousOptions.h"
#include "MCTargetDesc/ARMAddressingModes.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

STATISTIC(NumPrologues, "Number of prologues transformed to use shadow stack");
STATISTIC(NumEpilogues, "Number of epilogues transformed to use shadow stack");
STATISTIC(NumNullified, "Number of return addresses nullified");

char ARMEncodeDecode::ID = 0;

ARMEncodeDecode::ARMEncodeDecode() : ModulePass(ID) {}

StringRef ARMEncodeDecode::getPassName() const {
  return "ARM Encode and Decode Pass";
}

void ARMEncodeDecode::getAnalysisUsage(AnalysisUsage &AU) const {
  // We need this to access MachineFunctions
  AU.addRequired<MachineModuleInfoWrapperPass>();

  AU.setPreservesCFG();
  ModulePass::getAnalysisUsage(AU);
}

// 初始化R9

// 代码插桩，如下
//  mov r3 [r4]
//  // Decode the function pointer
//  xor r3 r9
//  // Jump or not jump to the other shadow
//  add r3 #offset (add r3 #0)
//  // Jump to the target function
//  blx r3

// push {r4-r8}
// // Encode the lr before push it to the stack
// xor lr r9
// push lr

// pop {r4-r8} lr
// // Decode the value of lr after fetch it from the stack
// xor lr r9

// pop {r7,lr}
// xor pc lr r9

//
// Method: EncodeLR()
//
// Description:
//   This method modifies a PUSH instruction to not save LR to the stack and
//   inserts new instructions that save LR to the shadow stack.
//
// Inputs:
//   MI     - A reference to a PUSH instruction that saves LR to the stack.
//   LR     - A reference to the LR operand of the PUSH.
//   Stride - A static stride to use.
//
// Return value:
//   true - The machine code was modified.
//

// push {r4-r8}
// // Encode the lr before push it to the stack
// xor lr r9
// push lr
bool ARMEncodeDecode::EncodeLR(MachineInstr &MI, MachineOperand &LR) {
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const DebugLoc &DL = MI.getDebugLoc();

  Register PredReg;
  ARMCC::CondCodes Pred = getInstrPredicate(MI, PredReg);

  // 1. replace the old PUSH with a new one that doesn't push LR to the
  // stack
  switch (MI.getOpcode()) {
  case ARM::t2STMDB_UPD:
    // STMDB_UPD should store at least two registers; if it happens to be two,
    // we replace it with a STR_PRE
    assert(MI.getNumExplicitOperands() >= 6 && "Buggy STMDB_UPD!");
    if (MI.getNumExplicitOperands() > 6) {
      MI.removeOperand(MI.getOperandNo(&LR));
    } else {
      unsigned Idx = MI.getOperandNo(&LR);
      Idx = Idx == 4 ? 5 : 4;
      insertInstBefore(MI, BuildMI(MF, DL, TII->get(ARM::t2STR_PRE), ARM::SP)
                               .add(MI.getOperand(Idx))
                               .addReg(ARM::SP)
                               .addImm(-4)
                               .add(predOps(Pred, PredReg))
                               .setMIFlags(MI.getFlags()));
      removeInst(MI);
    }
    break;

  case ARM::tPUSH:
    // PUSH should store at least one register; if it happens to be one, we
    // just remove it
    assert(MI.getNumExplicitOperands() >= 3 && "Buggy PUSH!");
    if (MI.getNumExplicitOperands() > 3) {
      MI.removeOperand(MI.getOperandNo(&LR));
    } else {
      removeInst(MI);
    }
    break;

  // ARM::t2STR_PRE
  default:
    // STR_PRE only stores one register, so we just remove it
    removeInst(MI);
    break;
  }

  // 2. Build the xor instruction
  // eor.w lr,lr,r9

  std::vector<MachineInstr *> NewInsts;
  NewInsts.push_back(BuildMI(MF, DL, TII->get(ARM::t2EORrr), ARM::LR)
                         .addReg(ARM::LR)
                         .addReg(XorReg)
                         .add(predOps(Pred, PredReg))
                         .add(condCodeOp()));

  // 3. insert a new PUSH with a new one that only push LR to the stack
  switch (MI.getOpcode()) {
  case ARM::tPUSH:
    NewInsts.push_back(BuildMI(MF, DL, TII->get(ARM::tPUSH))
                           .add(predOps(Pred, PredReg))
                           .addReg(ARM::LR));
    break;

  // ARM::t2STR_PRE
  default:
    // STR_PRE only stores one register, so we just remove it
    removeInst(MI);
    break;
  }

  MI.addOperand(
      MachineOperand::CreateReg(storeReg, /*isDef=*/true, /*isImp=*/false));

  // 4. Now insert these new instructions into the basic block
  insertInstsBefore(MI, NewInsts);

  ++NumPrologues;
  return true;
}

bool ARMEncodeDecode::insertNop(MachineInstr &MI) {
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const DebugLoc &DL = MI.getDebugLoc();

  Register PredReg;
  ARMCC::CondCodes Pred = getInstrPredicate(MI, PredReg);

  // 2. Build the xor instruction
  // eor.w lr,lr,r9

  std::vector<MachineInstr *> NewInsts;
  for(int i=0;i<4;i++){
      NewInsts.push_back(
    BuildMI(MF,DL,TII->get(ARM::tHINT)).addImm(0).addImm(ARMCC::AL).addReg(0));
  }

  // 4. Now insert these new instructions into the basic block
  insertInstsBefore(MI, NewInsts);

  ++NumPrologues;
  return true;
}

//
bool ARMEncodeDecode::EncodeCallSite(MachineInstr &MI, MachineOperand &MO) {
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const DebugLoc &DL = MI.getDebugLoc();

  Register PredReg;
  ARMCC::CondCodes Pred = getInstrPredicate(MI, PredReg);

  std::vector<MachineInstr *> NewInsts;
  unsigned Idx = MI.getOperandNo(&MO);

  NewInsts.push_back(BuildMI(MF, DL, TII->get(ARM::t2EORrr), MO.getReg())
                         .addReg(MO.getReg())
                         .addReg(XorReg)
                         .add(predOps(Pred, PredReg))
                         .add(condCodeOp()));

  // insert the decode instructions before blx
  insertInstsBefore(MI, NewInsts);

  return true;
}

//
// Method: DecodeLR()
//
// Description:
//   This method modifies a POP instruction to not write to PC/LR and inserts
//   new instructions that load the return address from the shadow stack into
//   PC/LR.
//
// Inputs:
//   MI     - A reference to a POP instruction that writes to LR or PC.
//   PCLR   - A reference to the PC or LR operand of the POP.
//   Stride - A static stride to use.
//
// Return value:
//   true - The machine code was modified.
//

bool ARMEncodeDecode::DecodeLR(MachineInstr &MI, MachineOperand &PCLR) {
  MachineFunction &MF = *MI.getMF();
  const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
  const DebugLoc &DL = MI.getDebugLoc();

  Register PredReg;
  ARMCC::CondCodes Pred = getInstrPredicate(MI, PredReg);

  std::vector<MachineInstr *> NewInsts;

  MachineInstrBuilder MIB =
      BuildMI(MF, DL, TII->get(ARM::t2LDMIA_UPD), ARM::SP).addReg(ARM::SP);
  for (MachineOperand &MO : MI.explicit_operands()) {
    if (MO.isReg() && MO.getReg() == ARM::PC) {
      MIB.addReg(ARM::LR, RegState::Define);
    } else {
      MIB.add(MO);
    }
  }
  NewInsts.push_back(MIB);

  NewInsts.push_back(BuildMI(MF, DL, TII->get(ARM::t2EORrr), ARM::LR)
                         .addReg(ARM::LR)
                         .addReg(XorReg)
                         .add(predOps(Pred, PredReg))
                         .add(condCodeOp()));

  NewInsts.push_back(
      BuildMI(MF, DL, TII->get(ARM::tBX_RET)).add(predOps(Pred, PredReg)));

  // Now insert these new instructions after pop.w
  insertInstsAfter(MI, NewInsts);

  removeInst(MI);

  return true;
}

//
// Method: runOnModule()
//
// Description:
//   This method is called when the PassManager wants this pass to transform
//   the specified Module.  This method
//
//   * creates a global variable as the shadow stack,
//
//   * creates a function that initializes the reserved registers for the
//     shadow stack, and
//
//   * transforms the Module to utilize the shadow stack for saving/restoring
//     return addresses and/or to nullify a saved return address on returns.
//
// Input:
//   M - A reference to the Module to transform.
//
// Output:
//   M - The transformed Module.
//
// Return value:
//   true  - The Module was transformed.
//   false - The Module was not transformed.
//

bool ARMEncodeDecode::runOnModule(Module &M) {
  if (!EnableEncodeDecode) {
    return false;
  }

  // random number stored in r9
  MachineModuleInfo &MMI = getAnalysis<MachineModuleInfoWrapperPass>().getMMI();


  // Instrument pushes and pops in each function
  bool changed = false;

  for (Function &F : M) {
    if (F.getName() != "Reset_Handler" ) 
        {
      MachineFunction *MF = MMI.getMachineFunction(F);
      if (MF == nullptr) {
        continue;
      }

      // Find out all pushes that write LR to the stack and all pops that read a
      // return address from the stack to LR or PC
      std::vector<std::pair<MachineInstr *, MachineOperand *>> Pushes;
      std::vector<std::pair<MachineInstr *, MachineOperand *>> Pops;
      std::vector<std::pair<MachineInstr *, MachineOperand *>> Blxs;
      MachineOperand *callRegister = nullptr; // 保存最后一个寄存器操作数的指针
      Register callRegister1 = ARM::R9; // 对标以下的r0
      Register callRegister2 = ARM::R9; // 对标以下的r0
      unsigned SPImm;

      for (MachineBasicBlock &MBB : *MF) {
        for (MachineBasicBlock::iterator I = MBB.begin(), E = MBB.end();
             I != E;) {
          MachineInstr &MI = *I;
          MachineBasicBlock::iterator I_ = I; // 记录当前位置
          int state = 1; // 表示当前要找哪一条指令
          if (MI.getOpcode() == ARM::tBLXr ||
              MI.getOpcode() == ARM::tBLXr_noip) {
            for (MachineOperand &MO : MI.explicit_operands()) {
              if (MO.isReg()) {
                callRegister = &MO; // 更新最后一个寄存器操作数的指针
              }
            }
            // Blxs.push_back(std::make_pair(&MI, callRegister));
            while (1) {
              if (I == MBB.begin()) {
                break;
              } else {
                I--;                    // 往上找
                MachineInstr &MI1 = *I; // 取当前的MI1
                if (state == 1) {       // 先找ldr  r2, [sp, #16]
                  int x = 0;
                  switch (MI1.getOpcode()) {
                  case ARM::LDRrs:
                  case ARM::PICLDR:
                  case ARM::LDRBrs:
                  case ARM::t2LDRDi8:
                  case ARM::LDRi12:
                  case ARM::t2LDRi12:
                  case ARM::tLDRi:
                  case ARM::tLDRspi:
                    for (MachineOperand &MO : MI1.explicit_operands()) {
                      if (MO.isReg() && callRegister->getReg() == MO.getReg()) {
                        unsigned Idx = MI1.getOperandNo(&MO);
                        callRegister1 = MI1.getOperand(Idx + 1).getReg();
                        SPImm = MI1.getOperand(Idx + 2).getImm();
                        state = 2; // 接下来可以找str  r0, [sp, #16] 2
                      }
                    }
                    break;
                  case ARM::tLDRpci:
                    x = 1;
                    break;
                  default:
                    break;
                  }
                  if (x == 1) {
                    break;
                  }
                } else if (state == 2) {
                  switch (MI1.getOpcode()) {
                  case ARM::STRrs:
                  case ARM::STRBrs:
                  case ARM::t2STRDi8:
                  case ARM::STRi12:
                  case ARM::t2STRi12:
                  case ARM::tSTRi:
                  case ARM::tSTRspi:
                    for (MachineOperand &MO : MI1.explicit_operands()) {
                      if (MO.isReg() && callRegister1 == MO.getReg()) {
                        unsigned Idx = MI1.getOperandNo(&MO); //
                        if (SPImm == MI1.getOperand(Idx + 1).getImm()) {
                          callRegister1 = MI1.getOperand(Idx - 1).getReg();
                          state = 3; // 接下来可以找ldr  r0, [r0, #0]
                        }
                      }
                    }
                    break;
                  default:
                    break;
                  }
                } else if (state ==
                           3) { // 找ldr  r0, [r0, #0],一步步迭代到add r0,pc
                  int f = 0;
                  switch (MI1.getOpcode()) {
                  case ARM::tPICADD:
                  case ARM::PICADD:
                    for (MachineOperand &MO : MI1.explicit_operands()) {
                      if (MO.isReg() && callRegister1 == MO.getReg()) {
                        unsigned Idx = MI1.getOperandNo(&MO);
                        Blxs.push_back(std::make_pair(&MI, callRegister));
                        f = 1;
                        break;
                      }
                    }
                    break;
                  case ARM::LDRrs:
                  case ARM::PICLDR:
                  case ARM::LDRBrs:
                  case ARM::t2LDRDi8:
                  case ARM::LDRi12:
                  case ARM::t2LDRi12:
                  case ARM::tLDRi:
                  case ARM::tLDRspi:
                  case ARM::tLDRpci:
                    if (MI1.getOperand(0).isReg() &&
                        callRegister1 == MI1.getOperand(0).getReg() &&
                        callRegister1 != MI1.getOperand(1).getReg()) {
                      state = 1; // 转到状态1
                      callRegister1 = MI1.getOperand(1).getReg();
                    }
                    break;
                  default:
                    break;
                  }
                  if (f == 1) {
                    break;
                  }
                }
              }
            }
            I = I_;
          }
          I++;
        }
      }

      for (MachineBasicBlock &MBB : *MF) {
        for (MachineInstr &MI : MBB) {
          switch (MI.getOpcode()) {
          // Frame-setup instructions in function prologue
          case ARM::t2STR_PRE:
          case ARM::t2STMDB_UPD:
            // STR_PRE and STMDB_UPD are considered as PUSH if they write to SP!
            if (MI.getOperand(0).getReg() != ARM::SP) {
              break;
            }
            LLVM_FALLTHROUGH;
          case ARM::tPUSH:
            if (MI.getFlag(MachineInstr::FrameSetup)) {
              for (MachineOperand &MO : MI.explicit_operands()) {
                if (MO.isReg() && MO.getReg() == ARM::LR) {
                  Pushes.push_back(std::make_pair(&MI, &MO));
                  break;
                }
              }
            }
            break;
          // Frame-destroy instructions in function epilogue
          case ARM::t2LDR_POST:
          case ARM::t2LDMIA_UPD:
          case ARM::t2LDMIA_RET:
            // LDR_POST and LDMIA_(UPD|RET) are considered as POP if they read
            // from SP!
            if (MI.getOperand(1).getReg() != ARM::SP) {
              break;
            }
            LLVM_FALLTHROUGH;
          case ARM::tPOP:
          case ARM::tPOP_RET:
            if (MI.getFlag(MachineInstr::FrameDestroy)) {
              // Handle 2 cases:
              // (1) Pop writing to LR
              // (2) Pop writing to PC
              for (MachineOperand &MO : MI.explicit_operands()) {
                if (MO.isReg()) {
                  if (MO.getReg() == ARM::LR || MO.getReg() == ARM::PC) {
                    Pops.push_back(std::make_pair(&MI, &MO));
                    break;
                  }
                }
              }
            }
            break;
          default:
            break;
          }
        }
      }


      for (auto &MIMO : Pushes) {
        changed |= EncodeLR(*MIMO.first, *MIMO.second);
      }

      for (auto &MIMO : Blxs) {
        changed |= EncodeCallSite(*MIMO.first, *MIMO.second);
      }

      for (auto &MIMO : Pops) {
        changed |= DecodeLR(*MIMO.first, *MIMO.second);
      }
    }

  }

  return changed;
}

ModulePass *llvm::createARMEncodeDecode(void) { return new ARMEncodeDecode(); }