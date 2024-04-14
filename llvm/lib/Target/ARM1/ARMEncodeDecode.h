#ifndef ARM_ENCODE_DECODE
#define ARM_ENCODE_DECODE

#include "ARMRandezvousInstrumentor.h"
#include "llvm/Pass.h"

namespace llvm {
  struct ARMEncodeDecode : public ModulePass, ARMRandezvousInstrumentor {
    // Pass Identifier
    static char ID;

    // xor number
    static constexpr Register storeReg = ARM::R8;
    static constexpr Register XorReg = ARM::R9;
    static constexpr StringRef InitFuncName = "__xor_register_init";

    ARMEncodeDecode();
    virtual StringRef getPassName() const override;
    void getAnalysisUsage(AnalysisUsage & AU) const override;
    virtual bool runOnModule(Module & M) override;

  private:
    bool EncodeLR(MachineInstr & MI, MachineOperand & LR);
    bool insertNop(MachineInstr &MI);
    bool EncodeCallSite(MachineInstr & MI, MachineOperand & MO);
    bool DecodeLR(MachineInstr & MI, MachineOperand & PCLR);
  };

  ModulePass * createARMEncodeDecode(void);
}

#endif