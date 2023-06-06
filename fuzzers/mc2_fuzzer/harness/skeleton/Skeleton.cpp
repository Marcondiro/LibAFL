#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils.h"
#include <iostream>
#include <set>
#include <fstream>

#define BRANCHES_FILE "branches.txt"

using namespace llvm;

namespace {
struct CaseExpr {
  ConstantInt *Val;
  BasicBlock  *BB;
  CaseExpr(ConstantInt *val = nullptr, BasicBlock *bb = nullptr)
      : Val(val), BB(bb) {
  }
};
using CaseVector = std::vector<CaseExpr>;

struct SkeletonPass : public ModulePass {
  static char ID;
  SkeletonPass() : ModulePass(ID) {
  }

  virtual void getAnalysisUsage(AnalysisUsage &AU) const override;
  virtual bool runOnModule(Module &F) override;

 private:
  bool        splitSwitches(Module &M);
  BasicBlock *switchConvert(CaseVector Cases, std::vector<bool> bytesChecked,
                            BasicBlock *OrigBlock, BasicBlock *NewDefault,
                            Value *Val, unsigned level);
};

}  // namespace
void SkeletonPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.setPreservesAll();
}

bool SkeletonPass::runOnModule(Module &M) {
  std::ofstream BranchesFile;

  // Open the file to write Branches info
  BranchesFile.open(BRANCHES_FILE);

  if (!BranchesFile.is_open()) { return 1; }

  // Get the LLVM context for the module
  LLVMContext &C = M.getContext();
  // Get the data layout for the module
  const DataLayout *DL = &M.getDataLayout();

  // Define several integer types of different bit widths using the LLVM context
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  Type *FloatTy = Type::getFloatTy(C);
  Type *DoubleTy = Type::getDoubleTy(C);

  // Get or insert several functions into the module using their names and
  // argument types.
  FunctionCallee LogFunc[4];
  LogFunc[0] = M.getOrInsertFunction("log_func8", Int1Ty, Int32Ty, Int1Ty,
                                     Int8Ty, Int8Ty, Int8Ty, Int8Ty);
  LogFunc[1] = M.getOrInsertFunction("log_func16", Int1Ty, Int32Ty, Int1Ty,
                                     Int16Ty, Int16Ty, Int8Ty, Int8Ty);
  LogFunc[2] = M.getOrInsertFunction("log_func32", Int1Ty, Int32Ty, Int1Ty,
                                     Int32Ty, Int32Ty, Int8Ty, Int8Ty);
  LogFunc[3] = M.getOrInsertFunction("log_func64", Int1Ty, Int32Ty, Int1Ty,
                                     Int64Ty, Int64Ty, Int8Ty, Int8Ty);

  // Support for FLoating point comparison
  FunctionCallee LogFloatFunc[2];
  LogFloatFunc[0] = M.getOrInsertFunction("log_func_f32", Int1Ty, Int32Ty,
                                          Int1Ty, FloatTy, FloatTy, Int8Ty);
  LogFloatFunc[1] = M.getOrInsertFunction("log_func_f64", Int1Ty, Int32Ty,
                                          Int1Ty, DoubleTy, DoubleTy, Int8Ty);

  // --------------------------------------------------------
  // IS IT DEAD CODE (?)
  FunctionCallee FakeFunc = M.getOrInsertFunction("fake_func", Int1Ty, Int32Ty);
  FunctionCallee SwitchFunc =
      M.getOrInsertFunction("switch_func", Int64Ty, Int32Ty, Int64Ty);
  // END DEAD CODE
  // --------------------------------------------------------

  splitSwitches(M);

  // Initialize a counter to keep track of the number of branches in the
  // module
  int br_cnt = 0;
  // Iterate over all the functions in the module
  for (auto &F : M) {
    // Iterate over all the basic blocks in the current function
    for (auto &BB : F) {
      // Get the terminator instruction of the current basic block
      Instruction *t_inst = BB.getTerminator();
      // Get the LLVM context for the terminator instruction
      LLVMContext &C = t_inst->getContext();

      // Create a metadata node to represent the branch ID
      // and attach it to the terminator instruction
      MDNode *N = MDNode::get(C, MDString::get(C, std::to_string(br_cnt)));
      t_inst->setMetadata("BB_ID", N);

      // Create a metadata node to represent the location of the terminator
      // instruction and attach it to the terminator instruction, if the
      // location is available
      std::string location = std::string("UNKNOWN");
      if (DILocation *Loc = t_inst->getDebugLoc().get()) {
        location = std::string(Loc->getFilename().data()) + std::string(":") +
                   std::to_string(Loc->getLine());
        MDNode *M = MDNode::get(C, MDString::get(C, location));
        t_inst->setMetadata("Loc", M);
      }

      // Insert a call to the "fake_func" function before the terminator
      // instruction with the current branch ID as an argument
      // TODO why (?) - try to remove this fake function
      IRBuilder<> IRB(t_inst);
      IRB.CreateCall(FakeFunc, {ConstantInt::get(Int32Ty, br_cnt)});

      // Write on file some information about the current function and branch
      BranchesFile << "@@@ " << F.getName().str() << ", branch id: " << br_cnt
                   << "| loc " << location << "\n";

      // Ensure that the branch counter does not overflow
      assert(br_cnt < 2000000000);
      br_cnt += 1;
    }
  }
  int cur_br_id = 0;
  int br_id_1 = 0;
  int br_id_2 = 0;

  // Handling conditional jumps
  for (auto &F : M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        // Retrieve the metadata previously attached about the id of the branch
        // (if any)
        if (MDNode *N = BB.getTerminator()->getMetadata("BB_ID")) {
          cur_br_id =
              std::stoi(cast<MDString>(N->getOperand(0))->getString().str());
        } else {
          BranchesFile << "ERROR NO BRANCH ID!\n";
          assert(0);
        }

        // Check if the br_instr is a Branch Instruction
        if (BranchInst *br_inst = dyn_cast<BranchInst>(&I)) {
          // If the br_instr is a conditional jump, extract the two
          // successor basic blocks and their corresponding brandch IDs
          // from the metadata previously attached
          IRBuilder<> IRB(br_inst);
          if (br_inst->isConditional()) {
            std::string true_cond;
            std::string false_cond;
            br_id_1 = std::stoi(cast<MDString>(br_inst->getSuccessor(0)
                                                   ->getTerminator()
                                                   ->getMetadata("BB_ID")
                                                   ->getOperand(0))
                                    ->getString()
                                    .str());
            br_id_2 = std::stoi(cast<MDString>(br_inst->getSuccessor(1)
                                                   ->getTerminator()
                                                   ->getMetadata("BB_ID")
                                                   ->getOperand(0))
                                    ->getString()
                                    .str());
            // Check if it is an Integer Comparison Instruction,
            // then it extracts the comparison instruction that
            // determines the jump condition
            if (ICmpInst *cmp_inst =
                    dyn_cast<ICmpInst>(br_inst->getCondition())) {
              // it obtains the predicate of the instruction
              ICmpInst::Predicate pred = cmp_inst->getPredicate();

              int is_signed = -1;
              assert(pred > 0 && pred <= 255);
              uint8_t cond_type = pred;

              // based on the predicate of the comparison instruction
              // it maps it to a corresponding true/false codition type
              switch (pred) {
                case ICmpInst::ICMP_UGT:
                  true_cond = "ICMP_UGT";
                  false_cond = "ICMP_ULE";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_SGT:  // 001
                  true_cond = "ICMP_SGT";
                  false_cond = "ICMP_SLE";
                  is_signed = 1;
                  break;
                case ICmpInst::ICMP_EQ:  // 010
                  true_cond = "ICMP_EQ";
                  false_cond = "ICMP_NE";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_UGE:  // 011
                  true_cond = "ICMP_UGE";
                  false_cond = "ICMP_ULT";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_SGE:  // 011
                  true_cond = "ICMP_SGE";
                  false_cond = "ICMP_SLT";
                  is_signed = 1;
                  break;
                case ICmpInst::ICMP_ULT:  // 100
                  true_cond = "ICMP_ULT";
                  false_cond = "ICMP_UGE";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_SLT:  // 100
                  true_cond = "ICMP_SLT";
                  false_cond = "ICMP_SGE";
                  is_signed = 1;
                  break;
                case ICmpInst::ICMP_NE:  // 101
                  true_cond = "ICMP_NE";
                  false_cond = "ICMP_EQ";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_ULE:  // 110
                  true_cond = "ICMP_ULE";
                  false_cond = "ICMP_UGT";
                  is_signed = 0;
                  break;
                case ICmpInst::ICMP_SLE:  // 110
                  true_cond = "ICMP_SLE";
                  false_cond = "ICMP_SGT";
                  is_signed = 1;
                  break;
                default:
                  true_cond = "NO_TYPE";
                  false_cond = "NO_TYPE";
                  BranchesFile << "ERROR NO ICMPTYPE!\n";
                  assert(0);
                  break;
              }

              // Write to file the pair (cur_br_id, br_id_x) and the condition
              // to follow the left or right successor basic blocks
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_1
                           << "), cond type " << true_cond << ", true\n";
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_2
                           << "), cond type " << false_cond << ", false\n";

              // get the operand of the cmp_inst
              Value *A0 = cmp_inst->getOperand(0);
              Value *A1 = cmp_inst->getOperand(1);

              // If the operands of the comparison instruction are not integers,
              // it checks if they are pointers. If they are pointers,
              // it generates a callback to LogFunc[3] with the current branch
              // id, the condition, the two operands, the is_signed flag, and
              // the comparison type. Otherwise, it prints a warning message,
              // and the comparison instruction is considered an "unknown
              // instruction."
              if (!A0->getType()->isIntegerTy()) {
                if (A0->getType()->isPointerTy()) {
                  BranchesFile
                      << cur_br_id << ", " << br_id_1 << ", " << br_id_2
                      << " pointer icmp: not an integer-valued icmp, but "
                         "still an icmp\n";

                  // use LogFunc[3] because it takes 64 bytes argument
                  auto CallbackFunc = LogFunc[3];
                  auto Ty = Type::getIntNTy(C, 64);
                  assert(is_signed == 0);
                  Value *ret_val = IRB.CreateCall(
                      CallbackFunc, {ConstantInt::get(Int32Ty, cur_br_id),
                                     br_inst->getCondition(), A0, A1,
                                     ConstantInt::get(Int8Ty, is_signed),
                                     ConstantInt::get(Int8Ty, cond_type)});
                  // Set the condition based on the ret_val of the CallbackFunc
                  br_inst->setCondition(ret_val);
                } else {
                  std::string              type_str;
                  llvm::raw_string_ostream rso(type_str);
                  A0->print(rso);
                  BranchesFile << rso.str() << " buggy instruction \n";
                  BranchesFile
                      << "UNKNOWNERROR "
                      << " not an integer-valued icmp, but still an icmp "
                         "and not a pointer\n";
                  BranchesFile << "ERROR: not yet supported\n";
                  assert(0);
                }
              } else {
                uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
                int      CallbackIdx = TypeSize == 8    ? 0
                                       : TypeSize == 16 ? 1
                                       : TypeSize == 32 ? 2
                                       : TypeSize == 64 ? 3
                                                        : 4;
                if (CallbackIdx == 4) {
                  BranchesFile << "UNKNOWNERROR";
                  BranchesFile << TypeSize << " is bit width\n";
                  BranchesFile << "ERROR: not yet supported\n";
                  assert(0);
                } else {
                  auto CallbackFunc = LogFunc[CallbackIdx];
                  assert(CallbackIdx >= 0);
                  assert(CallbackIdx <= 3);
                  auto Ty = Type::getIntNTy(C, TypeSize);
                  assert(is_signed >= 0);
                  assert(is_signed <= 1);
                  Value *ret_val = IRB.CreateCall(
                      CallbackFunc,
                      {ConstantInt::get(Int32Ty, cur_br_id),
                       br_inst->getCondition(), IRB.CreateIntCast(A0, Ty, true),
                       IRB.CreateIntCast(A1, Ty, true),
                       ConstantInt::get(Int8Ty, is_signed),
                       ConstantInt::get(Int8Ty, cond_type)});
                  // set the condition based on the ret_value of the
                  // CallbackFunc
                  br_inst->setCondition(ret_val);
                }
              }
            } else if (FCmpInst *cmp_inst =
                           dyn_cast<FCmpInst>(br_inst->getCondition())) {
              // it obtains the predicate of the instruction
              FCmpInst::Predicate pred = cmp_inst->getPredicate();

              int is_signed = 1;
              assert(pred > 0 && pred <= 255);
              uint8_t cond_type = pred;

              switch (pred) {
                case FCmpInst::FCMP_FALSE:
                  true_cond = "FCMP_FALSE";
                  false_cond = "FCMP_FALSE";
                  break;
                case FCmpInst::FCMP_OEQ:
                  true_cond = "FCMP_OEQ";
                  false_cond = "FCMP_ONE";
                  break;
                case FCmpInst::FCMP_OGT:
                  true_cond = "FCMP_OGT";
                  false_cond = "FCMP_OGE || FCMP_OLT";
                  break;
                case FCmpInst::FCMP_OGE:
                  true_cond = "FCMP_OGE";
                  false_cond = "FCMP_OLT";
                  break;
                case FCmpInst::FCMP_OLT:
                  true_cond = "FCMP_OLT";
                  false_cond = "FCMP_OGE";
                  break;
                case FCmpInst::FCMP_OLE:
                  true_cond = "FCMP_OLE";
                  false_cond = "FCMP_OGT";
                  break;
                case FCmpInst::FCMP_ONE:
                  true_cond = "FCMP_ONE";
                  false_cond = "FCMP_OEQ";
                  break;
                case FCmpInst::FCMP_ORD:
                  true_cond = "FCMP_ORD";
                  false_cond = "FCMP_UNO";
                  break;
                case FCmpInst::FCMP_UNO:
                  true_cond = "FCMP_UNO";
                  false_cond = "FCMP_ORD";
                  break;
                case FCmpInst::FCMP_UEQ:
                  true_cond = "FCMP_UEQ";
                  false_cond = "FCMP_UNE";
                  break;
                case FCmpInst::FCMP_UGT:
                  true_cond = "FCMP_UGT";
                  false_cond = "FCMP_ULE";
                  break;
                case FCmpInst::FCMP_UGE:
                  true_cond = "FCMP_UGE";
                  false_cond = "FCMP_ULT";
                  break;
                case FCmpInst::FCMP_ULT:
                  true_cond = "FCMP_ULT";
                  false_cond = "FCMP_UGE";
                  break;
                case FCmpInst::FCMP_ULE:
                  true_cond = "FCMP_ULE";
                  false_cond = "FCMP_UGT";
                  break;
                case FCmpInst::FCMP_UNE:
                  true_cond = "FCMP_UNE";
                  false_cond = "FCMP_UEQ";
                  break;
                case FCmpInst::FCMP_TRUE:
                  true_cond = "FCMP_TRUE";
                  false_cond = "FCMP_FALSE";
                  break;
              }

              // Write to file the pair (cur_br_id, br_id_x) and the condition
              // to follow the left or right successor basic blocks
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_1
                           << "), cond type " << true_cond << ", true\n";
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_2
                           << "), cond type " << false_cond << ", false\n";

              // get the operand of the cmp_inst
              Value *A0 = cmp_inst->getOperand(0);
              Value *A1 = cmp_inst->getOperand(1);

              if (Type::getFloatTy(C) == A0->getType()) {
                Value *ret_val = IRB.CreateCall(
                    LogFloatFunc[0], {ConstantInt::get(Int32Ty, cur_br_id),
                                      br_inst->getCondition(),
                                      IRB.CreateFPCast(A0, A0->getType()),
                                      IRB.CreateFPCast(A1, A1->getType()),
                                      ConstantInt::get(Int8Ty, is_signed),
                                      ConstantInt::get(Int8Ty, cond_type)});

                br_inst->setCondition(ret_val);

              } else if (Type::getDoubleTy(C) == A0->getType()) {
                Value *ret_val = IRB.CreateCall(
                    LogFloatFunc[1], {ConstantInt::get(Int32Ty, cur_br_id),
                                      br_inst->getCondition(),
                                      IRB.CreateFPCast(A0, A0->getType()),
                                      IRB.CreateFPCast(A1, A1->getType()),
                                      ConstantInt::get(Int8Ty, is_signed),
                                      ConstantInt::get(Int8Ty, cond_type)});

                br_inst->setCondition(ret_val);
              }

            } else {
              BranchesFile
                  << "ERROR" << br_inst->getCondition()->getName().str()
                  << " is not a ICMP nor FCMP but a conditional branch, "
                     "likely logical operators\n";
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_1
                           << "), cond type non-ICMP \n";
              BranchesFile << "@@@ edge id (" << cur_br_id << "," << br_id_2
                           << "), cond type non-ICMP \n";
              BranchesFile << "ERROR: not yet supported\n";
              assert(0);
            }
          }
        } else if (auto *sw_inst = dyn_cast<SwitchInst>(&I)) {
          BranchesFile << "ERROR: not yet supported\n";
          assert(0);
        }
      }
    }
  }
  // --------------------------------------------------------
  // IS IT DEAD CODE (?)
  std::vector<Instruction *> deleteCalls;
  for (auto &F : M) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (CallInst *call_inst = dyn_cast<CallInst>(&I)) {
          Function *fun = call_inst->getCalledFunction();
          if (fun && fun->getName().str() == "fake_func") {
            int count = 0;
            for (auto U : I.users()) {
              count++;
            }
            assert(count == 0);
            deleteCalls.emplace_back(&I);
          }
        }
      }
    }
  }

  for (auto I : deleteCalls) {
    I->eraseFromParent();
  }
  // END DEAD CODE
  // --------------------------------------------------------
  return true;
}

/* switchConvert - Transform simple list of Cases into list of CaseRange's */
BasicBlock *SkeletonPass::switchConvert(CaseVector        Cases,
                                        std::vector<bool> bytesChecked,
                                        BasicBlock       *OrigBlock,
                                        BasicBlock *NewDefault, Value *Val,
                                        unsigned level) {
  unsigned     ValTypeBitWidth = Cases[0].Val->getBitWidth();
  IntegerType *ValType =
      IntegerType::get(OrigBlock->getContext(), ValTypeBitWidth);
  IntegerType         *ByteType = IntegerType::get(OrigBlock->getContext(), 8);
  unsigned             BytesInValue = bytesChecked.size();
  std::vector<uint8_t> setSizes;
  std::vector<std::set<uint8_t> > byteSets(BytesInValue, std::set<uint8_t>());

  /* for each of the possible cases we iterate over all bytes of the values
   * build a set of possible values at each byte position in byteSets */
  for (CaseExpr &Case : Cases) {
    for (unsigned i = 0; i < BytesInValue; i++) {
      uint8_t byte = (Case.Val->getZExtValue() >> (i * 8)) & 0xFF;
      byteSets[i].insert(byte);
    }
  }

  /* find the index of the first byte position that was not yet checked. then
   * save the number of possible values at that byte position */
  unsigned smallestIndex = 0;
  unsigned smallestSize = 257;
  for (unsigned i = 0; i < byteSets.size(); i++) {
    if (bytesChecked[i]) continue;
    if (byteSets[i].size() < smallestSize) {
      smallestIndex = i;
      smallestSize = byteSets[i].size();
    }
  }

  assert(bytesChecked[smallestIndex] == false);

  /* there are only smallestSize different bytes at index smallestIndex */

  Instruction *Shift, *Trunc;
  Function    *F = OrigBlock->getParent();
  BasicBlock  *NewNode = BasicBlock::Create(Val->getContext(), "NodeBlock", F);
  Shift = BinaryOperator::Create(Instruction::LShr, Val,
                                 ConstantInt::get(ValType, smallestIndex * 8));
#if LLVM_VERSION_MAJOR >= 16
  Shift->insertInto(NewNode, NewNode->end());
#else
  NewNode->getInstList().push_back(Shift);
#endif

  if (ValTypeBitWidth > 8) {
    Trunc = new TruncInst(Shift, ByteType);
#if LLVM_VERSION_MAJOR >= 16
    Trunc->insertInto(NewNode, NewNode->end());
#else
    NewNode->getInstList().push_back(Trunc);
#endif
  } else {
    /* not necessary to trunc */
    Trunc = Shift;
  }

  /* this is a trivial case, we can directly check for the byte,
   * if the byte is not found go to default. if the byte was found
   * mark the byte as checked. if this was the last byte to check
   * we can finally execute the block belonging to this case */

  if (smallestSize == 1) {
    uint8_t byte = *(byteSets[smallestIndex].begin());

    /* insert instructions to check whether the value we are switching on is
     * equal to byte */
    ICmpInst *Comp =
        new ICmpInst(ICmpInst::ICMP_EQ, Trunc, ConstantInt::get(ByteType, byte),
                     "byteMatch");
#if LLVM_VERSION_MAJOR >= 16
    Comp->insertInto(NewNode, NewNode->end());
#else
    NewNode->getInstList().push_back(Comp);
#endif

    bytesChecked[smallestIndex] = true;
    bool allBytesAreChecked = true;

    for (std::vector<bool>::iterator BCI = bytesChecked.begin(),
                                     E = bytesChecked.end();
         BCI != E; ++BCI) {
      if (!*BCI) {
        allBytesAreChecked = false;
        break;
      }
    }

    //    if (std::all_of(bytesChecked.begin(), bytesChecked.end(),
    //                    [](bool b) { return b; })) {

    if (allBytesAreChecked) {
      assert(Cases.size() == 1);
      BranchInst::Create(Cases[0].BB, NewDefault, Comp, NewNode);

      /* we have to update the phi nodes! */
      for (BasicBlock::iterator I = Cases[0].BB->begin();
           I != Cases[0].BB->end(); ++I) {
        if (!isa<PHINode>(&*I)) { continue; }
        PHINode *PN = cast<PHINode>(I);

        /* Only update the first occurrence. */
        unsigned Idx = 0, E = PN->getNumIncomingValues();
        for (; Idx != E; ++Idx) {
          if (PN->getIncomingBlock(Idx) == OrigBlock) {
            PN->setIncomingBlock(Idx, NewNode);
            break;
          }
        }
      }
    } else {
      BasicBlock *BB = switchConvert(Cases, bytesChecked, OrigBlock, NewDefault,
                                     Val, level + 1);
      BranchInst::Create(BB, NewDefault, Comp, NewNode);
    }
  }
  /* there is no byte which we can directly check on, split the tree */
  else {
    std::vector<uint8_t> byteVector;
    std::copy(byteSets[smallestIndex].begin(), byteSets[smallestIndex].end(),
              std::back_inserter(byteVector));
    std::sort(byteVector.begin(), byteVector.end());
    uint8_t pivot = byteVector[byteVector.size() / 2];

    /* we already chose to divide the cases based on the value of byte at
     * index smallestIndex the pivot value determines the threshold for the
     * decicion; if a case value is smaller at this byte index move it to the
     * LHS vector, otherwise to the RHS vector */
    CaseVector LHSCases, RHSCases;

    for (CaseExpr &Case : Cases) {
      uint8_t byte = (Case.Val->getZExtValue() >> (smallestIndex * 8)) & 0xFF;
      if (byte < pivot) {
        LHSCases.push_back(Case);
      } else {
        RHSCases.push_back(Case);
      }
    }

    BasicBlock *LBB, *RBB;
    LBB = switchConvert(LHSCases, bytesChecked, OrigBlock, NewDefault, Val,
                        level + 1);
    RBB = switchConvert(RHSCases, bytesChecked, OrigBlock, NewDefault, Val,
                        level + 1);

    /* insert instructions to check whether the value we are switching on is
     * equal to byte */
    ICmpInst *Comp =
        new ICmpInst(ICmpInst::ICMP_ULT, Trunc,
                     ConstantInt::get(ByteType, pivot), "byteMatch");
#if LLVM_VERSION_MAJOR >= 16
    Comp->insertInto(NewNode, NewNode->end());
#else
    NewNode->getInstList().push_back(Comp);
#endif
    BranchInst::Create(LBB, RBB, Comp, NewNode);
  }

  return NewNode;
}

bool SkeletonPass::splitSwitches(Module &M) {
  LLVMContext              &C = M.getContext();
  std::vector<SwitchInst *> switches;

  /* iterate over all functions, bbs and instruction and add
   * all switches to switches vector for later processing */
  for (auto &F : M) {
    for (auto &BB : F) {
      SwitchInst *switchInst = nullptr;

      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {
        // if (switchInst->getNumCases() < 1) continue;
        switches.push_back(switchInst);
      }
    }
  }

  // if (!switches.size()) return false;
  for (auto &SI : switches) {
    BasicBlock *CurBlock = SI->getParent();
    BasicBlock *OrigBlock = CurBlock;
    Function   *F = CurBlock->getParent();
    /* this is the value we are switching on */
    Value      *Val = SI->getCondition();
    BasicBlock *Default = SI->getDefaultDest();
    unsigned    bitw = Val->getType()->getIntegerBitWidth();

    /* Create a new, empty default block so that the new hierarchy of
     * if-then statements go to this and the PHI nodes are happy.
     * if the default block is set as an unreachable we avoid creating one
     * because will never be a valid target.*/
    BasicBlock *NewDefault = nullptr;
    NewDefault = BasicBlock::Create(SI->getContext(), "NewDefault", F, Default);
    BranchInst::Create(Default, NewDefault);

    /* Prepare cases vector. */
    CaseVector Cases;
    for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
         ++i)
      Cases.push_back(CaseExpr(i->getCaseValue(), i->getCaseSuccessor()));
    /* bugfix thanks to pbst
     * round up bytesChecked (in case getBitWidth() % 8 != 0) */
    std::vector<bool> bytesChecked((7 + Cases[0].Val->getBitWidth()) / 8,
                                   false);
    BasicBlock       *SwitchBlock =
        switchConvert(Cases, bytesChecked, OrigBlock, NewDefault, Val, 0);

    /* Branch to our shiny new if-then stuff... */
    BranchInst::Create(SwitchBlock, OrigBlock);

    /* We are now done with the switch instruction, delete it. */
#if LLVM_VERSION_MAJOR >= 16
    SI->eraseFromParent();
#else
    CurBlock->getInstList().erase(SI);
#endif

    /* we have to update the phi nodes! */
    for (BasicBlock::iterator I = Default->begin(); I != Default->end(); ++I) {
      if (!isa<PHINode>(&*I)) { continue; }
      PHINode *PN = cast<PHINode>(I);

      /* Only update the first occurrence. */
      unsigned Idx = 0, E = PN->getNumIncomingValues();
      for (; Idx != E; ++Idx) {
        if (PN->getIncomingBlock(Idx) == OrigBlock) {
          PN->setIncomingBlock(Idx, NewDefault);
          break;
        }
      }
    }
  }

  // verifyModule(M);
  return true;
}

char SkeletonPass::ID = 0;

static void registerSkeletonPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
  PM.add(new SkeletonPass());
}
static RegisterStandardPasses RegisterMyPass(
    PassManagerBuilder::EP_OptimizerLast, registerSkeletonPass);
static RegisterStandardPasses RegisterMyPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerSkeletonPass);
