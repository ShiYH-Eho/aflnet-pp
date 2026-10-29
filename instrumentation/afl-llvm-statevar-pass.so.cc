/*
   american fuzzy lop++ (aflnet-pp) - state-variable feedback pass
   ---------------------------------------------------------------

   Companion instrumentation for the AFLNet state-variable feedback
   backend (state_mode == AFLNET_STATE_VAR_MODE == 2).

   The fuzzer (see src/aflnet/utils/statevar.c) creates a dedicated shared
   memory region (AFLNET_STATEVAR_SHM_SIZE, exported to the instrumented
   target via AFLNET_STATEVAR_SHM_ENV_VAR = "__AFL_AFLNET_STATEVAR_SHM_ID")
   and hashes its whole content after every server response to derive a
   "state id" for IPSM.  The target-side runtime glue lives in the independent
   object instrumentation/afl-statevar-rt.o.c
   (__afl_statevar_record() and __afl_statevar_record_ptr()).

   Value contract (2026-09-09, pointer semantics refined)
   -----------------------------------------------------
   All variables that carry the annotation

       __attribute__((annotate("__AFL_STATE_VAR__")))

   are assumed to be INTEGER types or POINTERS (int / unsigned / long / enum /
   int* / struct S* / void* / ...), i.e. every store to them is a whole scalar
   store that fits into one 64-bit word.  Aggregate variables (structs /
   arrays) are intentionally NOT tracked; if one is annotated anyway it is
   skipped with a debug note.

   For every such store the pass inserts, right after the store:

       void __afl_statevar_record(u64 word, u64 value)

   for integer variables, which writes the new value zero-extended into the
   variable's dedicated 8-byte slot of the state SHM; and

       void __afl_statevar_record_ptr(u64 word, const void *p, u64 width)

   for POINTER variables.  Raw addresses are never recorded (they depend on
   ASLR), only the state behind the pointer:

     width != 0  the pointee is an integer -> the runtime dereferences `p` and
                 records the pointed-to integer; width is the pointee size in
                 bytes (1/2/4/8).  sizeof(int) is used when the address
                 expression cannot be analysed (function call result, load,
                 inline asm, select of disagreeing alternatives, ...);
                 pointer arithmetic and `select`/`phi` on compatible
                 alternatives are analysed.  The chosen interpretation is
                 remembered per slot, so a later unanalysable store to the
                 same variable keeps the earlier, known width.
     width == 0  the pointee is NOT an integer (struct / union / array /
                 float / function pointer / ...) -> only whether the pointer
                 is NULL is state: the runtime records 0 or 1 without ever
                 touching the pointee.

   Writing a NULL pointer therefore always records 0, for integer and
   non-integer pointees alike.

   How the annotation reaches the pass (different per C construct)
   ----------------------------------------------------------------
   1) global / file-scope static / function-local static variables ->
      `llvm.global.annotations` appending array {var, annstr, file,
      line[, arg]}; survives -O2.
   2) struct *member field* annotated in the type
      (`struct S { int marked __attribute__((annotate(...))); };`) ->
      NOT in llvm.global.annotations; clang emits
      `llvm.ptr.annotation(ptr &obj.marked, ...)` at each use of the member
      address and stores go through the returned pointer (survives -O2,
      opaque-pointer spelling llvm.ptr.annotation.p0.p0).  The pass resolves
      the pointer to its storage object + byte offset and records stores to
      that member.  Only members that live in a global/static are recorded
      (members of stack objects are per-call, not persistent protocol state).
   3) function parameters (and automatic locals)
      (`int f(int p __attribute__((annotate(...)))))`) -> clang demotes the
      parameter to an alloca and emits `llvm.var.annotation(ptr %alloca,
      ...)` inside the function; the initial parameter store (and later
      assignments) can then be recorded.  Survives -O2.

   Intrinsic names carry opaque-pointer suffixes (llvm.var.annotation.p0.p0
   / llvm.ptr.annotation.p0.p0), so all matching is done by intrinsic ID.

   Slots: one 8-byte word per annotated variable, derived from a stable
   hash of its identity (name + defining file); in-TU overlap is avoided by
   linear probing.

   Pipeline placement: optimizer-last extension point (same as
   afl-llvm-ijon-pass.so); only stores that survive optimization (i.e. are
   observable) are instrumented.

   Enablement
   ----------
   Set AFL_LLVM_STATEVAR=1 when compiling the target with afl-clang-fast /
   afl-clang-lto / afl-clang (afl-cc loads this pass through -fpass-plugin).
   The target must run under an afl-fuzz built with AFLNet state-mode 2.
   Standalone: `opt -passes=statevar-instr`.

   Licensed under the Apache License, Version 2.0.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

// Include LLVM headers first to avoid macro conflicts
#include "llvm/Config/llvm-config.h"
#include "llvm/Passes/PassBuilder.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/raw_ostream.h"

// Now include AFL++ headers
#include "config.h"
#include "types.h"
#include "afl-llvm-common.h"

#ifndef LLVM_MAJOR
  #define LLVM_MAJOR LLVM_VERSION_MAJOR
#endif

using namespace llvm;

/* Keep these in sync with include/config.h and the fuzzer backend in
   src/aflnet/utils/statevar.c. */
#ifndef AFLNET_STATEVAR_SHM_SIZE
  #define AFLNET_STATEVAR_SHM_SIZE (1U << 14) /* 16 KB */
#endif
#define AFLNET_STATEVAR_WORD_SIZE 8U          /* bytes recorded per slot */
#define AFLNET_STATEVAR_NUM_SLOTS                                             \
  (AFLNET_STATEVAR_SHM_SIZE / AFLNET_STATEVAR_WORD_SIZE)
#define AFLNET_STATEVAR_ANNOTATION "__AFL_STATE_VAR__"
#define AFLNET_STATEVAR_RECORD_FN "__afl_statevar_record"
#define AFLNET_STATEVAR_RECORD_PTR_FN "__afl_statevar_record_ptr"

namespace {

/* FNV-1a 64-bit; used to derive a stable per-variable SHM slot. */
static uint64_t statevarHash(const std::string &s) {

  uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : s) {

    h ^= (uint64_t)c;
    h *= 1099511628211ULL;

  }

  return h;

}

/* Peel constant pointer casts (bitcast / addrspacecast) and constant GEPs
   whose indices are all zero, i.e. expressions that still address the base
   of the object.  Returns the underlying constant. */
static Constant *statevarPeel(Constant *C) {

  while (true) {

    auto *CE = dyn_cast<ConstantExpr>(C);
    if (!CE) return C;

    unsigned op = CE->getOpcode();
    if (op == Instruction::BitCast || op == Instruction::AddrSpaceCast ||
        op == Instruction::PtrToInt || op == Instruction::IntToPtr) {

      C = CE->getOperand(0);
      continue;

    }

    if (op == Instruction::GetElementPtr) {

      bool allZero = true;
      for (unsigned i = 1; i < CE->getNumOperands(); ++i) {

        auto *CI = dyn_cast<ConstantInt>(CE->getOperand(i));
        if (!CI || !CI->isZero()) {

          allZero = false;
          break;

        }

      }

      if (allZero) {

        C = CE->getOperand(0);
        continue;

      }

    }

    return C;

  }

}

/* Resolve an i8* / ptr constant that points at an NUL-terminated string
   constant (a GEP into a private [N x i8] global) to its text. */
static std::string statevarString(Constant *C) {

  C = statevarPeel(C);
  auto *GV = dyn_cast<GlobalVariable>(C);
  if (!GV || !GV->hasInitializer()) return "";

  auto *Init = dyn_cast<ConstantDataSequential>(GV->getInitializer());
  if (!Init || !Init->isString()) return "";

  StringRef s = Init->getAsString();
  size_t    nul = s.find('\0');
  if (nul != StringRef::npos) s = s.substr(0, nul);
  return s.str();

}

/* Resolve the first field of an llvm.global.annotations element (or the
   first argument of llvm.var.annotation) to the annotated global, if any. */
static GlobalVariable *statevarGlobal(Constant *C) {

  C = statevarPeel(C);
  return dyn_cast<GlobalVariable>(C);

}

/* True when the call is one of clang's annotation intrinsics.  We match by
   intrinsic ID (not by name) because opaque-pointer clang spells them
   llvm.var.annotation.p0.p0 / llvm.ptr.annotation.p0.p0. */
static bool isAnnotIntrinsic(const CallInst *CI, unsigned ID) {

  const Function *F = CI->getCalledFunction();
  if (!F || !F->isIntrinsic()) return false;
  return F->getIntrinsicID() == ID;

}

/* Per the current value contract only integer types and (integer) pointers
   are marked / recorded. */
static bool isIntOrPtr(Type *T) {

  return T->isIntegerTy() || T->isPointerTy();

}

/* What the pointer stored into an annotated pointer variable points to, as
   far as local value analysis can tell.  With opaque pointers (LLVM >= 15)
   the declared pointee type is not available, so it is inferred from the
   address expression being stored: the value type of a GlobalVariable, the
   allocated type of an AllocaInst, or the result element type of a GEP.
   `known == false` means the pointee could not be established. */
struct PointeeInfo {

  bool     known = false;
  bool     integer = false;  /* scalar integer pointee */
  unsigned bytes = 0;        /* pointee size in bytes when integer */

};

/* Classification of a single address expression (no branching inside). */
static PointeeInfo classifyAddress(Value *P, const DataLayout &DL) {

  (void)DL;
  P = P->stripPointerCasts();

  Type *T = nullptr;
  if (auto *GV = dyn_cast<GlobalVariable>(P)) T = GV->getValueType();
  else if (auto *AI = dyn_cast<AllocaInst>(P)) T = AI->getAllocatedType();
  else if (auto *G = dyn_cast<GEPOperator>(P)) T = G->getResultElementType();

  if (!T) return {};

  /* An array of integers is still integer state: look through the array. */
  while (T->isArrayTy() || T->isVectorTy()) {

    T = T->isArrayTy() ? T->getArrayElementType()
                       : cast<VectorType>(T)->getElementType();

  }

  PointeeInfo Info;
  Info.known = true;

  if (T->isIntegerTy()) {

    unsigned W = T->getIntegerBitWidth();
    if (W == 8 || W == 16 || W == 32 || W == 64) {

      Info.integer = true;
      Info.bytes = W / 8;

    }

  }

  return Info;

}

/* Flatten an address expression into the addresses it can evaluate to,
   looking through selects and phis (a pointer assigned under a condition is
   compiled to one of those). */
static void collectAddresses(Value *P, std::vector<Value *> &Out,
                             unsigned Depth) {

  P = P->stripPointerCasts();

  if (Depth < 8) {

    if (auto *Sel = dyn_cast<SelectInst>(P)) {

      collectAddresses(Sel->getTrueValue(), Out, Depth + 1);
      collectAddresses(Sel->getFalseValue(), Out, Depth + 1);
      return;

    }

    if (auto *Phi = dyn_cast<PHINode>(P)) {

      for (Value *In : Phi->incoming_values())
        collectAddresses(In, Out, Depth + 1);
      return;

    }

  }

  Out.push_back(P);

}

/* Pointee classification of an address expression.  NULL alternatives are
   ignored (whatever the width, a NULL pointer records 0), the other
   alternatives must agree, otherwise the result is "unknown" and the caller
   falls back to its default. */
static PointeeInfo pointeeInfo(Value *P, const DataLayout &DL) {

  std::vector<Value *> Cand;
  collectAddresses(P, Cand, 0);

  PointeeInfo Acc;
  bool        have = false;

  for (Value *C : Cand) {

    if (isa<ConstantPointerNull>(C->stripPointerCasts())) continue;

    PointeeInfo Info = classifyAddress(C, DL);

    /* one alternative we cannot analyse: do not guess */
    if (!Info.known) return {};

    if (!have) {

      Acc = Info;
      have = true;

    } else if (Acc.integer != Info.integer || Acc.bytes != Info.bytes) {

      /* e.g. select between a struct pointer and an int pointer */
      return {};

    }

  }

  if (!have) return {};  /* only NULL: the runtime records 0, width is moot */

  return Acc;

}

/* Result of resolving a (store) destination pointer to its storage object.
   byteOff is the constant byte offset inside the object when all GEP
   indices were constant; dynamic is set when an index was non-constant
   (the object root is still known). */
struct StoreLoc {

  GlobalVariable *gv = nullptr;
  AllocaInst     *ai = nullptr;
  uint64_t        byteOff = 0;
  bool            dynamic = false;
  bool            valid() const { return gv != nullptr || ai != nullptr; }

};

/* Walk a pointer expression through pointer annotation intrinsics, pointer
   casts and GEPs down to the underlying storage object (global or alloca),
   accumulating the constant byte offset. */
static StoreLoc resolveStoreLoc(Value *V, const DataLayout &DL) {

  StoreLoc Res;
  uint64_t Acc = 0;
  bool     Dyn = false;

  while (true) {

    if (auto *CI = dyn_cast<CallInst>(V)) {

      if (isAnnotIntrinsic(CI, Intrinsic::ptr_annotation) ||
          isAnnotIntrinsic(CI, Intrinsic::var_annotation)) {

        V = CI->getArgOperand(0);
        continue;

      }

    }

    V = V->stripPointerCasts();

    auto *G = dyn_cast<GEPOperator>(V);
    if (!G) break;

    APInt Off(DL.getIndexSizeInBits(G->getPointerAddressSpace()), 0);
    if (G->accumulateConstantOffset(DL, Off)) {

      Acc += Off.getZExtValue();

    } else {

      Dyn = true;

    }

    V = G->getPointerOperand();

  }

  V = V->stripPointerCasts();
  if (auto *GV = dyn_cast<GlobalVariable>(V)) Res.gv = GV;
  else if (auto *AI = dyn_cast<AllocaInst>(V)) Res.ai = AI;
  Res.byteOff = Acc;
  Res.dynamic = Dyn;
  return Res;

}

/* The pass itself.  A module pass: it needs the module-level
   `llvm.global.annotations` array and the module DataLayout. */
class StateVarInstr : public PassInfoMixin<StateVarInstr> {

 public:
  StateVarInstr() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  u64    allocateSlot(const std::string &ident);
  void   addWholeVar(Module &M, GlobalVariable *GV, const std::string &file);
  void   addMemberVar(Module &M, GlobalVariable *GV, u64 byteOff,
                      const std::string &file);
  void   addLocalVar(Module &M, AllocaInst *AI, const std::string &file);
  bool   collectAnnotated(Module &M);
  void   collectMemberAnnotations(Module &M);
  void   collectVarAnnotationCalls(Module &M);
  bool   instrumentFunction(Function &F);

  const DataLayout *DL = nullptr;
  Function         *recordFn = nullptr;
  Function         *recordPtrFn = nullptr;
  Type             *PtrTy = nullptr;

  bool usedWord[AFLNET_STATEVAR_NUM_SLOTS];  // in-TU collision avoidance

  /* entity -> SHM word index (one 8-byte slot per annotated variable) */
  std::map<GlobalVariable *, u64>                    wholeVars;
  std::map<std::pair<GlobalVariable *, u64>, u64>    memberVars;  // (gv, byteOff)
  std::map<AllocaInst *, u64>                        localVars;
  /* Pointer classification per word, remembered so that a variable keeps
     its interpretation if it is later assigned an address we cannot
     analyse (e.g. a call result). */
  std::map<u64, PointeeInfo>                         wordPointee;
  std::vector<std::string>                           debugDescr;
  unsigned annotatedVars = 0;
  unsigned instrumentedStores = 0;
  unsigned skippedStores = 0;
  unsigned nullFlagStores = 0;

};

/* Reserve one 8-byte word (linear probe from a hash of the identity). */
u64 StateVarInstr::allocateSlot(const std::string &ident) {

  u64 base = statevarHash(ident) % AFLNET_STATEVAR_NUM_SLOTS;
  for (u64 i = 0; i < AFLNET_STATEVAR_NUM_SLOTS; ++i) {

    u64 w = (base + i) % AFLNET_STATEVAR_NUM_SLOTS;
    if (!usedWord[w]) {

      usedWord[w] = true;
      return w;

    }

  }

  return base;  // all taken (unreachable in practice)

}

/* Register an annotated whole global/static.  Only integer / pointer-typed
   globals are tracked (see value contract); everything else is skipped. */
void StateVarInstr::addWholeVar(Module &M, GlobalVariable *GV,
                                const std::string &file) {

  if (wholeVars.count(GV)) return;
  if (GV->isDeclaration()) return;
  if (!isIntOrPtr(GV->getValueType())) {

    if (getenv("AFL_DEBUG"))
      fprintf(stderr,
              "statevar pass: skip global %s: not an integer/pointer type\n",
              GV->getName().str().c_str());
    return;

  }

  std::string ident =
      GV->getName().str() + "\n" + file + "\n" + M.getSourceFileName();
  u64 word = allocateSlot(ident);
  wholeVars[GV] = word;

  debugDescr.push_back(GV->getName().str() + " (global, " + file +
                       ") -> word " + std::to_string(word));
  ++annotatedVars;

}

/* Register an annotated struct member that lives inside a global/static.
   byteOff is the member's byte offset inside GV. */
void StateVarInstr::addMemberVar(Module &M, GlobalVariable *GV, u64 byteOff,
                                 const std::string &file) {

  auto Key = std::make_pair(GV, byteOff);
  if (memberVars.count(Key)) return;

  std::string ident = GV->getName().str() + "+0x" +
                      std::to_string(byteOff) + "\n" + file + "\n" +
                      M.getSourceFileName();
  u64 word = allocateSlot(ident);
  memberVars[Key] = word;

  debugDescr.push_back(GV->getName().str() + "+0x" +
                       std::to_string(byteOff) + " (member, " + file +
                       ") -> word " + std::to_string(word));
  ++annotatedVars;

}

/* Register an annotated function parameter / automatic local (alloca).
   Only integer / pointer-typed locals are tracked. */
void StateVarInstr::addLocalVar(Module &M, AllocaInst *AI,
                                const std::string &file) {

  if (localVars.count(AI)) return;
  if (!isIntOrPtr(AI->getAllocatedType())) return;

  Function *F = AI->getFunction();
  std::string vname = AI->getName().empty()
                          ? ("<local@" + (F ? F->getName().str() : "?") + ">")
                          : AI->getName().str();
  std::string ident =
      vname + "\n" + file + "\n" + (F ? F->getName().str() : "");
  u64 word = allocateSlot(ident);
  localVars[AI] = word;

  debugDescr.push_back(vname + " (local/param, " + file + ") -> word " +
                       std::to_string(word));
  ++annotatedVars;

}

/* Case 1: whole globals/statics from `llvm.global.annotations`. */
bool StateVarInstr::collectAnnotated(Module &M) {

  GlobalVariable *GA = M.getGlobalVariable("llvm.global.annotations");
  if (!GA || !GA->hasInitializer()) return false;

  auto *Array = dyn_cast<ConstantArray>(GA->getInitializer());
  if (!Array) return false;

  bool found = false;

  for (unsigned i = 0; i < Array->getNumOperands(); ++i) {

    auto *El = dyn_cast<ConstantStruct>(Array->getOperand(i));
    // { i8* / ptr variable, i8* / ptr annotation, i8* / ptr file, i32 line }
    if (!El || El->getNumOperands() < 3) continue;

    std::string ann = statevarString(El->getOperand(1));
    if (ann != AFLNET_STATEVAR_ANNOTATION) continue;

    GlobalVariable *GV = statevarGlobal(El->getOperand(0));
    if (!GV) continue;

    std::string file = statevarString(El->getOperand(2));
    addWholeVar(M, GV, file);
    found = true;

  }

  return found;

}

/* Case 2: annotated struct members.  clang records these at each use of the
   member's address with an llvm.ptr.annotation call whose first argument is
   the address expression (a constant GEP rooted at the storage object). */
void StateVarInstr::collectMemberAnnotations(Module &M) {

  for (Function &F : M) {

    if (F.isDeclaration()) continue;

    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || !isAnnotIntrinsic(CI, Intrinsic::ptr_annotation)) continue;

        std::string ann =
            statevarString(dyn_cast<Constant>(CI->getArgOperand(1)));
        if (ann != AFLNET_STATEVAR_ANNOTATION) continue;

        std::string file = "";
        if (auto *C = dyn_cast<Constant>(CI->getArgOperand(2)))
          file = statevarString(C);

        StoreLoc Loc = resolveStoreLoc(CI->getArgOperand(0), *DL);
        // Persistent protocol state only: member must live in a global/static
        // and its offset must be constant.  Members of stack objects are
        // per-call (not state) and pointers-of-unknown are not resolvable.
        if (Loc.gv && !Loc.dynamic) addMemberVar(M, Loc.gv, Loc.byteOff, file);

      }

    }

  }

}

/* Case 3: annotated function parameters / automatic locals.  clang demotes
   an annotated parameter/local to an alloca and records it with an
   llvm.var.annotation call inside the function (these survive -O2 with
   modern clang; the alloca is not SROA-promoted because the annotation takes
   its address). */
void StateVarInstr::collectVarAnnotationCalls(Module &M) {

  for (Function &F : M) {

    if (F.isDeclaration()) continue;

    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI || !isAnnotIntrinsic(CI, Intrinsic::var_annotation)) continue;

        std::string ann =
            statevarString(dyn_cast<Constant>(CI->getArgOperand(1)));
        if (ann != AFLNET_STATEVAR_ANNOTATION) continue;

        Value *Ptr = CI->getArgOperand(0)->stripPointerCasts();
        std::string file = "";
        if (auto *C = dyn_cast<Constant>(CI->getArgOperand(2)))
          file = statevarString(C);

        if (auto *AI = dyn_cast<AllocaInst>(Ptr)) addLocalVar(M, AI, file);
        // (var.annotation pointing at a global is handled via
        //  llvm.global.annotations; function-local statics are globals too.)

      }

    }

  }

}

/* Insert a __afl_statevar_record(word, value) call right after every
   surviving whole store to an annotated integer / integer-pointer
   variable, member or parameter. */
bool StateVarInstr::instrumentFunction(Function &F) {

  if (F.isDeclaration()) return false;
  if (F.size() < 1) return false;
  if (!isInInstrumentList(&F, FMNAME)) return false;

  bool changed = false;
  LLVMContext &Ctx = F.getContext();
  Type        *I64Ty = Type::getInt64Ty(Ctx);

  for (BasicBlock &BB : F) {

    for (Instruction &I : BB) {

      auto *SI = dyn_cast<StoreInst>(&I);
      if (!SI) continue;

      Value   *Val = SI->getValueOperand();
      Type    *ValTy = Val->getType();
      StoreLoc Loc = resolveStoreLoc(SI->getPointerOperand(), *DL);
      if (!Loc.valid()) continue;

      u64  word = 0;
      bool isTarget = false;

      if (Loc.ai) {

        auto It = localVars.find(Loc.ai);
        // whole scalar store to an annotated local/param
        if (It != localVars.end() && Loc.byteOff == 0 && !Loc.dynamic &&
            ValTy == Loc.ai->getAllocatedType()) {

          word = It->second;
          isTarget = true;

        }

      } else if (Loc.gv) {

        // Exact write to an annotated member of a struct global?
        auto MIt = memberVars.find(std::make_pair(Loc.gv, Loc.byteOff));
        if (MIt != memberVars.end() && !Loc.dynamic) {

          word = MIt->second;
          isTarget = true;

        } else {

          // whole scalar store to an annotated integer/pointer global
          auto WIt = wholeVars.find(Loc.gv);
          if (WIt != wholeVars.end() && Loc.byteOff == 0 && !Loc.dynamic &&
              ValTy == Loc.gv->getValueType()) {

            word = WIt->second;
            isTarget = true;

          }

        }

      }

      if (!isTarget) continue;

      // Insert AFTER the store so the recorded value matches memory.
      Instruction *InsertPt = SI->getNextNode();
      IRBuilder<>  IRB(InsertPt);
      CallInst    *Call = nullptr;

      if (ValTy->isIntegerTy()) {

        // Integer variable: record the new value zero-extended to 64 bits.
        unsigned W = ValTy->getIntegerBitWidth();
        if (W == 0 || W > 64) {

          ++skippedStores;
          continue;

        }

        Value *Val64 = (W == 64) ? Val : IRB.CreateZExt(Val, I64Ty);
        Call = IRB.CreateCall(recordFn, {IRB.getInt64(word), Val64});

      } else if (ValTy->isPointerTy()) {

        /* Pointer state variable.  The pointer value itself is never
           recorded: raw addresses depend on ASLR and would turn every run
           into a new state.  What is recorded is the state behind the
           pointer:

             - pointee is an integer  -> record the pointed-to integer
               (dereferenced here in the target), width = pointee size;
             - pointee is anything else (struct / union / array / float /
               function / ...) -> record only whether the pointer is NULL,
               which the runtime encodes as 0 or 1 (width == 0);
             - pointee unknown -> sizeof(int) fallback, as before. */

        PointeeInfo Info = pointeeInfo(Val, *DL);
        auto        It = wordPointee.find(word);

        if (Info.known) {

          wordPointee[word] = Info;

        } else if (It != wordPointee.end()) {

          Info = It->second;  /* known value from an earlier store */

        } else {

          Info.known = Info.integer = true;
          Info.bytes = 4;

        }

        u64 Width = Info.integer ? (u64)Info.bytes : 0;

        if (!Info.integer) ++nullFlagStores;

        Call = IRB.CreateCall(recordPtrFn,
                              {IRB.getInt64(word),
                               IRB.CreatePointerCast(Val, PtrTy),
                               IRB.getInt64(Width)});

      } else {

        ++skippedStores;
        continue;

      }

      setNoSanitizeMetadata(Call);
      Call->setMetadata("afl.skip", MDNode::get(Ctx, {}));
      changed = true;
      ++instrumentedStores;

    }

  }

  return changed;

}

PreservedAnalyses StateVarInstr::run(Module &M, ModuleAnalysisManager &MAM) {

  (void)MAM;

  setvbuf(stderr, NULL, _IONBF, 0);
  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG")) {

    fprintf(stderr, "afl-llvm-statevar-pass" VERSION "\n");

  } else if (getenv("AFL_QUIET")) {

    be_quiet = 1;

  }

  for (u64 i = 0; i < AFLNET_STATEVAR_NUM_SLOTS; ++i)
    usedWord[i] = false;
  wholeVars.clear();
  memberVars.clear();
  localVars.clear();
  wordPointee.clear();
  debugDescr.clear();
  annotatedVars = 0;
  instrumentedStores = 0;
  skippedStores = 0;
  nullFlagStores = 0;

  DL = &M.getDataLayout();
  LLVMContext &Ctx = M.getContext();
#if LLVM_MAJOR >= 20
  PtrTy = PointerType::getUnqual(Ctx);
#else
  PtrTy = PointerType::get(Type::getInt8Ty(Ctx), 0);
#endif

  collectAnnotated(M);
  collectMemberAnnotations(M);
  collectVarAnnotationCalls(M);

  if (annotatedVars == 0) {

    if (getenv("AFL_DEBUG")) {

      fprintf(stderr,
              "statevar pass: no __AFL_STATE_VAR__ annotated variables in "
              "this module\n");

    }

    return PreservedAnalyses::all();

  }

  // Declare the target-side runtime helper (afl-statevar-rt.o).
  recordFn = M.getFunction(AFLNET_STATEVAR_RECORD_FN);
  if (!recordFn) {

    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(Ctx),
        {Type::getInt64Ty(Ctx), Type::getInt64Ty(Ctx)}, false);
    recordFn = Function::Create(FT, Function::ExternalLinkage,
                                AFLNET_STATEVAR_RECORD_FN, &M);

  }

  recordPtrFn = M.getFunction(AFLNET_STATEVAR_RECORD_PTR_FN);
  if (!recordPtrFn) {

    FunctionType *FT = FunctionType::get(
        Type::getVoidTy(Ctx),
        {Type::getInt64Ty(Ctx), PtrTy, Type::getInt64Ty(Ctx)}, false);
    recordPtrFn = Function::Create(FT, Function::ExternalLinkage,
                                   AFLNET_STATEVAR_RECORD_PTR_FN, &M);

  }

  for (Function &F : M)
    instrumentFunction(F);

  if (getenv("AFL_DEBUG")) {

    for (auto &l : debugDescr)
      fprintf(stderr, "statevar pass:   %s\n", l.c_str());
    fprintf(stderr,
            "statevar pass: %u annotated variable(s), %u store(s) "
            "instrumented, %u store(s) skipped (%u recorded pointer "
            "nullity)\n",
            annotatedVars, instrumentedStores, skippedStores, nullFlagStores);

  }

  return instrumentedStores ? PreservedAnalyses::none()
                            : PreservedAnalyses::all();

}

}  // namespace

/* Register the pass so clang/afl-clang-fast can run it through
   -fpass-plugin (AFL_LLVM_STATEVAR=1) and so opt can run it manually via
   -passes=statevar-instr.  Optimizer-last: only stores that survive
   optimization are instrumented (observable state only, no dead-store
   noise). */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "StateVarInstr", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
#if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
#endif
                ) { MPM.addPass(StateVarInstr()); });

            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {

                  if (Name == "statevar-instr") {

                    MPM.addPass(StateVarInstr());
                    return true;

                  }

                  return false;

                });

          }};

}
