\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{amssymb}
\usepackage{amsmath}
\usepackage{listings}
\let\oldemptyset\emptyset
\let\emptyset\varnothing
\usepackage{parskip}
\usepackage{fancyvrb}

\title{ARM Instruction Grammar}
\author{Olivia Lucca Fraser\\B00109376}
\date{\today}

%include polycode.fmt

\begin{document}

\maketitle


\section{Introduction}

This module contains a parser for ARM 32-bit machine code. Its
purpose is to `re-compile' the machine code into a series of
haskell functions and data structures that we can manipulate
and effectively reason with. The information we extract from
the binary here will be used to aggregate the code into gadgets,
and -- together with the information extracted from the user-
provided script or specifications -- guide their compilation into
an initial population of ROP-chains.

\section{Dependencies}

First we'll need to import a handful of libraries. The most
interesting among these is Attoparsec, a fast binary-parsing
library that we're pulling from Hackage. Aux is a module of
general-purpose convenience functions, which I've written, and
the rest of the imports provide some fairly standard data types
and functions (Data.Word provides fixed width integer types,
Data.Bits gives us a few standard bitwise operations, etc.)

\begin{code}
module ARM32 where

import Aux
import ARMCommon

import Data.Word
import Data.Bits

import Numeric (showHex)
\end{code}


\section{Data Types}

Here we introduce a few data types that we'll be using to
organize the information we extract from each ARM instruction,
and define a few constants.

It will be handy to fix a few constants so that we can easily
refer to a few important registers. In particular, we want to
have constant pointers to the stack pointer (SP), the link
register (LR), the programme counter (PC), and the frame pointer
(FP).

Under ordinary circumstances, the frame pointer (FP) points to
the bottom of the stack frame for the active function, and, upon
exiting the function, it is used to restore the stack pointer (SP)
to where it was before that function had its way with it.

Unlike what we see with the x86, the function calling convention
for the ARM specifies that the return address for a function be
placed in a register reserved for that purpose, the link register.
The branch-link (BL) instruction does this by performing two actions
together: it sets the programme counter (PC) to the function's entry
point, and LR to the address of the instruction where execution will
resume.

For nested function calls, however, the familiar convention of pushing
the return address onto the stack is used, and so there are typically
two different conventions for exiting a function:

(1) MOV     PC, LR     ;; copy the lr into the pc
(2) LDMIA   SP!, {PC}  ;; pop the stack into pc

\begin{code}
  -- | Moved to ARMCommon.lhs | --
\end{code}


Compared to the motley structure of the x86 instruction set, the
ARM instruction set has a fairly regular format. There are just
14 (or 15, if we count "undefined") different layouts that the
instruction set makes use of, and so, before we can extract the
fields we need from the instruction (operation, source and desti-
nation registers, etc.).

Each layout can be recognized by its signature pattern of high
and low bits. There is not, however, a generic `layout' field
in the instruction, and so several different masks -- each isolating
different bitfields -- may need to be applied to an instruction
before we can decipher its layout. For this we will be using the
\texttt{mask} function defined in Aux.hs.

The development here is still lagging behind the developmento of the Thumb16.lhs module. In time, the layout instances will be furnished with additional fields encoding important type information about each instruction, such as its mnemonic/opcode, immediate values, etc.

\begin{code}

data Layout =
  DataProc DPMnemonic
  | Mult
  | MultLong
  | SingDataSwap
  | BranchExch
  | HalfWordDataI
  | HalfWordDataR
  | SingDataTrans
  | Undef
  | BlockDataTrans
  | Branch
  | CoprocDataTrans
  | CoprocDataOp
  | CoprocRegTrans
  | SWI
  | RAWDATA deriving (Eq, Show)

whatLayout :: Word32 -> Layout
whatLayout w
  | mask w 4 8 == 9 && mask w 22 28 == 0  = Mult
  | mask w 4 8 == 9 && mask w 23 28 == 1  = MultLong
  | mask w 4 12 == 9 && mask w 23 28 == 2 = SingDataSwap
  | mask w 4 28 == 0x12fff1               = BranchExch
  | mask w 4 5 == 1 && mask w 7 12 == 1
    && mask w 25 28 == 0                  = HalfWordDataR
  | mask w 4 5 == 1 && mask w 7 12 > 1
    && mask w 25 28 == 0                  = HalfWordDataI
  | mask w 26 28 == 1                     = SingDataTrans
  | mask w 25 28 == 3 && mask w 4 5 == 1  = Undef
  | mask w 25 28 == 4                     = BlockDataTrans
  | mask w 25 28 == 5                     = Branch
  | mask w 25 28 == 6                     = CoprocDataTrans
  | mask w 24 28 == 14 && mask w 4 5 == 0 = CoprocDataOp
  | mask w 24 28 == 14 && mask w 4 5 == 1 = CoprocRegTrans
  | mask w 24 28 == 15                    = SWI
  | mask w 25 28 <= 1                     = DataProc  (en $ mask w 21 25)

  | otherwise = RAWDATA
\end{code}

The mnemonic types here will be developed in a fashion analogous to their counterparts in the Thumb16.lhs module. 

\begin{code}

data DPMnemonic = AND
              | EOR
              | SUB
              | RSB
              | ADD
              | ADC
              | SBC
              | RSC
              | TST
              | TEQ
              | CMP
              | CMN
              | ORR
              | MOV
              | BIC
              | MVN
              | PLACEHOLDER deriving (Enum, Eq, Show)


\end{code}

\section{Extracting Instruction Information}

The functions defined in this section are concerned with
extracting information from machine code instructions --
what registers do they read from and write to? What operations
do they perform? and so on. The information is emitted not,
primarily, as human-readable text, but as haskell functions
and data structures.

\subsection{Layout}
The first thing we need to know about an ARM instruction is
its `layout', or instruction type. This will tell us which bits
we need to look at for the rest of the information we're after.
\subsection{Conditional Field}

Each ARM instruction has a conditional execution field, which
determines the circumstances -- the state of the flags
%% NB: it's not called "flags", look this up
register -- under which it will execute.
%% bit more on what this looks like in assembly. This field
is, conveniently, located in the same place in every layout.

\begin{code}
whatCond :: Word32 -> Cond
whatCond w =
  toEnum (fromIntegral $ mask w 28 32)
\end{code}

\subsection{Source and Destination Registers}


\begin{code}
srcRegs :: Word32 -> [Int]
srcRegs w = map fromIntegral $ case (whatLayout w) of
  DataProc _      -> [mask w 16 20]
  Mult            -> [mask w 12 16]
  MultLong        -> [mask w 8 12, mask w 0 4] -- check
  SingDataSwap    -> [mask w 16 20, mask w 0 4]
  BranchExch      -> [mask w 0 4]
  HalfWordDataI   -> [mask w 16 20]
  HalfWordDataR   -> [mask w 0 4, mask w 12 16]
  SingDataTrans   -> [mask w 16 20]
  Undef           -> []
  BlockDataTrans  -> if (testBit w 20)
                     then [mask w 16 20]
                     else m_block_data_regs w
  Branch          -> []
  CoprocDataTrans -> []
  CoprocDataOp    -> []
  CoprocRegTrans  -> [mask w 12 16]
  SWI             -> []
  RAWDATA         -> []
--  otherwise       -> error $ "Not yet implemented: 0x" ++ showHex w ""

dstRegs :: Word32 -> [Int]
dstRegs w = map fromIntegral $ case (whatLayout w) of
  DataProc _      -> [mask w 12 16]
  Mult            -> [mask w 16 20]
  MultLong        -> [mask w 12 16, mask w 16 20]
  SingDataSwap    -> [mask w 12 16]
  BranchExch      -> []
  HalfWordDataI   -> [mask w 12 16]
  HalfWordDataR   -> [mask w 12 16]
  SingDataTrans   -> [mask w 12 16]
  Undef           -> []
  BlockDataTrans  -> if (testBit w 20)
                     then m_block_data_regs w
                     else [mask w 16 20]
  Branch          -> []
  CoprocDataTrans -> []
  CoprocDataOp    -> []
  CoprocRegTrans  -> [mask w 12 16]
  SWI             -> []
  RAWDATA         -> []
--  otherwise       -> error $ "Not yet implemented: " ++ showHex w "\nGet back to work!"
\end{code}

\subsection{Operations}

Here, we will extract the actual operation that the instruction
is performing, and store it as a live haskell function.
Operations will be defined as a function of three 32-bit words
to a fourth 32-bit word.

$$ \lambda \texttt{operand_1} \texttt{operand_2} \texttt{destination} . \textit{result} $$

The reason for including the value of the destination register
in the signature is so that we can handle identity operations,
without changing type. (Some ARM instructions -- \text{CMP} for
instance -- do not alter the destination registers in any way, but
are peformed only to update the status or flag register.) %
\footnote{I have not yet implemented the flag registers or
conditional execution, in this model.}

\begin{code}

-- we could return a pair of Word32 values to capture the flags register
-- or we could simplify things by just ignoring the flags for now.
operation :: Word32 -> Operation
operation w = case (whatLayout w) of
  DataProc m  -> opDP m
  Mult        -> opM
  MultLong    -> opM
  otherwise   -> error $ "Not yet implemented: 0x" ++ showHex w "\nBACK TO WORK!"
  where --t = whatLayout w
    opDP :: DPMnemonic -> Operation
    opDP mnemonic = case mnemonic of
        -- ternary: op1, op2, dst; dst ignored in most
      AND ->  \a x y _ -> (a, x .&. y)
      EOR ->  \a x y _ -> (a, xor x y)
      SUB ->  \a x y _ -> (a, x - y)
      RSB ->  \a x y _ -> (a, flip (-) x y)
      ADD ->  \a x y _ -> (a, x + y)
      ADC ->  \a x y _ -> (a, x + y) -- PLUS CARRY
      SBC ->  \a x y _ -> (a, x - y)-- PLUS CARRY - 1
      RSC -> \a x y _ -> (a, flip (-) x y) -- PLUS CARRY - 1
      TST -> \a _ _ z -> (a, z) -- SET FLAGS AS WITH AND
      TEQ -> \a _ _ z -> (a, z) -- SET FLAGS AS WITH EOR
      CMP -> \a _ _ z -> (a, z) -- SET FLAGS AS WITH SUB
      CMN -> \a _ _ z -> (a, z) -- SET FLAGS AS WITH ADD
      ORR -> \a x y _ -> (a, x .|. y)
      MOV -> \a _ y _ -> (a, y)
      BIC -> \a x y _ -> (a, x .&. (complement y))
      MVN -> \a _ y _ -> (a, complement y)
    opM :: Operation
    opM = \a x y _ -> (a, x * y)

-- TODO: get immediate operands. 
immediate :: Word32 -> Maybe Word32
immediate w =
  if (testBit w 25) then (Just $ mask w 0 12) else Nothing
 
    


m_block_data_regs :: Word32 -> [Word32]
m_block_data_regs w =
  let rg = mask w 0 16
  in colR rg 0
  where colR r n
          | n > 15       = []
          | r .&. 1 == 1 = n : colR (shiftR r 1) (n + 1)
          | otherwise    = colR (shiftR r 1) (n + 1)
\end{code}

\end{document}
