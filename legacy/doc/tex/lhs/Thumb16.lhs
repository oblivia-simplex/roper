\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{amssymb}
\usepackage{amsmath}
\usepackage{listings}
\let\oldemptyset\emptyset
\let\emptyset\varnothing
\usepackage{parskip}
\usepackage{fancyvrb}

\title{Thumb Mode Grammar}
\author{Olivia Lucca Fraser\\B00109376}
\date{\today}

%include polycode.fmt

\begin{document}

%% Insert some stuff on the Thumb architecture
%% often stands alone
%% but more frequently occurs intertwined with ARM
%% optimizing for density etc
%% interest bc palimpsest for ROP

\section{Introduction to the Thumb-1 Instruction Set}

In this module, we will be dealing only with the Thumb-1 specification,
according to which all Thumb instructions are uniformly of 16 bits in length.
However, a Thumb-2 specification does now exist, and allows for a combination of 32 and 16 bit instructions. This is a conservative extension of Thumb-1, and I will develop it as a separate module. Once we have fixed the grammar for each, correctly parsing binary code as Thumb-2 should be a fairly simple matter: if a 4-byte pattern matches a Thumb-2 instruction, parse it as Thumb-2, and if not, fall
back to Thumb-1.

Most ARM platforms allow the programmer (or compiler) to alternate freely between ARM and Thumb mode, though certain processors, chiefly intended for use in embedded devices with limited memory resources, operate entirely in Thumb.

The operating mode of the processor -- Thumb or ARM -- is decided by a 1-bit flag in the Current Process Status Register (see ARMCommon.lhs for details). This bit can be flipped in one of several ways: a branch instruction that targets an odd-valued address (one whose least significant bit is 1) will switch to Thumb mode (and round off the last bit of the destination address), the BLX instruction in ARM mode will switch to Thumb mode after setting the PC to the target address (while its counterpart, the BLX instruction in Thumb mode, does the opposite), and, finally, the CSPR can be modified directly, using a special set of instructions.

\section{Format of the Thumb Instruction: Overview}

\begin{Verbatim}[fontsize=\scriptsize]
   15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
  +---+---+---+-------+-------------------+-----------+-----------+
1 | 0 | 0 | 0 |  Op   |   Offset5         |   Rs      |     Rd    | Move shifted register
2 | 0 | 0 | 0 | 1 | 1 | I | Op|  Rn/offs3 |   Rs      |     Rd    | Add/subtract
3 | 0 | 0 | 1 |  Op   |    Rd     |           Offset8             | Move/compare/add/subtract immediate
4 | 0 | 1 | 0 | 0 | 0 | 0 |       Op      |   Rs      |     Rd    | ALU operations
5 | 0 | 1 | 0 | 0 | 0 | 1 |   Op  | H1| H2|  Rs/Hs    |    Rd/Hd  | High register operations/branch exchange
6 | 0 | 1 | 0 | 0 | 1 |     Rd    |            Word8              | PC-relative load
7 | 0 | 1 | 0 | 1 | L | B | 0 |    Ro     |    Rb     |    Rd     | Load/store with register offset
8 | 0 | 1 | 0 | 1 | H | S | 1 |    Ro     |    Rb     |    Rd     | Load/store sign-extended byte/halfword
9 | 0 | 1 | 1 | B | L |   Offset5         |    Rb     |    Rd     | Load/store with immediate offset
10| 1 | 0 | 0 | 0 | L |   Offset5         |    Rb     |    Rd     | Load/store halfword
11| 1 | 0 | 0 | 1 | L |     Rd    |            Word8              | SP-relative load/store
12| 1 | 0 | 1 | 0 | SP|     Rd    |            Word8              | Load address
13| 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | S |          SWord7           | Add offset to stack pointer
14| 1 | 0 | 1 | 1 | L | 1 | 0 | R |            Rlist              | Push/pop registers
15| 1 | 1 | 0 | 0 | L |    Rb     |            Rlist              | Multiple load/store
16| 1 | 1 | 0 | 1 |     Cond      |            Soffset8           | Conditional branch
17| 1 | 1 | 0 | 1 | 1 | 1 | 1 | 1 |            Value8             | Software Interrupt
18| 1 | 1 | 1 | 0 | 0 |              Offset11                     | Unconditional branch
19| 1 | 1 | 1 | 1 | H |              Offset11                     | Long branch with link
  +---+---+---+---+---+-------------------------------------------+
    15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
\end{lstlisting}

\section{Imports}

The modules we'll need to import here are by now familiar, if you have already visited the ARM32.lhs or ARMCommon.lhs modules.

\begin{code}
module Thumb16 where

import Aux        -- A grab bag of generally useful, mathematical functions.
import ARMCommon  -- The code that's shared between Thumb16 and ARM32 modules

import Data.Word  -- standard module for working with fixed width ints
import Data.Bits  -- standard module for doing bitwise arithmetic
import Data.List  -- standard module for list manipulation

-- We'll refactor the parsing engine out to a separate module
-- import Control.Applicative
-- import qualified Data.List as L
-- import qualified Data.ByteString as B
-- import Data.Attoparsec.ByteString
-- import Data.Attoparsec.Binary
import Numeric (showHex)  -- for displaying hexidecimal numbers, for debugging
\end{code}

\section{Data Types for the Thumb Grammar}

Here's where we begin analysing the Thumb-1 grammar. Like the ARM instruction set, Thumb-1 uses a relatively small number of distinct layouts which tell us where to find each of the fields (source register, destination register, opcode, etc.) that we're interested in. 

Each layout is distinguished by an irregular signature of constant bits, which it will be the job of our \textt{whatLayout} function to match.

The Layout type is a compound, or what Haskellers call `algebraic`, data type, and each instance varies somewhat in the information it bundles together with the layout identifier. Typically, an opcode will be included in the form of an instance of an Enum type that, in most cases, resembles the usual assembler mnemonic. Sometimes, however, we need to make finer-grained distinctions than the assembler does, and so the mnemonics will often be tagged with suffixes to differentiate, for instance, the addition of 3-bit values or low registers (ADD3), the addition of 8-bit immediate values (ADD8), and addition of high registers (ADDh)). When an immediate value is embedded in the instruction, this may also be wrapped in the layout instance. Source and destination registers are handled separately, as lists of integers.

Once we have extracted the Mnemonic -- a sort of abstract representation of the logical operation the instruction performs, for which we define a handful of predicates to better classify them\footnote{See ARMCommon.lhs} -- we are able to assign a concrete operation to the instruction. This will be a 'live' Haskell function, with which we can perform computations in the Haskell environment. These will give us the ability to, in some minimal sense, virtualize the ARM operations, without needing to run a full emulation, while being able to manipulate them with any higher-order functions we choose. This will give us enough insight into the code -- and the gadgets extracted from that code -- to be able to regiment it as a compiler might, and search for combinations of gadgets that satisfy (perhaps to some degree of approximation) a given, specified function.

The Instruction record type -- the Haskell counterpart to C's structs -- will bring all this together: source list, destination list, layout instance (with mnemonic, preserved for human readability), and effective operation. These will be the units of which gadgets, and by extension ROP-chains, are composed.

\begin{code}

data Layout =
  MoveShiftedRegister MSR'Mnemonic
  | Add'Subtract AS'Mnemonic Bool   -- True if immediate value, False if reg
  | MCAS'Immediate MCASI'Mnemonic Word8
  | ALU'Operations ALU'Mnemonic
  | HighRegOp'BX HROBX'Mnemonic
  | PCRelativeLoad
  | Load'StoreRegisterOffset
  | Load'StoreSignExtendedByte'Halfword
  | Load'StoreImmediateOffset
  | Load'StoreHalfword
  | SPRelativeLoad'Store
  | LoadAddress
  | AddOffsetToStackPointer
  | Push'PopRegisters
  | MultipleLoad'Store
  | ConditionalBranch
  | SoftwareInterrupt
  | UnconditionalBranch
  | LongBranchWithLink
  | RAWDATA deriving (Eq, Show)
instance Format Layout

data MSR'Mnemonic =
  M'LSL
  | M'LSR
  | M'ASR deriving (Show, Enum, Eq)
instance Mnemonic MSR'Mnemonic

data AS'Mnemonic =
  ADD3
  | SUB3 deriving (Show, Enum, Eq)
instance Mnemonic AS'Mnemonic where
  additive ADD3 = True   -- example of mnemonic predicates
  additive SUB3 = False

data ALU'Mnemonic =
  AND
  | EOR
  | LSL
  | LSR
  | ASR
  | ADC
  | SBC
  | ROR
  | TST
  | NEG deriving (Show, Enum, Eq)
instance Mnemonic ALU'Mnemonic where
  additive ADC = True
  additive _   = False
  writeR   TST = False
  setCPSR  _   = True

data MCASI'Mnemonic =
   MOV8
   | CMP8
   | ADD8
   | SUB8 deriving (Show, Enum, Eq)
instance Mnemonic MCASI'Mnemonic where
  additive ADD8 = True
  additive _    = False
  writeR   CMP8 = False   -- comparison ops don't write to destination register
  setCPSR  _    = True

-- Mnemonics for High Register Operations / Branch Exchange instructions
data HROBX'Mnemonic =
  ADDh
  | CMPh
  | MOVh
  | BXh deriving (Show, Enum, Eq)
instance Mnemonic HROBX'Mnemonic where
  additive ADDh = True
  additive _    = False
  writeR   CMPh = False
  setCPSR  CMPh = True
  ctrlFlow BXh  = True

-- As I piece-by-piece implement the different operations associated
-- with each layout, I'll add the required fields to each Layout type entry
whatLayout :: Word16 -> Layout
whatLayout w
  | mask w 8 16  == 0xDF = SoftwareInterrupt
  | mask w 8 16  == 0xB0 = AddOffsetToStackPointer
  | mask w 10 16 == 0x08 = ALU'Operations (en $ mask w 6 10)
  | mask w 10 16 == 0x09 = HighRegOp'BX (en $ mask w 8 10)
  | mask w 11 16 == 0x03 = Add'Subtract (en $ testBit w 9) (testBit w 10)
  | mask w 13 16 == 0x00 = MoveShiftedRegister (en $ mask w 11 13)
  | mask w 13 16 == 0x01 = MCAS'Immediate (en $ mask w 11 13) $ en $ mask w 0 8
  | mask w 11 16 == 0x09 = PCRelativeLoad
  | (mask w 12 16 == 0x05) && (testBit w 9) = Load'StoreSignExtendedByte'Halfword
  | (mask w 12 16 == 0x05) && (not $ testBit w 9) = Load'StoreRegisterOffset
  | mask w 13 16 == 0x03 = Load'StoreImmediateOffset
  | mask w 12 16 == 0x08 = Load'StoreHalfword
  | mask w 12 16 == 0x09 = SPRelativeLoad'Store
  | mask w 12 16 == 0x0A = LoadAddress
  | (mask w 12 16 == 0x0B) && (mask w 9 11 == 0x02) = Push'PopRegisters
  | mask w 12 16 == 0x0C = MultipleLoad'Store
  | mask w 12 16 == 0x0D = ConditionalBranch
  | mask w 11 16 == 0x1C = UnconditionalBranch
  | mask w 12 16 == 0x0F = LongBranchWithLink
  | otherwise = RAWDATA

\end{code}

\section{Source and Destination Registers}

The following functions will, on the basis of the layout, extract lists of the source and destination registers used by each instruction. Certain instructions in both Thumb and ARM mode have the capacity to read or write from multiple registers at once -- the POP instruction, in Thumb, for instance, and the load and store instructions (LDMI, LDME, STMI, STME) in ARM, have this feature. For this reason, and to avoid unnecessary complexity, we use the [Int] (list of integers) type for source and destination registers, uniformly.


\begin{code}

srcRegs :: Word16 -> [Int]
srcRegs w = map fromIntegral $ case (whatLayout w) of
  MoveShiftedRegister _        ->    [mask w 3 6]
  Add'Subtract        _  False ->    [mask w 3 6, mask w 6 9]
  Add'Subtract        _  True  ->    [mask w 3 6]
  ALU'Operations      _        ->    [mask w 3 6]
  MCAS'Immediate      _   _    ->    []
  HighRegOp'BX        _        ->    [(mask w 3 6) `shiftL`
                                      ((en $ testBit w 6) * 3)]
  otherwise -> []

dstRegs :: Word16 -> [Int]
dstRegs w = map fromIntegral $ case (whatLayout w) of
  MoveShiftedRegister    _     ->    [mask w 0 3]
  Add'Subtract           _  _  ->    [mask w 0 3]
  ALU'Operations         m     -> if (writeR m) then [mask w 0 3] else []
  MCAS'Immediate         m  _  -> if (writeR m) then [mask w 8 11] else []
  HighRegOp'BX           _     ->    [(mask w 0 3) `shiftL`
                                      ((en $ testBit w 6) * 3)]
  otherwise -> []

\end{code}

\section{Extracting the Operation}

One particularly useful (even fundamental) feature of functional programming languages like Haskell is the facility with which they allow the programmer to manipulate functions as 'first class citizens' of the language. We take advantage of this here by decoding the operation that each instruction performs and storing it as live function, which can be used natively in a Haskell environment. These functions each have a peculiar signature, however, which is documented in ARMCommon.lhs, and which sets them apart from garden variety primitives like $+$, $-$, and so on. In the interest of simplifying things, for the compiler, at least, if not for us humans, each operation shares the same, uniform signature: it takes three Wor32 arguments (operand1, operand2, destination register), and returns a pair that contains the CPSR and the value to be written to the destination register. 

\begin{code}
operation :: Word16 -> Operation
operation w = case (whatLayout w) of
  MoveShiftedRegister m  ->    let sh = (fromIntegral (mask w 6 11))
                               in case m of
                                  M'LSL -> \c s _ _ -> (c, (shiftL s sh))
                                  M'LSR -> \c s _ _ -> (c, (shiftR s sh))
                                  M'ASR -> \c s _ _ -> (c, (aShiftR s sh))
  ALU'Operations m        ->    case m of
                                 AND -> op' (.&.) True
                                 EOR -> op' xor True
                                 LSL -> op' shiftL True
                                 LSR -> op' shiftR True
                                 ASR -> op' aShiftR True
                                 ADC -> cOp ADC
                                 SBC -> cOp SBC
                                 ROR -> op' rotateR True
                                 TST -> op' (.&.) False
                                 NEG -> op' (\_ s -> negate s) True
  Add'Subtract m i       ->    case m of
                                 ADD3 -> cOp ADD3
                                 SUB3 -> cOp SUB3

  MCAS'Immediate m val ->  let v :: Word32
                               v =  en val
                           in case m of
                           MOV8 -> \_ _ _ _ -> (aspr $ setNZFlags v
                                                ,v)
                           CMP8 -> \c d s n -> (op' (-) False) c d v d
                           ADD8 -> \c d s n -> (cOp ADD8) c d v d
                           SUB8 -> \c d s n -> (cOp SUB8) c d v d
  otherwise              ->    undefined
  where
    op' :: (Int -> Int -> Int) -> Bool -> Operation
    op' oper effective =
      \c d s n -> let res  = fromIntegral $ (fromIntegral n)
                             `oper` (fromIntegral s)
                      flgs = setNZFlags res
                  in ((aspr flgs), if effective then res else d)
    cOp :: Mnemonic a => a -> Operation
    cOp m =
      \c d s n -> let res64  :: Word64
                      res32  :: Word32
                      opA    :: (Num a, Bits a) => a -> a -> a
                      opA    = (if (additive m) then (+) else (-))
                      res64  = (fromIntegral n) `opA` (fromIntegral s)
                               `opA` (if (testFlag c Cflag) then 1 else 0)
                      res32  = fromIntegral res64
                      flgs   = setNZFlags 32
                               ++ (if (shiftR res32 32 > 0) then [Cflag] else [])
                               ++ (if (overflow s d res32)  then [Vflag] else [])
                  in ((aspr flgs), res32)


\end{code}
