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
import Data.Word
import Data.Bits

import Control.Applicative
import qualified Data.List as L
import qualified Data.ByteString as B
import Data.Attoparsec.ByteString
import Data.Attoparsec.Binary

import Numeric (showHex)
\end{code}


\section{Data Types}

Here we introduce a few data types that we'll be using to
organize the information we extract from each ARM instruction.

\begin{code}
sp = 13 :: Int
lr = 14 :: Int
pc = 15 :: Int

data Layout = DataProc | Mult | MultLong | SingDataSwap
              | BranchExch | HalfWordDataI | HalfWordDataR
              | SingDataTrans | Undef | BlockDataTrans | Branch
              | CoprocDataTrans | CoprocDataOp | CoprocRegTrans
              | SWI | RAWDATA deriving (Eq, Show)

data Cond = C_EQ | C_NE | C_CS | C_CC | C_MI | C_PL | C_VS | C_VC |
            C_HI | C_LS | C_GE | C_LT | C_GT | C_LE | C_AL |
            C_RESERVED deriving (Show, Enum)

type APSR = Word32
type Operand = Word32
type DstRegister = Word32
type Operation = (APSR -> Operand -> Operand -> DstRegister
                 -> (APSR, DstRegister))


data Inst = Inst {
   iRaw  :: Word32
  ,iLay  :: Layout
  ,iSrc  :: [Int]
  ,iDst  :: [Int]
  ,iCnd  :: Cond
  ,iOpC  :: Mnemonic
  ,iOp   :: Operation
  }

instance Eq Inst where
  x == y  =  ((iRaw x) == (iRaw y))

instance Show Inst where
  show x  = "0x" ++ (showHex (iRaw x) ": ") ++ (show $ iOpC x)
            ++ " " ++ (stringy iSrc) ++ " ->" ++ (stringy iDst)
            ++ "  (" ++ (show $ iLay x) ++ ")" ++ "\n"
    where stringy field =
            (foldl (\a b -> a ++ " " ++ b) [] (fmap show $ field x))
-- Some mnemonics we'll be using for DataProc instructions.
-- Note that a different system will be needed for the
-- other layouts.
data Mnemonic = AND
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

ARM defines fifteen different layouts, each of which can be
recognized by its own signature pattern of high and low bits.
There is not, however, a generic `layout' field in the
instruction, and so several different masks -- each isolating
different bitfields -- may need to be applied to an instruction
before we can decipher its layout. For this we will be using the
\texttt{mask} function defined in Aux.hs.

\begin{code}
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
  | mask w 25 28 <= 1                     = DataProc
  | otherwise = RAWDATA
--  | otherwise = error $ "Not yet implemented: " ++
--                (printf "%08x\n*** " w) ++ (binStr w)
\end{code}

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
srcRegs :: Word32 -> Layout -> [Int]
srcRegs w t = map fromIntegral $ sr w t
  where sr w t
          | DataProc == t        = [mask w 16 20]
          | Mult == t            = [mask w 12 16]
          | MultLong == t        = [mask w 8 12, mask w 0 4] -- check
          | SingDataSwap == t    = [mask w 16 20, mask w 0 4]
          | BranchExch == t      = [mask w 0 4]
          | HalfWordDataI == t   = [mask w 16 20]
          | HalfWordDataR == t   = [mask w 0 4, mask w 12 16]
          | SingDataTrans == t   = [mask w 16 20]
          | Undef == t           = []
          | BlockDataTrans == t &&
            testBit w 20         = [mask w 16 20]
          | BlockDataTrans == t &&
            (not $ testBit w 20) = m_block_data_regs w
          | Branch == t          = []
          | CoprocDataTrans == t = []
          | CoprocDataOp == t    = []
          | CoprocRegTrans == t  = [mask w 12 16]
          | SWI == t             = []
          | RAWDATA == t          = []
          | otherwise            = error $ "Not yet implemented: "
                                   ++ show t

dstRegs :: Word32 -> Layout -> [Int]
dstRegs w t = map fromIntegral $ dr w t
  where dr w t
          | DataProc == t        = [mask w 12 16]
          | Mult == t            = [mask w 16 20]
          | MultLong == t        = [mask w 12 16, mask w 16 20]
          | SingDataSwap == t    = [mask w 12 16]
          | BranchExch == t      = []
          | HalfWordDataI == t   = [mask w 12 16]
          | HalfWordDataR == t   = [mask w 12 16]
          | SingDataTrans == t   = [mask w 12 16]
          | Undef == t           = []
          | BlockDataTrans == t &&
            testBit w 20         = m_block_data_regs w
          | BlockDataTrans == t &&
            (not $ testBit w 20) = [mask w 16 20]
          | Branch == t          = []
          | CoprocDataTrans == t = []
          | CoprocDataOp == t    = []
          | CoprocRegTrans == t  = [mask w 12 16]
          | SWI == t             = []
          | RAWDATA == t         = []
          | otherwise            = error $ "Not yet implemented: "
                                   ++ show t
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

getMnemonic :: Word32 -> Layout -> Mnemonic
getMnemonic w t
  | DataProc == t   =   toEnum $ fromEnum $ mask w 21 25
  | Mult     == t   =   PLACEHOLDER
  | MultLong == t   =   PLACEHOLDER
  | otherwise       =   PLACEHOLDER

-- we could return a pair of Word32 values to capture the flags register
-- or we could simplify things by just ignoring the flags for now.
operation :: Word32 -> Layout -> Operation
operation w t
  | DataProc == t        = opDP $ getMnemonic w t
  | Mult == t            = opM
  | MultLong == t        = opM
  | otherwise            = error $ "Not yet implemented: " ++ show t
  where --t = whatLayout w
        opDP :: Mnemonic -> Operation
        opDP mnemonic
        -- ternary: op1, op2, dst; dst ignored in most
          | mnemonic == AND = \a x y _ -> (a, x .&. y)
          | mnemonic == EOR = \a x y _ -> (a, xor x y)
          | mnemonic == SUB = \a x y _ -> (a, x - y)
          | mnemonic == RSB = \a x y _ -> (a, flip (-) x y)
          | mnemonic == ADD = \a x y _ -> (a, x + y)
          | mnemonic == ADC = \a x y _ -> (a, x + y) -- PLUS CARRY
          | mnemonic == SBC = \a x y _ -> (a, x - y)-- PLUS CARRY - 1
          | mnemonic == RSC = \a x y _ -> (a, flip (-) x y) -- PLUS CARRY - 1
          | mnemonic == TST = \a _ _ z -> (a, z) -- SET FLAGS AS WITH AND
          | mnemonic == TEQ = \a _ _ z -> (a, z) -- SET FLAGS AS WITH EOR
          | mnemonic == CMP = \a _ _ z -> (a, z) -- SET FLAGS AS WITH SUB
          | mnemonic == CMN = \a _ _ z -> (a, z) -- SET FLAGS AS WITH ADD
          | mnemonic == ORR = \a x y _ -> (a, x .|. y)
          | mnemonic == MOV = \a _ y _ -> (a, y)
          | mnemonic == BIC = \a x y _ -> (a, x .&. (complement y))
          | mnemonic == MVN = \a _ y _ -> (a, complement y)
        opM :: Operation
        opM = \a x y _ -> (a, x * y)

-- a composition function for operation types
-- they will look like little bird heads
-- left compose

-- KLUDGE: I feel like these functions could be
-- written more elegantly. 

-- | carry over the APSR from the first op to the
-- | second, and take the dst reg of the first op
-- | as the x (first operand) of the second op
(@<) :: Operation -> Operation -> Operation
op2 @< op1 = compL
  where compL a1 x y d = (op2 a2 d2 y d)
          where (a2, d2) = op1 a1 x y d

-- | carry over the APSR from the first op to the
-- | second, and take the dst reg of the first op
-- | as y (second operand) for the second op
(@>) :: Operation -> Operation -> Operation
op2 @> op1 = compR
  where compR a1 x y d = (op2 a2 x d2 d)
          where (a2, d2) = op1 a1 x y d

-- | carry over the APSR from the first op to the
-- | second, and take the dst reg of the first op
-- | as x and y for the second op
(@<>) :: Operation -> Operation -> Operation
op2 @<> op1 = comp
  where comp a1 x y d = (op2 a2 d2 d2 d)
          where (a2, d2) = op1 a1 x y d

-- It would probably make sense to define a state monad or
-- applicative that carries the APSR information across the
-- operations, and lets us use them as ordinary binary ops.
-- Learning how to do this is on the TODO list.

-- you could also maintain the entire cpu context as a
-- state monad's state. But that's getting a bit heavy handed,
-- and we have an emulator for that. 


-- Now, we need to actually fill in the Operand 1, Operand 2, Dst
-- fields. Maybe this information should be stowed up in the
-- inst record, for easy access. Or perhaps called from an
-- "apply operation" function that populates the operand fields
-- and executes the operation function.
op1 :: Word32 -> Word32
op1 w = mask w 16 20
 
op2 :: Word32 -> Word32
op2 w = mask w 0 12

imOp2 :: Word32 -> Bool
imOp2 w = testBit w 25

-- returns bits [low..high] of word, high exclusive, low inclusive

m_block_data_regs :: Word32 -> [Word32]
m_block_data_regs w =
  let rg = mask w 0 16
  in colR rg 0
  where colR r n
          | n > 15       = []
          | r .&. 1 == 1 = n : colR (shiftR r 1) (n + 1)
          | otherwise    = colR (shiftR r 1) (n + 1)
\end{code}

You'll also want to keep track of how far each gadget moves
the stack pointer.

\begin{code}

altSP :: Word32 -> Bool
altSP w =
  let t = whatLayout w in
  sp `elem` dstRegs w t || (bang w)

bang :: Word32 -> Bool
bang _ = False
-- placeholder. Return True if ! in load or store instruction

-- the tricky, but not difficult, part of spD is basically a
-- mini-decompiler: take an assembly instruction, and return
-- an "equivalent" haskell function.


\end{code}

The spD of an instruction cannot always be expressed as a constant.
It is, more generally, expressible as a function.
This is not a serious limitation.

\section{Parser}

Here's where we do the actual parsing. Since machine code has no real
grammar to speak of, beyond the layout structure that we've already
written several functions to pull apart, this part is almost trivial:

\begin{code}

-- Some helper functions that we can use to quickly switch endianness,
-- without needing to fuss with the layout-destructuring functions above:
data Endian = Big | Little
endian = Little

anyWord16 = case endian of
  Big    -> anyWord16be
  Little -> anyWord16le

anyWord32 = case endian of
  Big    -> anyWord32be
  Little -> anyWord32le

anyWord64 = case endian of
  Big    -> anyWord64be
  Little -> anyWord64le

-- The instruction parser, itself
inst :: Parser Inst
inst = do
  w <- anyWord32
  let t = whatLayout w
  pure $ Inst {
     iRaw = w
    ,iLay = t
    ,iSrc = srcRegs w t
    ,iDst = dstRegs w t
    ,iCnd = whatCond w
    ,iOp  = operation w t
    ,iOpC = getMnemonic w t
    }

-- And a parser that just repeatedly applies the instruction parser
-- until we are out of input.
-- Note that we could, perhaps, handle switching between Thumb and
-- ARM mode here, and distinguishing between data and code. But this
-- would require quite a bit more complexity.
instructions :: Parser [Inst]
instructions = do
  s <- many inst
  pure s
\end{code}

\section{Testing functions}

\begin{code}

-- the text section of an ARM Elf binary, extracted with dd
-- just to tide us over until the Elf header parser is written
textpath = "/home/oblivia/Projects/roper-stack/bins/arm/ldconfig.text"

main :: IO ()
main = do
  text   <- B.readFile textpath
  let parsed = parseOnly instructions $ B.take 0x200 text
  print parsed

\end{code}
