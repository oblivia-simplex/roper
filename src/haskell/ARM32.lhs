|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|
                _______
 __ _ _ _ _ __ |__ /_  )
/ _` | '_| '  \ |_ \/ /
\__,_|_| |_|_|_|___/___|

|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|

All of the ARM-specific code should go into this module, as far as
possible, though shortcuts might be taken in the early stages of dev-
elopment.

Things that need doing:
- functions to classify instructions by type and effects

* It would be handy to skip the conversion to Word32 format...


\begin{code}
module ARM32 where
import Data.Word
import Data.Bits
import Aux
-- ARM MODE --

popPCp :: Word32 -> Bool
popPCp inst = (inst .&. 0xFFFF0000 == 0xe8bd0000) -- is it a POP ?
               && ((inst .&. (shift 1 15)) /= 0)  -- does it pop into PC?

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

type Operation = (Word32 -> Word32 -> Word32 -> Word32)

-- Write some tests for this one. There's a lot of room for error.
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

whatCond :: Word32 -> Cond
whatCond w =
  toEnum (fromIntegral $ mask w 28 32)

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
          | otherwise            = error $ "Not yet implemented: "  ++ show t
--          where t = whatLayout w

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
          | otherwise            = error $ "Not yet implemented: "  ++ show t
--          where t = whatLayout w

-- we could return a pair of Word32 values to capture the flags register
-- or we could simplify things by just ignoring the flags for now.
operation :: Word32 -> Layout -> Operation
operation w t
  | DataProc == t        = opDP $ mask w 21 25
  | Mult == t            = opM
  | MultLong == t        = opM
  | otherwise            = error $ "Not yet implemented: " ++ show t
  where --t = whatLayout w
        opDP :: Word32 -> Operation
        opDP opcode
        -- ternary: op1, op2, dst; dst ignored in most
          | opcode == and = \x y _ -> x .&. y
          | opcode == eor = \x y _ -> xor x y
          | opcode == sub = \x y _ -> x - y
          | opcode == rsb = \x y _ -> flip (-) x y
          | opcode == add = \x y _ -> x + y
          | opcode == adc = \x y _ -> x + y -- PLUS CARRY. HOW?
          | opcode == sbc = \x y _ -> x - y -- PLUS CARRY - 1
          | opcode == rsc = \x y _ -> flip (-) x y -- PLUS CARRY - 1
          | opcode == tst = \_ _ z -> z -- SET FLAGS AS WITH AND
          | opcode == teq = \_ _ z -> z -- SET FLAGS AS WITH EOR
          | opcode == cmp = \_ _ z -> z -- SET FLAGS AS WITH SUB
          | opcode == cmn = \_ _ z -> z -- SET FLAGS AS WITH ADD
          | opcode == orr = \x y _ -> x .|. y
          | opcode == mov = \_ y _ -> y
          | opcode == bic = \x y _ -> x .&. (complement y)
          | opcode == mvn = \_ y _ -> complement y
          where and = 0;  eor = 1
                sub = 2;  rsb = 3
                add = 4;  adc = 5
                sbc = 6;  rsc = 7
                tst = 8;  teq = 9
                cmp = 10; cmn = 11
                orr = 12; mov = 13
                bic = 14; mvn = 15
        opM :: Operation
        opM = \x y _ -> x * y

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

