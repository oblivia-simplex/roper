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
-- {-# LANGUAGE BinaryLiterals #-}
module ARM32 where
import Data.Word
import Data.Bits
import Text.Printf
import Aux
-- ARM MODE --

popPCp :: Word32 -> Bool
popPCp inst = (inst .&. 0xFFFF0000 == 0xe8bd0000) -- is it a POP ?
               && ((inst .&. (shift 1 15)) /= 0)  -- does it pop into PC?

data Layout = DataProc | Mult | MultLong | SingDataSwap
              | BranchExch | HalfWordDataI | HalfWordDataR
              | SingDataTrans | Undef | BlockDataTrans | Branch
              | CoprocDataTrans | CoprocDataOp | CoprocRegTrans | UNSURE
              | SWI deriving (Eq, Show)

data Cond = C_EQ | C_NE | C_CS | C_CC | C_MI | C_PL | C_VS | C_VC |
            C_HI | C_LS | C_GE | C_LT | C_GT | C_LE | C_AL |
            C_RESERVED deriving (Show, Enum)

-- Write some tests for this one. There's a lot of room for error.
whatLayout :: Word32 -> Layout
whatLayout w
  | mask w 25 28 == 1                     = DataProc
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
  | otherwise = UNSURE
--  | otherwise = error $ "Not yet implemented: " ++
--                (printf "%08x\n*** " w) ++ (binStr w)

whatCond :: Word32 -> Cond
whatCond w =
  toEnum (fromIntegral $ mask w 28 32)

srcRegs :: Bool -> Word32 -> [Word32]
srcRegs d w
  | DataProc == t        = [mask w 16 20]
  | Mult == t            = [mask w 12 16]
  | MultLong == t        = [mask w 8 12, mask w 0 4] -- check
  | SingDataSwap == t    = ifd [mask w 16 20, mask w 0 4]
  | BranchExch == t      = ifd [mask w 0 4]
  | HalfWordDataI == t   = ifd [mask w 16 20]
  | HalfWordDataR == t   = ifd [mask w 0 4, mask w 12 16]
  | SingDataTrans == t   = ifd [mask w 16 20]
  | Undef == t           = []
  | BlockDataTrans == t &&
    testBit w 20         = ifd [mask w 16 20]
  | BlockDataTrans == t &&
    (not $ testBit w 20) = ifd $ m_block_data_regs w
  | Branch == t          = []
  | CoprocDataTrans == t = []
  | CoprocDataOp == t    = []
  | CoprocRegTrans == t  = ifd [mask w 12 16]
  | SWI == t             = []
  | UNSURE == t          = []
  | otherwise            = error $ "Not yet implemented: "  ++ show t
  where t = whatLayout w
        ifd lst = if d then lst else []

dstRegs :: Bool -> Word32 -> [Word32]
dstRegs d w
  | DataProc == t        = [mask w 12 16]
  | Mult == t            = [mask w 16 20]
  | MultLong == t        = [mask w 12 16, mask w 16 20]
  | SingDataSwap == t    = ifd [mask w 12 16]
  | BranchExch == t      = []
  | HalfWordDataI == t   = ifd [mask w 12 16]
  | HalfWordDataR == t   = ifd [mask w 12 16]
  | SingDataTrans == t   = ifd [mask w 12 16]
  | Undef == t           = []
  | BlockDataTrans == t &&
    testBit w 20         = ifd $ m_block_data_regs w
  | BlockDataTrans == t &&
    (not $ testBit w 20) = ifd [mask w 16 20]
  | Branch == t          = []
  | CoprocDataTrans == t = []
  | CoprocDataOp == t    = []
  | CoprocRegTrans == t  = ifd [mask w 12 16]
  | SWI == t             = []
  | UNSURE == t          = []
  | otherwise            = error $ "Not yet implemented: "  ++ show t
  where t = whatLayout w
        ifd lst = if d then lst else []

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
