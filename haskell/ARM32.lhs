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

\begin{code}
-- {-# LANGUAGE BinaryLiterals #-}
module ARM32 where
import Data.Word
import Data.Bits
import Aux
-- ARM MODE --

popPCp :: Word32 -> Bool
popPCp inst = (inst .&. 0xFFFF0000 == 0xe8bd0000) -- is it a POP ?
               && ((inst .&. (shift 1 15)) /= 0)  -- does it pop into PC?


-- MASK CONSTANTS --
data InstType = DataProc | Mult | MultLong | SingDataSwap | BranchExch |
                HalfWordData | SingDataTrans | Undef | BlockDataTrans |
                Branch | CoprocDataTrans | CoprocDataOp | CoprocRegTrans |
                SWI deriving (Eq, Show)


whitemask = 0xFFFFFFFF :: Word32
blackmask = 0x00000000 :: Word32

--- remember to use fromIntegral to return more generic type in list
-- use guards to dispatch appropriate masking function.
destRegs :: Word32 -> InstType -> [Word32]
destRegs w t
  | t == DataProc = [m_dp_dstR w] 
  | otherwise = error "Not yet implemented"

-- returns bits [low..high] of word, high exclusive, low inclusive
mask :: Word32 -> Int -> Int -> Word32
mask word low high
  | low > high = error "Lower bound higher than upper bound"
  | otherwise = (`shiftR` low) bitmask .&. word
  where bitmask = complement (shiftL (shiftR whitemask high) high)

m_cond :: Word32 -> Word32
m_cond w = mask w 28 32

-- get operand 2 in data processing/PSR transfer insts
m_dp_op2 :: Word32 -> Word32
m_dp_op2 w = mask w 0 12

-- get the destination register in data processing/PSR insts
m_dp_dstR :: Word32 -> Word32
m_dp_dstR w = mask w 12 16



\end{code}
