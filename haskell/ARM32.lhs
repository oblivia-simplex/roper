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
                Branch | CoprocDataTrans | CoprocDataOp | CoprocRegTrans | SWI


wordsize  = 32
whitemask = 0xFFFFFFFF :: Word32
blackmask = 0x00000000 :: Word32
-- MASKING FUNCTIONS --

-- returns bits [low..high] of word, inclusive
-- (consider making exclusive by incrementing high)
mask :: Word32 -> Int -> Int -> Word32
mask word low high =
  let lowmask  = shiftL whitemask low
      highmask = shiftR whitemask high
  in word .&. lowmask .&. highmask

m_cond :: Word32 -> Word32
m_cond w = mask w 28 31

-- get operand 2 in data processing/PSR transfer insts
m_dp_op2 :: Word32 -> Word32
m_dp_op2 w = mask w 0 11



\end{code}
