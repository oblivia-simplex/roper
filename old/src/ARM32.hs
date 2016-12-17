
module ARM32 where

import Aux
import ARMCommon
import qualified Instruction as I
import Data.Word
import Data.Bits

import Numeric (showHex)

  -- | Moved to ARMCommon.lhs | --


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
  | BlockDataTrans BDTMnemonic
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
                                              (lpu w)
  | mask w 25 28 == 5                     = Branch
  | mask w 25 28 == 6                     = CoprocDataTrans
  | mask w 24 28 == 14 && mask w 4 5 == 0 = CoprocDataOp
  | mask w 24 28 == 14 && mask w 4 5 == 1 = CoprocRegTrans
  | mask w 24 28 == 15                    = SWI
  | mask w 25 28 <= 1                     = DataProc  (en $ mask w 21 25)

  | otherwise = RAWDATA

lpu :: Word32 -> BDTMnemonic 
lpu w = let idxs = [23, 24, 20]
            f :: Int -> Int
            f i  = fromIntegral $ 
                   if testBit w (idxs !! i) then bit i else 0 :: Word8
        in en $ sum $ map f [0, 1, 2]


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

--                                                 LPU
data BDTMnemonic = STMED -- post-decrement store | 000
                 | STMEA -- post-increment store | 001
                 | STMFD -- pre-decrement store  | 010
                 | STMFA -- pre-increment store  | 011
                 | LDMFA -- post-decrement load  | 100
                 | LDMFD -- post-increment load  | 101
                 | LDMEA -- pre-decrement load   | 110
                 | LDMED -- pre-increment load   | 111
                 deriving (Enum, Eq, Show)            


whatCond :: Word32 -> Cond
whatCond w =
  toEnum (fromIntegral $ mask w 28 32)

-- | Is the second operand in a dataproc instruction immediate?
dpOp2Imm :: Word32 -> Bool
dpOp2Imm = flip testBit 25

{- 
s1Regs :: Word32 -> [Int]
s1Regs w = case whatLayout' w of
  "datap" -> m 16 20
  "multi" -> m 0 4
  "multl" -> m 0 4 
  where m i j = map fromIntegral [mask w i j]


s2Regs :: Word32 -> [Int]
s2Regs w = case whatLayout' w of
  "datap" -> if testBit w 25 then m 0 12 else []
  "multi" -> m 8 12
  "multl" -> m 8 12
  where m i j = map fromIntegral [mask w i j]
  -}
-- | Get a list of source registers
srcRegs :: Word32 -> [Int]
srcRegs w = map fromIntegral $ case (whatLayout w) of
  DataProc _        -> [mask w 16 20]
  Mult              -> [mask w 12 16]
  MultLong          -> [mask w 8 12, mask w 0 4] -- check
  SingDataSwap      -> [mask w 16 20, mask w 0 4]
  BranchExch        -> [mask w 0 4]
  HalfWordDataI     -> [mask w 16 20]
  HalfWordDataR     -> [mask w 0 4, mask w 12 16]
  SingDataTrans     -> [mask w 16 20]
  Undef             -> []
  BlockDataTrans _  -> if (testBit w 20)
                       then [mask w 16 20]
                       else m_block_data_regs w
  Branch            -> []
  CoprocDataTrans   -> []
  CoprocDataOp      -> []
  CoprocRegTrans    -> [mask w 12 16]
  SWI               -> []
  RAWDATA           -> []
--  otherwise       -> error $ "Not yet implemented: 0x" ++ showHex w ""

op2Regs :: Word32 -> [Int]
op2Regs w = map fromIntegral $ case (whatLayout w) of
  DataProc _      -> if (dpOp2Imm w) then [] else [(mask w 0 4)]
-- TODO: Complete this, and incorporate it in instruction type

dstRegs :: Word32 -> [Int]
dstRegs w = map fromIntegral $ case (whatLayout w) of
  DataProc _       -> [mask w 12 16]
  Mult             -> [mask w 16 20]
  MultLong         -> [mask w 12 16, mask w 16 20]
  SingDataSwap     -> [mask w 12 16]
  BranchExch       -> []
  HalfWordDataI    -> [mask w 12 16]
  HalfWordDataR    -> [mask w 12 16]
  SingDataTrans    -> [mask w 12 16]
  Undef            -> []
  BlockDataTrans _ -> if (testBit w 20)
                     then m_block_data_regs w
                     else [mask w 16 20]
  Branch           -> []
  CoprocDataTrans  -> []
  CoprocDataOp     -> []
  CoprocRegTrans   -> [mask w 12 16]
  SWI              -> []
  RAWDATA          -> []
--  otherwise       -> error $ "Not yet implemented: " ++ showHex w "\nGet back to work!"

-- | break this down into op2immediate, etc. 
-- TODO: get immediate operands, if present. 
immediate :: Word32 -> Maybe Word32
immediate w =
  case (whatLayout w) of
    DataProc _ -> if (dpOp2Imm w) then (Just $ mask w 0 12) else Nothing
    otherwise  -> Nothing



mkShift :: Bits c => Int -> (c -> c)
mkShift i =
  case (mask i 1 3) of
    0 -> flip shiftL shiftVal
    1 -> flip shiftR shiftVal
    2 -> flip aShiftR shiftVal
    3 -> flip rotateR shiftVal
  where shiftVal = en $ if (testBit i 0)
                           then mask i 7 12
                           else 0 --mask i 8 12
                      -- | KLUGDE should be register value
                      -- this is an acceptable source of noise for now

{-
mkRot :: Bits c => Int -> (c -> c)
mkRot i = flip rotate i
-} 

-- | returns a shift operation
shifter :: (Bits c) => Word32 -> (c -> c)
shifter w = case whatLayout w of 
  DataProc _  -> if dpOp2Imm w
                 then flip rotate $ en (mask w 8 12)
                 else mkShift $ en (mask w 4 12)

-- we could return a pair of Word32 values to capture the flags register
-- or we could simplify things by just ignoring the flags for now.
operation :: Word32 -> I.Op Word32
operation w = case whatLayout w of
  DataProc m  -> opDP m
  Mult        -> (*)
  MultLong    -> (*)
  _           -> error $ "Not yet implemented: 0x" ++ showHex w "\nBACK TO WORK!"
  where --t = whatLayout w
    opDP :: DPMnemonic -> I.Op Word32
    opDP mnemonic = case mnemonic of
        -- ternary: op1, op2, dst; dst ignored in most
      AND ->  (.&.)
      EOR ->  xor
      SUB ->  (-)
      RSB ->  flip (-)
      ADD ->  (+)
      ADC ->  (+) -- PLUS CARRY
      SBC ->  (-) -- PLUS CARRY - 1
      RSC ->  flip (-) -- PLUS CARRY - 1
      TST ->  (.&.) -- SET FLAGS AS WITH AND
      TEQ ->  xor -- SET FLAGS AS WITH EOR
      CMP ->  (-)  -- SET FLAGS AS WITH SUB
      CMN ->  (+) -- SET FLAGS AS WITH ADD
      ORR ->  (.|.)
      MOV ->  curry snd  -- or fst?
      BIC ->  \x y -> x .&. complement y
      MVN ->  \x y -> complement y -- or fst/x?

  

-- if (whatLayout w == (DataProc _) && testBit w 25) then (Just $ mask w 0 12) else Nothing
 
    


m_block_data_regs :: Word32 -> [Word32]
m_block_data_regs w =
  let rg = mask w 0 16
  in colR rg 0
  where colR r n
          | n > 15       = []
          | r .&. 1 == 1 = n : colR (shiftR r 1) (n + 1)
          | otherwise    = colR (shiftR r 1) (n + 1)
