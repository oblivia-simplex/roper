
module Thumb16 where

import Aux        -- A grab bag of generally useful, mathematical functions.
import ARMCommon  -- The code that's shared between Thumb16 and ARM32 modules
import qualified Instruction as I
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


operation :: Word16 -> I.Op Word32
operation w = case whatLayout w of
  MoveShiftedRegister m  ->    let sh = fromIntegral (mask w 6 11)
                               in case m of
                                  M'LSL -> \y _ -> shiftR y sh 
                                  M'LSR -> \y _ -> shiftR y sh
                                  M'ASR -> \y _ -> aShiftR y sh
  ALU'Operations m        ->    case m of
                                 AND -> (.&.)
                                 EOR -> xor
                                 LSL -> \x y -> x `shiftL` en y
                                 LSR -> \x y -> x `shiftR` en y
                                 ASR -> \x y -> x `aShiftR` en y
                                 ADC -> (+)
                                 SBC -> (-)
                                 ROR -> \x y -> x `rotateR` en y
                                 TST -> (.&.)
                                 NEG -> \x y -> negate x
  Add'Subtract m i       ->    case m of
                                 ADD3 -> (+)
                                 SUB3 -> (-)

  MCAS'Immediate m val ->  let v :: Word32
                               v =  en val
                           in case m of
                           MOV8 -> curry fst
                           CMP8 -> (-)
                           ADD8 -> (+)
                           SUB8 -> (-)
  _                    ->    undefined


