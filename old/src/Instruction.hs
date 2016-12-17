-- | A Monad for Instructions
-- | Specifically, for DataProc instructions. 
-- | Or Mult instructions, I suppose.
module Instruction where

import Control.Monad
import Control.Applicative
import Data.Word
import Data.Bits
import Data.Maybe


data Mnemonic =
  ADD | SUB | M'LSL | M'LSR | M'ASR | ADD3 | SUB3 |
  EOR | AND | LSL | LSR | ASR | ADC | SBC | ROR | TST | NEG |
  MOV8 | CMP8 | ADD8 | SUB8 | ADDh | CMPh | MOVh | BXh |
  RSB | RSC | TEQ | CMN | ORR | MOV | BIC | MVN |
  STMED | STMEA | STMFD | STMFA | LDMFA | LDMEA |
  LDMED

  deriving (Show, Eq)-- and so on


type Flag = Int

data CPU w = CPU { reg :: [w]
                 , flg :: [Flag]
                 } deriving (Show, Eq)

type Op  w = w -> w -> w
type CPU32 = CPU Word32
type CPU16 = CPU Word16
type Op32  = Op Word32
type Op16  = Op Word16

type Layout = String

data Inst w = Inst { op  :: Op w
                   , lay :: Layout
                   , raw :: w
                   , rS1 :: [Int]
                   , rS2 :: [Int]
                   , rD  :: [Int] 
                   , imm :: Maybe w
                   , cnd :: [Flag] -- flags that must be up in order to execute
                   } 

type Inst32 = Inst Word32
type Inst16 = Inst Word16

--allIn :: (Eq a) => [a] -> [a] -> Bool
--allIn a b = all (`elem` b) a
-- some dummy values for testing
fop  = (+)
inst0 :: Inst Word32
inst0 = Inst { op  = fop
             , rS1 = [8]
             , rS2 = [2]
             , rD  = [8]
             , cnd = []
             , imm = Just 0xFF
             }
inst1 :: Inst Word32
inst1 = Inst { op  = (-)
             , rS1 = [0]
             , rS2 = [1]
             , rD  = [0]
             , cnd = []
             , imm = Nothing
             }

rS1' = head . rS1
rS2' = head . rS2
rD'  = head . rD

fcpu :: CPU32 
fcpu = CPU { reg = [15,14..0], flg = [] }

exec :: (Integral a, Bits a) => CPU a -> Inst a -> CPU a
exec cpu inst = 
   let rS1v = reg cpu !! rS1' inst
       rS2v = fromMaybe (reg cpu !! rS2' inst) (imm inst)
   in if all (`elem` flg cpu) (cnd inst) 
      then CPU { reg = let (x,_:xs) = splitAt (rD' inst) (reg cpu)
                       in x ++ [op inst rS1v rS2v] ++ xs
              
      --take (rD inst - 1) (reg cpu)
       --           ++ [op inst rS1v rS2v]
        --          ++ drop (rD inst) (reg cpu)
               , flg = [] -- PLACEHOLDER
               }
      else cpu         

execL :: (Integral a, Bits a) => CPU a -> [Inst a] -> CPU a
execL = foldl exec 
-- we could make the op type more complex so that it takes
-- flg as a parameter as well, and maybe a condition code.
test = execL fcpu [inst0, inst1]

