module Phylogen where

import Hatchery
import Gadget
import Data.Elf
import ElfHelper
import qualified Data.List as L
import ARM32
import ARMParser
import System.Random
import Control.Monad.Random
import Control.Applicative
import qualified Data.ByteString as BS
import Unicorn
import Data.Bits
import Aux

type Chain = [Gadget]
type Goal = ([Int], [Int])

goal :: Goal
goal = ([0, 1, 12], [100, 2, 0xdeadbeef])

distance :: Goal -> [Int] -> Int
distance (idxs,target) out = 
  let focus = map (out !!) idxs
  in  sum $ map abs $ zipWith (-) focus target

-- | some errors are our fault, some are the chains' fault.
-- | if the chain erred for reasons of its own -- trying to
-- | fetch an inaccessible address, e.g., then its fitness
-- | should reflect that
errorPenalty :: Int -> Int
errorPenalty err = case en err of
  ErrOk             -> 0
  ErrNomem          -> 0
  ErrReadUnmapped   -> major
  ErrWriteUnmapped  -> major
  ErrReadUnaligned  -> minor
  ErrWriteUnaligned -> minor
  ErrWriteProt      -> minor
  ErrReadProt       -> minor
  ErrFetchProt      -> minor
  ErrInsnInvalid    -> minor
  _                 -> 0
  where major = 0xFFFF
        minor = 0x1000

fitness :: [Int] -> Int
fitness (0xdeadfeed:out) = 0xFFFF0000 .|. errorPenalty (head out) 
fitness out              = (distance goal . take 16) out 

evalChain :: Emulator Engine -> [Gadget] -> IO Int
evalChain uc chain = 
  fitness <$> hatchChain uc (unicornPack chain)

mate :: RandomGen g => Chain -> Chain -> Rand g Chain
mate mom dad = (++) <$> flip take mom <*> flip drop dad <$> pivot
  where pivot = getRandomR (0, length mom - 1)

    

