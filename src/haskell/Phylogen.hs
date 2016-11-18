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

type Chain = [Gadget]
type Goal = ([Int], [Int])

goal :: Goal
goal = ([0, 1, 12], [100, 2, 0xdeadbeef])

distance :: Goal -> [Int] -> Int
distance (idxs,target) out = 
  let focus = map (out !!) idxs
  in  sum $ map abs $ zipWith (-) focus target

fitness :: [Int] -> Int
fitness (0xdeadfeed:out) = 0xFFFF0000 .|. (head out)
fitness out              = (distance goal . take 16) out 

evalChain :: Emulator Engine -> [Gadget] -> IO Int
evalChain uc chain = 
  fitness <$> hatchChain uc (unicornPack chain)

mate :: RandomGen g => Chain -> Chain -> Rand g Chain
mate mom dad = (++) <$> flip take mom <*> flip drop dad <$> pivot
  where pivot = getRandomR (0, length mom - 1)

    

