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

type Chain = [Gadget]
type Telos = ([Int], [Int])



telos :: Telos
telos = ([0, 1, 12], [100, 2, 0xdeadbeef])

distance :: Telos -> [Int] -> Int
distance (idxs,target) out =
  let focus = map (out !!) idxs
  in  sum $ map abs $ zipWith (-) focus target

evalChain :: Emulator Engine -> [Gadget] -> IO Int
evalChain uc chain = 
  (distance telos . take 16) <$> hatchChain uc (unicornPack chain)

mate :: RandomGen g => Chain -> Chain -> Rand g Chain
mate mom dad = (++) <$> flip take mom <*> flip drop dad <$> pivot
  where pivot = getRandomR (0, length mom - 1)

    

