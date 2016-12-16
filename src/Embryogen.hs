module Embryogen where

import Control.Monad
import Control.Monad.Random
import Control.Monad.State
import System.Random
import Control.Applicative
import Gadget
import qualified ARM32
import qualified Thumb16
import ARMParser
import Data.List
import Data.Word

-- | The ground zero compiler: random chains with padding | --
type Chain    = [Gadget]
type Fitness  = Maybe Int
type Creature = (Fitness, Chain)


rndChain :: (RandomGen g) => g -> [Gadget] -> [Gadget]
rndChain gen gads = rec base
  where base :: [Gadget]
        base = map (\i -> gads !! i) 
               $ randomRs (0, length gads - 1) gen
        rec :: [Gadget] -> [Gadget]
        rec []     = [] 
        rec (x:xs) = x : take (gSpDelta x - 1) rImms ++ rec xs
        rImms :: [Gadget]
        rImms =
          let rs :: [Int]
              rs = randoms gen
          in  map mkImmGadget rs

streamChunks :: Int   -- size of chunks 
             -> [a]   -- stream to be chunked
             -> [[a]] -- chunky stream
streamChunks _ [] = []
streamChunks n xs = let (a,b) = splitAt n xs
                    in  a : streamChunks n b

mkRndChains :: (RandomGen g) => g 
                             -> Int        -- number of chains 
                             -> Int        -- length of chains
                             -> [Gadget]   -- gadget supply
                             -> [Chain]    -- list of chains
mkRndChains g num size xs = 
  take num $ streamChunks size $ rndChain g xs


initFitness :: [Chain] -> [(Fitness, Chain)]
initFitness = zip (repeat Nothing) 
--------------------------
-- building blocks
--

-- higher level of complexity than gadgets
-- clumps
-- makeAndRegisterClump: build a clump and register it in a 
-- list that will be kept as a state
-- fetchClump :: Int -> Clump : fetch the nth clump from the list,
-- modulo the length of the list. put that clump in the chain.
-- This will give us something like tagging, without touching the
-- machine code.
type Immed = Gadget
type Tag   = Int
type Clump = (Int, Chain)
type Address = Word32 -- defined somewhere else, actually. tidy it.



clusterClump :: (Eq a, Eq b) => [(a,b)] -> [b] 
clusterClump [] = []
clusterClump cl@(c:cs) =
  case lookup (fst c) $ filter (/= c) cl of
    Nothing -> snd c : clusterClump cs
    Just x  -> x : clusterClump cs


clump :: Tag -> Gadget -> [Immed] -> Clump
clump t g imms = (t, g : take (gSpDelta g) imms)

clumpImms :: [Gadget] -> [Immed]
clumpImms = tail



-- sample individual:
-- clump 0xCODEFACE [0xFFFFFFFE, 0xBEEFBABE, 0x00000008] 
-- 

