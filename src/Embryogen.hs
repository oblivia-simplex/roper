module Embryogen where

import Control.Monad
import Control.Monad.Random
import System.Random
import Control.Applicative
import Gadget
import qualified ARM32
import qualified Thumb16
import ARMParser
import Data.List

-- | The ground zero compiler: random chains with padding | --



rndChain :: (RandomGen g) => g -> [Gadget] -> [Gadget]
rndChain gen gads = rec base
  where base :: [Gadget]
        base = map (\i -> gads !! i) 
               $ randomRs (0, (length gads)-1) gen
        rec :: [Gadget] -> [Gadget]
        rec []     = [] 
        rec (x:xs) = x : (take (gSpDelta x - 1) rImms) ++ rec xs
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
                             -> [[Gadget]] -- list of chains
mkRndChains g num size xs = 
  take num $ streamChunks size $ rndChain g xs


