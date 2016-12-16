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
import Control.Monad.State
--import Control.Monad.Trans.State
import qualified Data.ByteString as BS
import Unicorn
import Data.Bits
import Aux
--import qualified Embryogen as Em
import Embryogen
import Debug.Trace

--type Chain = [Gadget]
type Goal = ([Int], [Int])
--type Fitness = Maybe Int
--type Creature = (Fitness, Chain)
data Population = Pop { biomass :: [(Fitness, Chain)]
                      , best    :: [(Fitness, Chain)]
                      }
nullCreature :: Creature
nullCreature = (Nothing, [])

data Params = Params { popSize :: Int
                     , initLen :: Int
                     , tSize   :: Int
                     , seed    :: Int
                     } deriving (Show, Eq)

-- initPop will call on the "Embryogenic" functions to
-- generate an initial population. It needs a list of
-- Gadgets, as raw material, and a random number generator.
initPop :: RandomGen g => g 
                       -> Int        -- population size
                       -> Int        -- initial chain length
                       -> [Gadget]   -- raw material
                       -> Population 
initPop gen num len gads =
  Pop { biomass = zip (repeat Nothing) (mkRndChains gen num len gads)
      , best    = [nullCreature]
      }


goal :: Goal
goal = ([0, 1, 2], [100, 2, 0xdeadbeef])

distance :: Goal -> [Int] -> Int
distance _ [] = 0xffffffff
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

fitness :: [Int] -> Fitness
fitness (0xdeadfeed:out) = Just $ 0xFFFF0000 .|. errorPenalty (head out) 
fitness out              = Just $ (distance goal . take 16) out 

evalChain :: Emulator Engine -> Chain -> IO Fitness
evalChain uc chain = 
  fitness <$> hatchChain uc (unicornPack chain)

evalPop :: Emulator Engine -> Population -> Population
evalPop = undefined

mate :: RandomGen g => g -> [Chain] -> Chain
mate g (mom:dad:_) = (`evalRand` g) $ (++) <$> flip take mom <*> flip drop dad <$> pivot
  where pivot = getRandomR (0, length mom - 1)

mateWrap :: RandomGen g => g -> [Creature] -> [Creature]
mateWrap g parents = 
  let chains = [ mate g (snd <$> parents)
               , mate g (snd <$> reverse parents)]
  in  zip (repeat Nothing) chains
                      
{-
evolve :: RandomGen g => g 
                      -> Emulator Engine 
                      -> StateT Population IO [Creature] 
evolve g uc = do
  t <- trace "Tournement time!" $ tournement g uc
  population <- get
  return $ best population
-}

evolveIO :: RandomGen g => g
                        -> Emulator Engine
                        -> Population
                        -> Params
                        -> IO Population
evolveIO g uc p params = do
  p' <- trace "Tournement time!" $ tournement g uc p params
  putStrLn $ "Best: " ++ show (best p')
  evolveIO g uc p' params

f :: Monad m => [m a] -> m [a]
f [mm] = mm >>= \m -> return [m]

apply2 :: (a -> a -> b) -> [a] -> b
apply2 f (x:y:_) = f x y

evalIfNeeded :: Emulator Engine -> Creature -> IO Creature
evalIfNeeded uc crt =
  case crt of 
    (Just n,  _) -> return crt
    (Nothing, c) -> evalChain uc c >>= \x -> return (x, c)

arena :: Emulator Engine -> [Creature] -> IO [Creature]
arena uc = mapM (evalIfNeeded uc) 
                                   
tournement :: RandomGen g => g
                          -> Emulator Engine 
                          -> Population
                          -> Params
                          -> IO Population
tournement g uc p params = do
  let b     = best p
  let bio   = biomass p
  let lots  = take (tSize params) $ randomRs (0, popSize params - 1) g
  let nG    = snd $ next g
  let brawl = (bio !!) <$> lots 
  let rest  = bio L.\\ brawl
  evalled  <- arena uc brawl
  let parents = take 2 evalled
  let theDead = drop 2 evalled
  let spawn = mateWrap g parents
  let theLiving = rest ++ spawn
  let theBest = if fst (head parents) > fst (head b)
                then head parents : b
                else b 
  let newPop = Pop { biomass = theLiving, best = theBest }
  return newPop
                  

  -- we're halfway to defining a tournement here!!
  -- TODO: Finish this!!
--tournement :: RandomGen g => g -> [Chain] -> [Chain]

