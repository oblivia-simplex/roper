module Main where
import Gadget
import Hatchery
--import Data.Elf
import qualified Data.List as L
--import ARM32
import ARMParser
import System.Random
--import Control.Monad.Random
import ElfHelper
import qualified Data.ByteString as B
import Phylogen
import Embryogen
import Control.Monad
import Control.Monad.State
import Debug.Trace
import Control.Monad.Trans.State

path :: String
path = "/home/oblivia/Projects/roper/data/ldconfig.real"

chainSize :: Int
chainSize = 6

defaultParams :: Params
defaultParams = Params { popSize = 64
                       , initLen = 32
                       , seed    = 42
                       , tSize   = 4
                       }
main :: IO ()
main = do
  secs <- getElfSecs path
  putStrLn "Loading elf sections..."
  let Just text   = L.find ((== ".text") . name) secs
  let Just rodata = L.find ((== ".rodata") . name) secs
  putStrLn "Extracting gadgets..."
  let gadgets     = parseIntoGadgets ArmMode text
  let rndGen      = mkStdGen $ seed defaultParams
  let chains      = mkRndChains rndGen 64 chainSize gadgets
  putStrLn "Initializing random list of gadgets..."
  putStrLn "Initializing engine..."
  -- | slow careful way | -- out <- mapM (prepAndHatch text rodata) (map unicornPack chains)
  -- putStrLn $ show $ map (map showHex) out
  let uc          = initEngine text rodata  
  let population  = initPop rndGen 
                            (popSize defaultParams) 
                            (initLen defaultParams)
                            gadgets
  putStrLn "Population initialized"
  
  p' <- evolveIO rndGen uc population defaultParams

  print (best p')
--  r <- execStateT (evolve rndGen uc) population
--  putStrLn "typechecked!"
                            

  
  --putStrLn $ show (chains !! 0)
  --putStrLn "Hatching chain..."
  --let packed = unicornPack (chains !! 0)
  --putStrLn $ show $ B.unpack packed
  --out <- mapM (evalChain uc) chains
  --print $ liftM (fmap showHex) out

