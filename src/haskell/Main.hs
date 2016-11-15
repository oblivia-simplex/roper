module Main where
import Gadget
import Hatchery
import HatchSock
import Data.Elf
import qualified Data.List as L
import ARM32
import ARMParser
import System.Random
import Control.Monad.Random
import ElfHelper
import qualified Data.ByteString as BS

path :: String
path = "data/ldconfig.real"

seed = 43
chainSize = 8

main :: IO ()
main = do
  secs <- getElfSecs path
  putStrLn "Loading elf sections..."
  let Just text   = L.find ((== ".text") . name) secs
  let Just rodata = L.find ((== ".rodata") . name) secs
  putStrLn "Extracting gadgets..."
  let gadgets     = parseIntoGadgets ArmMode text
  putStrLn "Initializing random list of gadgets..."
  let rndGen      = (mkStdGen seed)
  let chains      = mkRndChains rndGen 10 chainSize gadgets
  let pkChains    = map unicornPack chains
  let testChain   = pkChains !! 0
  putStrLn "Initializing engine..."
  let uc          = initEngine text rodata  
  putStrLn $ show (chains !! 0)
  putStrLn $ show $ BS.unpack testChain
  putStrLn "Hatching chain..."
  out <- (hatchChain uc) $ pkChains !! 0
   
  putStrLn $ out
  
