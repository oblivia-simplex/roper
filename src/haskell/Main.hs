module Main where
import Gadget
import Hatchery
import Data.Elf
import qualified Data.List as L
import ARM32
import ARMParser
import System.Random
import Control.Monad.Random
import ElfHelper
import qualified Data.ByteString as BS
import Phylogen
import Embryogen

path :: String
path = "data/ldconfig.real"

seed = 666
chainSize = 64

main :: IO ()
main = do
  secs <- getElfSecs path
  putStrLn "Loading elf sections..."
  let Just text   = L.find ((== ".text") . name) secs
  let Just rodata = L.find ((== ".rodata") . name) secs
  putStrLn "Extracting gadgets..."
  let gadgets     = parseIntoGadgets ArmMode text
  let rndGen      = (mkStdGen seed)
  let chains      = mkRndChains rndGen 64 chainSize gadgets
  putStrLn "Initializing random list of gadgets..."
  putStrLn "Initializing engine..."
  let uc          = initEngine text rodata  
  putStrLn $ show (chains !! 0)
  putStrLn "Hatching chain..."
  let packed = unicornPack (chains !! 0)
  putStrLn $ show $ BS.unpack packed
  out <- mapM (evalChain uc) chains
  putStrLn $ show $ map showHex out

