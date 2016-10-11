-- first stab at getting the emulation to work in haskell.
-- compare with emhatchery.c and listener.c.
-- borrowing liberally from SampleArm.hs for now
module Hatchery where

import Debug.Trace
import ARMParser
import Unicorn
import UnicornUtils
import Unicorn.Hook
import qualified Unicorn.CPU.Arm as Arm
import qualified Unicorn.Internal.Core
import qualified Data.ByteString as BS
import Data.Word
import Data.List
import Control.Monad
import GHC.Int
import qualified Data.Attoparsec.ByteString as Atto
import System.IO
import Network.Socket
import Data.Bits
import qualified Numeric as N
import ElfHelper

type Code    = BS.ByteString
type Address = Int64

hardcodePath :: String
hardcodePath = "data/ldconfig.real"

b = BS.pack
port    = 8888     :: PortNumber
memSize = 0x100000 :: Int -- 1 MiB 

-- memory addr where emulaton starts
baseAddress :: Word64
baseAddress = 0x10000

-- calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
  fromIntegral . BS.length

hookBlock :: BlockHook ()
hookBlock _ addr size _ =
  putStrLn $ margin ++ "Tracing basic block at 0x" ++ 
  showHex addr ++ ", block size = 0x" ++ (maybe "0" showHex size)

hookCode :: CodeHook ()
hookCode _ addr size _ =
  putStrLn $ margin ++ "Tracing instruction at 0x" ++ showHex
  addr ++ ", instruction size = 0x" ++ (maybe "0" showHex size)

margin :: String
margin = "--| "

-- | Run this function to prepare the engine for
-- | each round of execution. (Whereas initEngine
-- | only needs to be run once per session.)
prepareEngine :: Emulator Engine -> Emulator Engine 
prepareEngine eUc = do
  uc <- eUc 
  setRegisters' uc $ replicate 15 0
  return uc

-- | Note that any changes made to the engine state
-- | will be forgotten after this function returns,
-- | It is not wrapped in an Emulator monad...
-- | Execute the payload and report the state. 
hatchCode :: Emulator Engine -> Code -> IO [Char]
hatchCode eUc code = do
  result <- runEmulator $ do
    -- initialize emulator in ARM mode
    -- pull the engine out of its monad wrapper
    uc <- eUc

    -- write machine code to be emulated to memory
    memWrite uc baseAddress code
  
    -- emulate machine code in unlimited time, or when finishing
    -- all the code
    let codeLen = codeLength code
    start uc baseAddress (baseAddress + codeLen) Nothing Nothing
    -- Return the results
    rList <- mapM (regRead uc) $ map r [0..15]
    return rList

  case result of
    Right rList -> return $ "\n" ++ "** Emulation complete. " ++
                          "Below is the CPU context **\n\n" ++  
                          (showRegisters rList)
    Left err -> return $ "Failed with error: " ++ show err ++ 
                         " (" ++ strerror err ++ ")"

-- | Pretty print register contents.
showRegisters :: (Show a, Integral a) => [a] -> String
showRegisters rList = 
  foldr (\(r,v) next -> margin ++ "r"++r++": "++(pad r)
         ++v++"\n" ++ next)
        "" $ zip (map show [0..15]) 
          (map showHex rList)
  where pad r = replicate (2 - length r) ' '
                                  
runConn :: (Socket, SockAddr) -> Emulator Engine -> IO [Char]
runConn (skt, _) eUc = do
  hdl <- socketToHandle skt ReadWriteMode
  hSetBuffering hdl NoBuffering 
  codeStr <- hGetContents hdl
  let code :: [Word8]
      code = map toEnum $ map fromEnum codeStr
  let packedCode = BS.pack(code)
  -- just to ease debugging, let's pass this to our parser, too
  let parsed = Atto.parseOnly (instructions ArmMode) packedCode
  let dealWith p = do
                     result <- hatchCode ( eUc) $ BS.pack code
                     hPutStrLn hdl $ p ++ result
                     return $ p ++ result
  case parsed of 
    Right s -> dealWith $ foldr (++) "" $ map show s 
    Left  e -> dealWith $ "Parsing Error: " ++ (show e)

mainLoop :: Emulator Engine -> Socket -> IO () 
mainLoop eUc skt = do
  conn <- accept skt
  result <- runConn conn eUc    
  putStrLn result
  mainLoop eUc skt

-- Do all the engine initialization stuff here. 
-- including, for now, hardcoding in some nonwriteable mapped memory
-- (the .text and .rodata sections, specifically)
-- so that we can move towards sending just stacks of addresses
-- over the wire. 
-- We'll need another routine to refresh the writeable memory
-- each cycle. That'll be called from the mainLoop. 
initEngine :: Section -> Section -> Emulator Engine
initEngine text rodata = do
  uc <- open ArchArm [ModeArm]
  memMap uc baseAddress memSize [ProtAll]
  -- now map the unwriteable memory zones
  -- leave it all under protall for now, but tweak later
  memWrite uc (addr text) (code text)
  --putStrLn "Loaded text section..."
  memWrite uc (addr rodata) (code rodata)
  --putStrLn "Loaded rodata section..."
   
   -- tracing all basic blocks with customized callback
  --blockHookAdd uc hookBlock () 1 0
   -- tracing one instruction at address with customized callback
  --codeHookAdd uc hookCode () baseAddress baseAddress
  return uc

textSection :: Section
textSection   = undefined
rodataSection :: Section
rodataSection = undefined

hatchMain :: IO ()
hatchMain = do
  sections <- getElfSecs hardcodePath
  let Just textSection   = find ((== ".text") . name)   sections
  let Just rodataSection = find ((== ".rodata") . name) sections 
  let eUc = initEngine textSection rodataSection 
  sock <- socket AF_INET Stream 0
  setSocketOption sock ReuseAddr 1 -- make socket immediately reusable
  bind sock (SockAddrInet port iNADDR_ANY) -- listen on port 9999
  listen sock 8
  mainLoop eUc sock
  return ()
