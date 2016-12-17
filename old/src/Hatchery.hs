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
import Aux
import Data.List.Split

-- type Code    = BS.ByteString
type Address = Int64

hardcodePath :: String
hardcodePath = "data/ldconfig.real"

b = BS.pack
port    = 8888     :: PortNumber

-- | At this point in the development, we're treating the entire
-- | memory space as fair game, so that we don't have to worry about
-- | segfaults. This will be tightened up later, once everything else
-- | is working. 
memSize = 0x40000000 :: Int -- 1 MiB 

-- memory addr where emulaton starts
baseAddr :: Word64
baseAddr = 0x00000000

-- phony address used to mark stopping point
stopAddress :: Word64
stopAddress = 0

stackAddr :: Int64
stackAddr = 0xb4238 -- Hardcoded for now

-- calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
  fromIntegral . BS.length


-- | Pretty print register contents.
-- | for debugging. later replace with machine-readable format.
-- | a packed bytestring of register values would be fine
showRegisters :: (Show a, Integral a) => [a] -> String
showRegisters rList = 
  let s = foldr (\(r,v) next -> "r"++r++": "++ (replicate (2 - length r) ' ')
            ++v++"  " ++ next)
            "" $ zip (map show [0..15]) (map showHex rList)
  in intercalate "\nr8" (splitOn "r8" s)

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

-- Note: these two functions look as if they should
-- be taking or returning Word32s, but because of
-- the way the unicorn api works, we have to treat
-- these values as Word64s.
 
firstWord :: [Word8] -> Word64
firstWord bytes = 
  let w = take 4 bytes
  in foldr (.|.) 0 $ map (adj w) [0..3]
  where adj :: [Word8] -> Int -> Word64
        adj wrd i = 
          (fromIntegral $ wrd !! i)  `shiftL` (i * 8)

wordify :: [Word8] -> [Word64]
wordify [] = []
wordify xs = (firstWord xs):wordify (drop 4 xs)

prepAndHatch :: Section -> Section -> Code -> IO [Int]
prepAndHatch text rodata chain = do
  let uc = initEngine text rodata
  out <- hatchChain uc chain 
  return out
-- | Note that any changes made to the engine state
-- | will be forgotten after this function returns. 
-- | Execute the payload and report the state. 
hatchChain :: Emulator Engine -> Code -> IO [Int] --[Char]
hatchChain eUc chain = do
  res <- runEmulator $ do
    let startAddr = firstWord $ BS.unpack chain
    uc <- prepareEngine eUc
    memWrite uc (en stackAddr) chain
    memWrite uc (en $ stackAddr + codeLength chain) $ 
      word64BS stopAddress
    regWrite uc Arm.Sp $ en (stackAddr + 4)
    start uc startAddr stopAddress Nothing (Just 0x1000) 
    rList <- mapM (regRead uc) $ map r [0..15] 
    stack <- memRead uc (en stackAddr) 0x30
    return (rList, stack)
  case res of
    Right (rList, stack) -> 
      return $ map en $ rList ++ (map en $ wordify $ BS.unpack stack)
               -- | "\n" ++ "** Emulation complete. " ++
               -- | "Below is the CPU context **\n\n" ++  
               -- | (showRegisters rList) ++
               -- |"\n\nAnd here is the stack:\n\n" ++
               -- |foldr (\x y -> x ++ "\n" ++ y) "\n" 
               -- |      (showHex <$> (wordify $ BS.unpack stack))
    Left err -> 
      return $ [0xdeadfeed, en err]
              -- | "Failed with error: " ++ show err ++ 
              -- | " (" ++ strerror err ++ ")"

textSection   :: Section
textSection    = undefined
rodataSection :: Section
rodataSection  = undefined

-- | ** Hooks ** | -- 

hookBlock :: BlockHook ()
hookBlock uc addr size b =
  putStrLn $ "\n" ++ margin ++ "Tracing gadget at 0x" ++ 
  showHex addr ++ ", gadget size = 0x" ++ (maybe "0" showHex size) 

hookCode :: CodeHook ()
hookCode uc addr size _ = do 
  inst'   <- runEmulator $ memRead uc addr 4
  regs'   <- runEmulator $ mapM (regRead uc) $ map r [0..15] 
  let inst :: String
      inst = case inst' of
                Left err -> "[" ++ (show err) ++ "]"
                Right bs -> showHex $ firstWord $ BS.unpack bs 
      regs :: String
      regs = case regs' of
                Left err -> show err
                Right rg -> showRegisters rg
  putStrLn $ "    " ++ (showHex addr) ++ ": " ++ inst ++ "\n"
             ++ regs -- (showRegisters regs) 
  return ()
   
hookMem :: MemoryHook ()
hookMem uc accessType addr size writeVal _ =
  putStrLn $ "--> .rodata memory access at " ++ (showHex addr)

hookPreText :: CodeHook ()
hookPreText uc addr size _ =
  putStrLn "--| executing prior to .text!"

hookPostText :: CodeHook ()
hookPostText uc addr size _ =
  putStrLn "--| executing posterior to .text!"

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
  memMap uc baseAddr memSize [ProtAll]
  -- now map the unwriteable memory zones
  -- leave it all under protall for now, but tweak later
  memWrite uc (addr text) (code text)
  memWrite uc (addr rodata) (code rodata)
  -- tracing all basic blocks with customized callback
  blockHookAdd uc hookBlock () 1 0
  let endText = ((addr text) + (en (BS.length (code text))))
  codeHookAdd uc hookCode () (addr text) endText
  -- codeHookAdd uc hookPreText () baseAddr (addr text) 
  -- codeHookAdd uc hookPostText () endText (baseAddr + en memSize)
  memoryHookAdd uc HookMemRead hookMem () (addr rodata) 
    ((addr rodata) + (en (BS.length (code rodata))))  
  return uc

