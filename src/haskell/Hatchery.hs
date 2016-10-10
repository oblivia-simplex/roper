-- first stab at getting the emulation to work in haskell.
-- compare with emhatchery.c and listener.c.
-- borrowing liberally from SampleArm.hs for now
module Hatchery where

import ARMParser
import Unicorn
import UnicornUtils
import Unicorn.Hook
import qualified Unicorn.CPU.Arm as Arm
import qualified Unicorn.Internal.Core
import qualified Data.ByteString as BS
import Data.Word
import Control.Monad
import GHC.Int
import qualified Data.Attoparsec.ByteString as Atto
import System.IO
import Network.Socket
import Data.Bits
import qualified Numeric as N

pORT = 9999

b = BS.pack

-- mov r0, #0x37; sub r1, r2, r3
armCode :: BS.ByteString
armCode = BS.pack [0xFF, 0x00, 0xa0, 0xe3, 0x03, 0x10, 0x42, 0xe0]

-- sub sp, #0xc
thumbCode :: BS.ByteString
thumbCode = BS.pack [0x83, 0xb0]

-- memory addr where emulaton starts
address :: Word64
address = 0x10000


-- calculate code length
codeLength :: Num a => BS.ByteString -> a
codeLength =
  fromIntegral . BS.length

hookBlock :: BlockHook ()
hookBlock _ addr size _ =
  putStrLn $ margin ++ "Tracing basic block at 0x" ++ showHex addr ++
  ", block size = 0x" ++ (maybe "0" showHex size)

hookCode :: CodeHook ()
hookCode _ addr size _ =
  putStrLn $ margin ++ "Tracing instruction at 0x" ++ showHex addr ++
  ", instruction size = 0x" ++ (maybe "0" showHex size)

margin :: String
margin = "--| "


testArm :: BS.ByteString -> IO [Char]
testArm armCode = do
  result <- runEmulator $ do
    -- initialize emulator in ARM mode

    uc <- open ArchArm [ModeArm]

    -- map 2MB memory for this emulation
    memMap uc address 0x800 [ProtAll]

    -- write machine code to be emulated to memory
    memWrite uc address armCode

    -- initialize machine registers
    -- regWrite uc Arm.R0 0x1234
    --regWrite uc Arm.R2 0x6789
    --regWrite uc Arm.R3 0x3333
    --setRegisters uc $ map Just [0x10,0x12..0x2E] 
    setRegisters' uc [0,5..(5*15)]

    -- tracing all basic blocks with customized callback
    blockHookAdd uc hookBlock () 1 0

    -- tracing one instruction at address with customized callback
    codeHookAdd uc hookCode () address address

    -- emulate machine code in unlimited time, or when finishing
    -- all the code
    let codeLen = codeLength armCode
    start uc address (address + codeLen) Nothing Nothing

    -- return the results
    r0 <- regRead uc Arm.R0
    r1 <- regRead uc Arm.R1

    return (r0, r1)
  case result of
    Right (r0, r1) -> return (margin ++ "Emulation done. Below is CPU context\n" 
                      ++ margin ++ "R0 = 0x"++ showHex r0 ++ "\n" ++ margin ++ 
                      "R1 = 0x"++ showHex r1 ++ "\n")
    Left err -> return ("Failed with error: " ++ show err ++ " (" ++ strerror err ++ ")")

--data Endian = Little | Ord deriving (Eq, Show, Ord)

{-
hexdump :: Endian -> [Word8] -> String
hexdump e b
  | bE == []  = ""
  | otherwise = (hexit $ take 4 bE) ++ "\n" ++ (hexdump e $ drop 4 bE)
  where hexit :: [Word8] -> String 
        hexit bb = 
          let bbbb :: [Word32]
              bbbb = map fromIntegral bb
          in -- this is uglier than it should be
          reverse $ take 8 $ reverse $ showHex $ 
          ((bbbb !! 0) `shiftL` 24) .|. ((bbbb !! 1) `shiftL` 16) 
          .|. ((bbbb !! 2) `shiftL` 8) .|. (bbbb !! 0)  
        bE = if (e == Little) then (reverse b) else b 
-}

runConn :: (Socket, SockAddr) -> IO [Char]
runConn (skt, _) = do
  hdl <- socketToHandle skt ReadWriteMode
  hSetBuffering hdl NoBuffering
  
  codeStr <-   (hGetContents hdl)
  let code :: [Word8]
      code = map toEnum $ map fromEnum codeStr
  --putStrLn $ hexdump Little code
  putStrLn $ "CODE: " ++ (foldr (++) "" $ map (flip N.showHex "") code)
  let packedCode = BS.pack(code)
-- Now, just to ease debugging, let's pass this to our parser, too
  let parsed = Atto.parseOnly (instructions ArmMode) packedCode
  let dealWith p = do
                     result <- testArm $ BS.pack code
                     hPutStrLn hdl $ p ++ result
                     return $ p ++ result
  case parsed of 
    Right s -> dealWith $ foldr (++) "" $ map show s 
                
    Left  e -> dealWith $ "Parsing Error: " ++ (show e)
-- okay, that was fun. now let's get on with the emulation.
-- this is all inexcusably ugly, but I'm learning the ropes here. 

mainLoop :: Socket -> IO () 
mainLoop skt = do
  conn <- accept skt
  result <- runConn conn    
  putStrLn result
  mainLoop skt

hatch :: IO ()
hatch = do
  sock <- socket AF_INET Stream 0
  setSocketOption sock ReuseAddr 1 -- make socket immediately reusable
  bind sock (SockAddrInet pORT iNADDR_ANY) -- listen on port 9999
  listen sock 8
  mainLoop sock
  return ()
