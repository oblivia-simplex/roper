module HatchSock where

import Hatchery
import Data.Elf
import Unicorn
import Network.Socket
import System.IO
import Data.List
import UnicornUtils
import ElfHelper
import ARM32
import ARMParser
import qualified Data.ByteString as BS
import qualified Data.Attoparsec as Atto


runConn :: (Socket, SockAddr) -> Emulator Engine -> IO [Char]
runConn (skt, _) eUc = do
  hdl    <- socketToHandle skt ReadWriteMode
  hSetBuffering hdl NoBuffering 
  code   <- BS.hGetContents hdl
  result <- hatchCode code
  return result

mainLoop :: Emulator Engine -> Socket -> IO () 
mainLoop eUc skt = do
  conn <- accept skt
  result <- runConn conn eUc    
  putStrLn result
  mainLoop eUc skt

hatchSockMain :: IO ()
hatchSockMain = do
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
