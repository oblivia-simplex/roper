
module ARM32Parser where

import ARM32
import Control.Applicative
import qualified Data.List as L
import qualified Data.ByteString as B
import Data.Attoparsec.ByteString
import Data.Attoparsec.Binary

import Data.Elf


data Endian = Big | Little
endian = Little

anyWord16 = case endian of
  Big    -> anyWord16be
  Little -> anyWord16le

anyWord32 = case endian of
  Big    -> anyWord32be
  Little -> anyWord32le

anyWord64 = case endian of
  Big    -> anyWord64be
  Little -> anyWord64le

data Inst = Inst {
   iLay  :: Layout
  ,iSrc  :: [Int]
  ,iDst  :: [Int]
  ,iCnd  :: Cond
  ,iOp   :: Operation
  }

inst :: Parser Inst
inst = do
  w <- anyWord32
  let t = whatLayout w
  pure $ Inst {
     iLay = t
    ,iSrc = srcRegs w t
    ,iDst = dstRegs w t
    ,iCnd = whatCond w
    ,iOp  = operation w t
    }

instructions :: Parser [Inst]
instructions = many inst

readElfFile :: [Char] -> IO Elf
readElfFile filename = do
  rawbytes <- B.readFile filename
  return $ parseElf rawbytes


main :: IO ()
main = do
  let filename = "/home/oblivia/Projects/roper/bins/arm/ldconfig.real"
  elf <- readElfFile filename
  print elf
