
module ARM32Parser where

import ARM32
import Data.Word
import Control.Applicative
import qualified Data.List as L
import qualified Data.ByteString as B
import Data.Attoparsec.ByteString
import Data.Attoparsec.Binary

import Numeric (showHex)

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
   iRaw  :: Word32
  ,iLay  :: Layout
  ,iSrc  :: [Int]
  ,iDst  :: [Int]
  ,iCnd  :: Cond
  ,iOpC  :: Mnemonic
  ,iOp   :: Operation
  }

instance Eq Inst where
  x == y  =  ((iRaw x) == (iRaw y))

instance Show Inst where
  show x  = ("0x" ++ showHex (iRaw x) "") ++ "\n || " ++ (show $ iLay x)
    ++ ", " ++ (show $ iOpC x) ++ ":\t" ++ (show $ iSrc x) ++ " => " ++ (show $ iDst x) ++ "\n"

inst :: Parser Inst
inst = do
  w <- anyWord32
  let t = whatLayout w
  pure $ Inst {
     iRaw = w
    ,iLay = t
    ,iSrc = srcRegs w t
    ,iDst = dstRegs w t
    ,iCnd = whatCond w
    ,iOp  = operation w t
    ,iOpC = getMnemonic w t
    }

instructions :: Parser [Inst]
instructions = do
  s <- many inst
  pure s

-- the text section of an ARM Elf binary, extracted with dd
-- just to tide us over until the Elf header parser is written
textpath = "/home/oblivia/Projects/roper-stack/bins/arm/ldconfig.text"

main :: IO ()
main = do
  text   <- B.readFile textpath
  let parsed = parseOnly instructions $ B.take 0x80 text
  print parsed
