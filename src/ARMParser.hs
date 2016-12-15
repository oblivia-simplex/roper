
module ARMParser where
import Aux
import ARMCommon
import qualified Instruction as I
import qualified Thumb16 as Th  -- to avoid namespace conflicts
import qualified ARM32   as Ar
import Control.Applicative
import qualified Data.List as L
import qualified Data.ByteString as B
import Data.Attoparsec.ByteString
import Data.Attoparsec.Binary
import Data.Word
import Data.Bits
import qualified Numeric as N (showHex)


type Code = B.ByteString

data Endian = Little | Big deriving (Show, Eq, Ord)
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


data Layout' = Thumb Th.Layout | ARM Ar.Layout deriving (Show, Eq)

type Raw = Word32
--instance Enum Raw where
 -- fromEnum r = fromEnum $ fromRaw r
 -- toEnum r = W32 (fromEnum r)
-- SHOW INSTANCE


data Mode = ArmMode | ThumbMode deriving (Eq, Show, Enum)


data Inst = Inst {
   iRaw  :: Raw
  ,iImm  :: Maybe Word32
  ,iLay  :: Layout'
  ,iSrc  :: [Int]
  ,iDst  :: [Int]
  ,iCnd  :: Cond
  ,iOp   :: I.Op Word32
  }

instance Eq Inst where
  x == y  =  ((iRaw x) == (iRaw y))

showHex :: (Integral a, Show a) => a -> String
showHex n =
  let s = flip N.showHex "" n
  in pad s
  where pad st =
          (L.take (8 - (length st)) $ repeat '0') ++ st


instance Show Inst where
  show x  = (reverse $ L.take 8 $ reverse $ showHex $ iRaw x) ++ ": "
            ++ (show $ iLay x)  
            ++ " " ++ (showImm $ iImm x) ++ "; " ++ (stringy iSrc) ++ "-> "
            ++ (stringy iDst) ++ "\n"
    where stringy :: (Inst -> [Int]) -> String
          stringy field =
            (foldr (\a b -> "r" ++ a ++ " " ++ b ) "" 
              (fmap show $ field x))
          showImm i = case i of
                        Just im -> "#&" ++ showHex im
                        Nothing -> "--"
            
-- Some mnemonics we'll be using for DataProc instructions.
-- Note that a different system will be needed for the
-- other layouts.


-- The instruction parser, itself
thumbInst :: Parser Inst
thumbInst = do
  w <- anyWord16
  pure $ Inst {
     iRaw  = en w
    ,iImm  = Nothing -- just for now
    ,iLay  = Thumb $ Th.whatLayout w
    ,iSrc  = Th.srcRegs w
    ,iDst  = Th.dstRegs w
    ,iCnd  = undefined
    ,iOp   = Th.operation w
   -- ,iMnem = Mnemonic
    }
{-
thumbInst' :: Parser (I.Inst Word16)
thumbInst' = do
  w <- anyWord16
  pure I.Inst {
     I.raw = w
    ,I.imm = Nothing -- STUB
    ,I.lay = show $ Th.whatLayout w
    ,I.rS1 = Th.s1Regs w
    ,I.rS2 = Th.s2Regs w
    ,I.rD  = Th.dstRegs w
    ,I.cnd = [] -- STUB/TODO
    ,I.op  = Th.operation w
  }
-}

armInst :: Parser Inst
armInst = do
  w <- anyWord32
  pure $ Inst {
     iRaw  = w
    ,iImm  = Ar.immediate w
    ,iLay  = ARM $ Ar.whatLayout w
    ,iSrc  = Ar.srcRegs w
    ,iDst  = Ar.dstRegs w
    ,iCnd  = undefined
    ,iOp   = Ar.operation w
    -- ,iMnem = Mnemonic
    }
{-
armInst' :: Parser (I.Inst Word32)
armInst' = do
  w <- anyWord32
  pure I.Inst {
     I.raw = w
    ,I.lay = show $ Ar.whatLayout w
    ,I.imm = Ar.immediate w
    ,I.rS1 = Ar.s1Regs w
    ,I.rS2 = Ar.s2Regs w
    ,I.rD  = Ar.dstRegs w
    ,I.cnd = [] -- STUB/TODO
    ,I.op  = Ar.operation w
  }
-}

instructions :: Mode -> Parser [Inst]
instructions ArmMode = many armInst
instructions ThumbMode = many thumbInst



parseInstructions :: Mode -> Code -> [Inst]
parseInstructions mode code =
  let res = parseOnly (instructions mode) code
  in case res of
      Left s  -> []
      Right i -> i

  



-- the text section of an ARM Elf binary, extracted with dd
-- just to tide us over until the Elf header parser is written
textpath = "/home/oblivia/Projects/roper-stack/bins/arm/ldconfig.text"

testMain :: IO ()
testMain = do
  text   <- B.readFile textpath
  putStrLn "===================================================="
  putStrLn "                   Arm Mode"
  putStrLn "===================================================="
  let aparsed = parseOnly  (instructions ArmMode) $  B.take 0x200 text
  print aparsed
--  putStrLn "===================================================="
--  putStrLn "                   Thumb Mode"
--  putStrLn "===================================================="
--  let tparsed = parseOnly  (instructions ThumbMode) $ B.take 0x200 text
--  print tparsed
-- find some pure Thumb code to test Thumb mode with (TODO)

--parseARM :: B.Bytestring -> 
