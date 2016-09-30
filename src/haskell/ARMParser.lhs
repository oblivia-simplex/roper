\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{amssymb}
\usepackage{amsmath}
\usepackage{listings}
\let\oldemptyset\emptyset
\let\emptyset\varnothing
\usepackage{parskip}
\usepackage{fancyvrb}

\title{A Parser for ARM and Thumb Binaries}
\author{Olivia Lucca Fraser\\B00109376}
\date{\today}

%include polycode.fmt

\begin{document}



\begin{code}
module ARMParser where
import Aux
import ARMCommon
import qualified Thumb16 as Th  -- to avoid namespace conflicts
import qualified ARM32   as Ar
import Control.Applicative
import qualified Data.List as L
import qualified Data.ByteString as B
import Data.Attoparsec.ByteString
import Data.Attoparsec.Binary
import Data.Word
import Data.Bits
import Numeric (showHex)
\end{code}
\section{Parser}


Here's where we do the actual parsing. Since machine code has no real
grammar to speak of, beyond the layout structure that we've already
written several functions to pull apart, this part is almost trivial.

The control structures here are furnished by Attoparsec, a popular parsing library that deals especially well with raw binary data. Attoparsec has many resources for handling syntax on the macro level -- the relational structure obtaining between separate instructions -- but since we are dealing with fixed-width (RISC) instructions, there isn't much for it to do here. The complexities of the grammar are all situated at the 'micro' level, inside each instruction. While we could have pressed Attoparsec into service in that domain, it was just as simple to perform
 the analysis with a bit of pattern matching and bit twisting. 

\section {Endianness}

The ARM architecture is bi-endian, meaning that it can operate in either big-endian or little-endian mode. This choice is controled by a flag bit in the CPSR register (the 'E' flag). For the time being, we'll be focussing on little-endian code, and will hardcode this into our parser. In the interest of maintaining flexibility, however, we will hardcode it as delicately as possible, so that in the future we will be able to easily parameterize this option.

\begin{code}

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

\end{code}

\section {Some Auxiliary Types}

Since we will be pulling in code from both the Thumb and ARM modules here, modules which largely parallel one another, it will be helpful to have a handful of auxiliary types that can be used to braid together the two instruction modes.

We will also introduce the Inst type, which will assemble all the information we have pulled from each instruction in a convenient record type (a record is the Haskellian counterpart to C's structs).

\begin{code}
data Layout' = Thumb Th.Layout | ARM Ar.Layout deriving (Show, Eq)

data Raw = W16 Word16 | W32 Word32 deriving (Show, Eq)
--instance Enum Raw where
 -- fromEnum r = fromEnum $ fromRaw r
 -- toEnum r = W32 (fromEnum r)
fromRaw32 :: Raw -> Word32
fromRaw16 :: Raw -> Word16
fromRaw16 (W16 w) = w
fromRaw32 (W32 w) = w

data Mode = ArmMode | ThumbMode deriving (Eq, Show, Enum)

data Inst = Inst {
   iRaw  :: Raw
  ,iLay  :: Layout'
  ,iSrc  :: [Int]
  ,iDst  :: [Int]
  ,iCnd  :: Cond
  ,iOp   :: Operation
  }

instance Eq Inst where
  x == y  =  ((iRaw x) == (iRaw y))

instance Show Inst where
  show x  = (show $ iRaw x) ++ ": "
            ++ " " ++ (stringy iSrc) ++ " ->" ++ (stringy iDst)
            ++ "  (" ++ (show $ iLay x) ++ ")" ++ "\n"
    where stringy field =
            (foldl (\a b -> a ++ " " ++ b) [] (fmap show $ field x))
-- Some mnemonics we'll be using for DataProc instructions.
-- Note that a different system will be needed for the
-- other layouts.
\end{code}

\section {Parsing Functions}

Here, we finally introduce our parsing functions for Thumb and ARM, respectively.

\begin{code}

-- The instruction parser, itself
thumbInst :: Parser Inst
thumbInst = do
  w <- anyWord16
  pure $ Inst {
     iRaw = W16 w
    ,iLay = Thumb $ Th.whatLayout w
    ,iSrc = Th.srcRegs w
    ,iDst = Th.dstRegs w
    ,iCnd = undefined
    ,iOp  = Th.operation w
    }

armInst :: Parser Inst
armInst = do
  w <- anyWord32
  pure $ Inst {
     iRaw = W32 w
    ,iLay = ARM $ Ar.whatLayout w
    ,iSrc = Ar.srcRegs w
    ,iDst = Ar.dstRegs w
    ,iCnd = undefined
    ,iOp  = Ar.operation w
    }
\end{code}

Now we just need to pull this together with a parser that repeatedly applies one or the other until it exhausts the input.

Since we are not emulating the code here, we have no \emph{a priori} way of knowing whether we should be reading the code as Thumb or as ARM. This is, itself, an interesting feature of the ARM/Thumb instruction set, from the point of view of the attacker: heedless of the 'intentions' of the programmer or compiler, so long as she is able to manipulate the $T$ flag in the CPSR, the attacker is free to interpret any executable data as \emph{either} Thumb or ARM, which coexist in a sort of virtual palimpsest in the code -- so long, that is, as the code can be properly parsed.

\begin{code}

instructions :: Mode -> Parser [Inst]
instructions ArmMode = many armInst
instructions ThumbMode = many thumbInst
\end{code}

\section{Testing functions}

This bit here is solely for testing purposes, to see if our parser is able to process a chunk of real-world data (pulled from the .text section of ldconfig.real, a statically compiled binary, found in the bowels of a Raspberry Pi's Debian installation, whose day job is to create, update, and remove symbolic links for shared library object files, enlisted here only because it supplies a large amount of statically compiled ARM code).

\begin{code}

-- the text section of an ARM Elf binary, extracted with dd
-- just to tide us over until the Elf header parser is written
textpath = "/home/oblivia/Projects/roper-stack/bins/arm/ldconfig.text"

main :: IO ()
main = do
  text   <- B.readFile textpath
  putStrLn "===================================================="
  putStrLn "                   Arm Mode"
  putStrLn "===================================================="
  let aparsed = parseOnly  (instructions ArmMode) $  B.take 0x200 text
  print aparsed
  putStrLn "===================================================="
  putStrLn "                   Thumb Mode"
  putStrLn "===================================================="
  let tparsed = parseOnly  (instructions ThumbMode) $ B.take 0x200 text
  print tparsed
-- find some pure Thumb code to test Thumb mode with (TODO)
\end{code}

\end{document}

