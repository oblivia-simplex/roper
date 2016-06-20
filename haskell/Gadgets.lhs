|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|
              _          _             _               _
 __ _ __ _ __| |__ _ ___| |_   _____ _| |_ _ _ __ _ __| |_ ___ _ _
/ _` / _` / _` / _` / -_)  _| / -_) \ /  _| '_/ _` / _|  _/ _ \ '_|
\__, \__,_\__,_\__, \___|\__| \___/_\_\\__|_| \__,_\__|\__\___/_|
|___/          |___/

|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|


For the sake of simplicity, we're going to just focus on the ARM 32bit
architecture for now. It should be easy to extend it to other RISC
instruction sets, and slightly more complicated to extend it to CISC
architectures.

First, we'll import the modules we need, and define some data types.
The Gadget type will be a record (struct) that holds a variety of useful
information about the gadgets collected: the code, in raw byte format (as
it will be passed to the unicorn emulator), the code again, in 32 bit words
(more convenient for analysis), a list of the registers read from, a list of
the registers written to, a keyword describing the control type (pop PC?
br LR? brx LR? etc.), and mode (thumb or arm).

Note: there's something kind of awkward about storing the code twice. Find a
more efficient but not less convenient way to do this.

\begin{code}
module GadgetExtractor where

import Data.List
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BC
import Data.Binary.Get
import Data.Word
import Data.Elf
import Control.Exception as E
import System.IO
import Control.Monad
import Text.Printf

import Hapstone.Capstone
import Unicorn

import ARM32
import Aux

-- make the field types more definite when you can
data Gadget = Gadget { g_codebytes   :: BC.ByteString  -- the code of the gadget itself
                     , g_codewords   :: [Word32]       -- same, but in 32 bit words
                     , g_start   :: Word64      -- initial address of the gadget
                     , g_stop    :: Word64      -- last address of gadget, incl. 
                     , g_ctrl   :: String      -- a keyword would be better...
                     , g_src  :: [Word32]       -- register indices
                     , g_dst :: [Word32]       -- register indices
                     }

\end{code}


Now, a few functions for extracting information from the ELF file:

\begin{code}
readElfFile :: [Char] -> IO Elf
readElfFile filename = do
  rawbytes <- BC.readFile filename
  return $ parseElf rawbytes

extractSection :: [Char] -> Elf -> ElfSection
extractSection sname elf =
  strip $ find (\s -> (elfSectionName s) == sname) $ elfSections elf
  where strip (Just a) = a
        strip Nothing = error $ "No section named " ++ sname

get32bitInsts_ :: Get [Word32]
get32bitInsts_  = do
  empty <- isEmpty
  if empty
    then return []
    else do inst <- getWord32le
            rest <- get32bitInsts_
            return (inst : rest)

extractInsts :: ElfSection -> [Word32]
extractInsts text =
  runGet get32bitInsts_ $ BL.fromStrict (elfSectionData text)


describeElf :: Elf -> IO ()
describeElf elf = do
  printf "[*] Architecture detected: %s\n" (show $ elfMachine elf)
  printf "[*] SECTION\t\t\tSTART\t\t\tEND\n"
  mapM_ descSec $ tail $ elfSections elf
  where descSec e = printf "[+] %s\t\t\t%08x\t\t\t%08x\n"
                    (elfSectionName e) (elfSectionAddr e)
                    ((+) (elfSectionAddr e) (elfSectionSize e))

\end{code}

Now, here's where it gets interesting: we need to extract all
the candidate gadgets, sort them by type, and then store them
in a data structure that will facilitate analysis and use. Cf.
the Q paper, and the tree structure the authors use.

\begin{code}

-- (defun int-arm-pop-pc-p (opcode)
--   (and
--    ;; is it a pop?
--    (= (print (logand opcode #xFFFF0000)) #xe8bd0000)
--    ;; does it pop into register 15 (pc)?
--    (/= (print (logand opcode (ash 1 15))) 0 )))


--- now, scan the reversed instructions list
--- and when you hit a popPCp == True, take n instructions from
--- that point. return the resulting list of lists.
gadLen = 8 -- tweakable
wordsize :: Word64
wordsize = 4 -- architecture dependent. should extract from elf.

secEnd ::  ElfSection -> Word64
secEnd sec = (elfSectionAddr sec) + (elfSectionSize sec) - wordsize


extractRawGads :: ElfSection -> (Word32 -> Bool) -> [Gadget]
extractRawGads sec gadp =
  filter (\g -> length (g_codewords g) > 1) $ ergR (reverse (extractInsts sec))
  (secEnd sec) gadp
  where
    ergR :: [Word32] -> Word64 -> (Word32 -> Bool) -> [Gadget] -- replace w reclst
    ergR [] _ _ = []
    ergR insts addr gadp
    -- replace the gadget list with a gadget record
    -- for addr field, set to addr - l. check for off-by-one errors
      | gadp (head insts) = let wrds = reverse (take l insts)
                            in Gadget {g_codewords = wrds
                                      ,g_codebytes = w2bs wrds
                                      ,g_start = addr - ((l+1) * wordsize)
                                      ,g_stop = addr
                                      ,g_ctrl = "" -- placeholder. might not even be a string
                                      ,g_src = nub $ concat $ map (srcRegs False) wrds
                                      ,g_dst = nub $ concat $ map (dstRegs False) wrds
                                      } :
                               ergR (drop l insts) (step addr) gadp
      | otherwise = ergR (tail insts) (addr - wordsize) gadp
      where l :: Integral n => n -- Word64
            l = (+1) $ fromIntegral $ (length (takeWhile
                                                (not . gadp) $ tail
                                                $ take gadLen insts)) -- ineff?
            step a = a - l * wordsize



\end{code}

Finally, a 'main' function, for testing purposes.

\begin{code}

main :: IO ()
main = do
  let filename = "/home/oblivia/Projects/roper/bins/arm/ldconfig.real" :: [Char]
  elf <- readElfFile filename
  let text = extractSection ".text" elf
  let rodata = extractSection ".rodata" elf
  let instructions = extractInsts text
  let gadgets = extractRawGads text popPCp
  let gads = map g_codewords gadgets
        --runGet get32bitInsts_ $ BL.fromStrict (elfSectionData text)
-- >><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<
  printf "[*] Elf file: %s\n\n" filename
  describeElf elf

  printf "\n>>> Number of 32 bit instructions in text: 0x%x\n" (length instructions)
  printf ">>> FIRST FEW >>> %08x %08x %08x %08x \n"
    (instructions !! 0) (instructions !! 1) (instructions !! 2) (instructions !! 3)
  printf ">>> Number of POP PC returns: %d\n" (length (filter popPCp instructions))
  printf ">>> Number of gadgets found: %d\n" (length gads)
  printf ">>> Avg length of gadgets: %d\n"
    ((sum $ map length gads) `div` (length gads))

--  mapM_ (printf "%08x\n") $ filter ((== C_RESERVED) . whatCond) instructions
--  mapM_ (printf "%s\n" . show) $ take 100 $ map dstRegs instructions
  mapM_ (\g -> (mapM_ (\ (t,s,d) ->
                          (printf "%s: %s ==> %s\n"
                            (show t) (show s) (show d)))
                 (zip3
                   (map whatLayout g)
                   (map (srcRegs True) g)
                   (map (dstRegs True) g))
               >> putStrLn "--------------")) gads

  mapM_ (\g -> (printf "FROM %08x to %08x: %s ==> %s\n" (g_start g) (g_stop g)
                (show $ g_src g) (show $ g_dst g)))
    gadgets
-- mapM_ (printf "%s\n" . binStr)  $ filter ((== UNSURE) . whatLayout) instructions
--  mapM_ disasmIO $ filter ((== C_RESERVED) . whatCond) instructions
--  $ map whatLayout instructions
-- >><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<

\end{code}

