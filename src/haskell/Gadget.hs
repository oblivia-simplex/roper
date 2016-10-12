module Gadget where

import ARMCommon (Register
                 ,Operation)
import ARMParser
import Aux
import Data.Word
import qualified Data.List as L
import Data.Bits
import Control.Monad
import qualified Data.Attoparsec.ByteString as Atto
import qualified Data.ByteString as BS
import ElfHelper
import ARM32
--import Thumb16
import ARMCommon (sp, fp, lr, pc)
--type Code = BS.ByteString 
-- lifting a lot of this from common.ml in ropc-llvm, and translating it from
-- ocaml to haskell.
data AbGad = -- abstract gadget
    LoadConst Register Int    -- reg, stack offset
  | CopyReg Register Register      -- dst reg = src reg
  | BinOp Register Register Operation     -- dst reg = src1 `op` src2
  | ReadMem Register Register Int  -- dst = [addr reg + offset]
  | WriteMem Register Int Register -- [addr_reg + offset] = src
  | OpSP Operation Register Int      -- SP = SP `op` reg
  | OpPC Operation Register Int      -- PC = PC `op` reg
  | DUMMY
-- | I'll leave out ReadMemOp and WriteMemOp for now, since those aren't
-- | ARM primitive anyway, and can be composed from WriteMem * BinOp, etc.

data Gadget = Gadget { gAbstract    :: [AbGad]       -- abstract type
                     --, gOperation   :: Operation     -- func gadget performs 
                     , gMode    :: Mode
                     , gInsts   :: [Inst]        -- same, but parsed 
                     , gStart       :: Word64        -- initial address of the gadget
                     , gStop        :: Word64        -- last address of gadget 
                     , gSrcRegs     :: [Int]         -- register indices
                     , gDstRegs     :: [Int]         -- register indices
                     --, gSpDelta     :: Int           -- stack ptr delta
                     }

instance Show Gadget where
  show g = let line  = (replicate 60 '-') 
               start = (gStart g)
               stop  = (gStop g)
               step  = if (gMode g) == ArmMode then 4 else 2
           in line ++ "\n" 
              ++ "[" ++ (showHex $ gStart g) ++ "-" 
              ++(showHex $ gStop g)++"]: " ++ 
              (show $ (gStop g) - (gStart g)) ++
              " instructions"
              ++ "\n"++line
              ++(foldl (++) "\n" 
                    (zipWith (\x y -> x++ ":  "++y) -- 4 should be dynamically set
                         (fmap showHex [start,start+step..])
                         (fmap show $ gInsts g)))
              ++ line ++ "\n"
 

isRet :: Mode -> Inst -> Bool
isRet mode inst = (iLay inst) == ARM BlockDataTrans &&
                  pc `elem` (iDst inst) &&
                  sp `elem` (iSrc inst)

isCtrl :: Mode -> Inst -> Bool
isCtrl mode inst = isRet mode inst
                   || (iLay inst == (ARM Branch))

splitUpon :: (a -> Bool) -> [a] -> [[a]]
splitUpon p xs = 
  let first = L.takeWhile (not . p) xs
  in first : [L.drop (length first) xs]


type PreGadget = (Word64, [Inst])

parseIntoPreGadgets :: Mode -> Section -> [PreGadget]
parseIntoPreGadgets mode sec = 
  gad endAddr (reverse insts)
  where
    insts     :: [Inst]
    insts      = parseInstructions mode (code sec)
    startAddr :: Word64
    startAddr  = (addr sec)
    step      :: Word64
    step       = if mode == ArmMode then (-4) else (-2)
    endAddr   :: Word64
    endAddr    = (addr sec) + (size sec) + step
    stride    :: [a] -> Word64
    stride s   = step * (en $ length $ s)
    gad       :: Word64 -> [Inst] -> [(Word64, [Inst])]
    gad _ []   = []
    gad a (x:xs) 
      | isRet mode x =
          let chopped  = splitUpon (isCtrl ArmMode) xs
          in ((a + (stride $ head chopped)), (x:head chopped))
             : gad (a+(stride $ head chopped)+step) 
                   (last chopped) 
      | otherwise      = gad (step + a) xs

gadgetize :: Mode -> [PreGadget] -> [Gadget]
gadgetize _ [] = []
gadgetize mode ((addr,insts):ps) = 
  Gadget { gInsts    = (reverse insts)
         , gMode     = mode
         , gStart    = addr
         , gStop     = (addr + en (length insts))
         , gSrcRegs  = foldr (++) [] (fmap iSrc insts)
         , gDstRegs  = foldr (++) [] (fmap iDst insts) -- do unique
         , gAbstract = [DUMMY]
         } : gadgetize mode ps

parseIntoGadgets :: Mode -> Section -> [Gadget]
parseIntoGadgets m s = gadgetize m $ parseIntoPreGadgets m s

testGadget :: String -> IO ()
testGadget path = do
  secs <- getElfSecs path
  let Just text = L.find ((== ".text") . name) secs
  let gadgets = parseIntoGadgets ArmMode text
  putStrLn $ foldl (++) "" $ map show $ take 32 gadgets
  --putStrLn $  show $ fmap show gadgets
--  putStrLn $ "Number of gadgets: " ++ (show $ length gadgets)
--  let insts = parseInstructions ArmMode (code text)
--  putStrLn $ "Number of rets: " ++ (show $ length $ filter (isRet ArmMode) insts)







