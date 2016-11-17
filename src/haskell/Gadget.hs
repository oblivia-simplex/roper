module Gadget where

import Control.Monad.Random
import System.Random
import ARMCommon (Register
                 ,Operation)
import ARMParser
import Aux
import Data.Word
import qualified Data.List as L
import Data.Bits
import Control.Monad
import Control.Applicative
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
  | Immediate
  | DUMMY
-- | I'll leave out ReadMemOp and WriteMemOp for now, since those aren't
-- | ARM primitive anyway, and can be composed from WriteMem * BinOp, etc.
type Address = Word64

data Gadget = Gadget { gAbstract    :: [AbGad]       -- abstract type
                     --, gOperation   :: Operation     -- func gadget performs 
                     , gMode        :: Mode
                     , gInsts       :: [Inst]        -- same, but parsed 
                     , gStart       :: Address        -- initial address of the gadget
                     , gSrcRegs     :: [Int]         -- register indices
                     , gDstRegs     :: [Int]         -- register indices
                     , gSpDelta     :: Int           -- stack ptr delta
                     }

-- Sometimes a "gadget" will just be an immediate
-- value: 0xFFFFFFFF in gStart, for example, and
-- nothing else. 

instance Show Gadget where
  show g = let line  = replicate 60 '-'
               start = gStart g
               len   = length (gInsts g)
               stop  = (en $ gStart g) + len
               step  = stepSize (gMode g)
           in line ++ "\n" 
              ++ "[" ++ (showHex $ gStart g) ++ "-" 
              ++ showHex stop
              ++ "]: " 
              ++ show len
              ++ " instructions; SP moves "++(show $ gSpDelta g)
              ++ "\n"++line
              ++ foldl (++) "\n" 
                    (zipWith (\x y -> x++ ":  "++y) 
                         (showHex <$> [start,start+step..])
                         (show <$> gInsts g))
              ++ line ++ "\n"
 
isRet :: Inst -> Bool
isRet inst = isPop inst &&
             pc `elem` (iDst inst) &&
             sp `elem` (iSrc inst)

isCtrl :: Inst -> Bool
isCtrl inst = isRet inst
              || (iLay inst == (ARM Branch))
              || (pc `elem` (iDst inst))
              || (sp `elem` (iDst inst))

isPop :: Inst -> Bool
isPop inst = 
  case iLay inst of
    ARM (BlockDataTrans m) -> m == LDMFD || m == LDMED
    otherwise              -> False
    
isPush :: Inst -> Bool
isPush inst =
  case iLay inst of
    ARM (BlockDataTrans m) -> m == STMFD || m == STMED
    other                  -> False

splitUpon :: (a -> Bool) -> [a] -> [[a]]
splitUpon p xs = 
  let first = L.takeWhile (not . p) xs
  in first : [L.drop (length first) xs]

spDelta :: Inst -> Int
spDelta inst
  | isPop  inst = length (iDst inst)
  | isPush inst = (-1) * length (iSrc inst) 
  | otherwise   = 0


stepSize :: Mode -> Address
stepSize ArmMode   = (4)
stepSize ThumbMode = (2)
 

type PreGadget = (Address, [Inst])

parseIntoPreGadgets :: Mode -> Section -> [PreGadget]
parseIntoPreGadgets mode sec = 
  gad endAddr (reverse insts)
  where
    insts     :: [Inst]
    insts      = parseInstructions mode (code sec)
    startAddr :: Address
    startAddr  = (addr sec)
    step      :: Address
    step       = (- stepSize mode)
    endAddr   :: Address
    endAddr    = (addr sec) + (size sec) + step
    stride    :: [a] -> Address
    stride s   = step * (en $ length $ s)
    gad       :: Address -> [Inst] -> [(Address, [Inst])]
    gad _ []   = []
    gad a (x:xs) 
      | isRet x =
          let chopped  = splitUpon isCtrl xs
          in ((a + (stride $ head chopped)), (x:head chopped))
             : gad (a+(stride $ head chopped)+step) 
                   (last chopped) 
      | otherwise      = gad (step + a) xs

-- | Build the full gadget from the data in the pregadget
-- | we could do this in a single pass, but it's not terribly
-- | time sensitive, and this seems more manageable. 
gadgetize :: Mode -> [PreGadget] -> [Gadget]
gadgetize _ [] = []
gadgetize mode ((addr,insts):ps) 
  -- place other filter conditions here, if desired 
  | (length insts) <= 1  = gadgetize mode ps
  | otherwise            =
      Gadget { gInsts    = (reverse insts)
             , gMode     = mode
             , gStart    = addr
             , gSrcRegs  = L.nub $ foldr (++) [] (fmap iSrc insts)
             , gDstRegs  = L.nub $ foldr (++) [] (fmap iDst insts) 
             , gSpDelta  = foldr (+) 0 $ map spDelta insts
             , gAbstract = [DUMMY]
             } : gadgetize mode ps

parseIntoGadgets :: Mode -> Section -> [Gadget]
parseIntoGadgets m s = gadgetize m $ parseIntoPreGadgets m s

packAddr :: Int -> Gadget -> BS.ByteString
packAddr size g = BS.pack $ wordLEBytes (en $ gStart g) size

packChain :: Int -> [Gadget] -> BS.ByteString
packChain wordsize gs = foldr (.++.) BS.empty $ map (packAddr wordsize) gs

unicornPack :: [Gadget] -> BS.ByteString
unicornPack gs = packChain 4 gs

-- now we need a func to build random chains, for testing
-- purposes, and to seed the population with a little noise

rndChain :: (RandomGen g) => g -> [a] -> [a]
rndChain g xs = map (\i -> xs !! i) $ randomRs (0, (length xs)-1) g

streamChunks :: Int -> [a] -> [[a]]
streamChunks _ [] = []
streamChunks n xs = let (a,b) = splitAt n xs
                    in  a : streamChunks n b

mkRndChains :: (RandomGen g) => g -> Int -> Int -> [a] -> [[a]]
mkRndChains g num size xs = 
  take num $ streamChunks size $ rndChain g xs

mkImmGadget :: Integral a => a -> Gadget
mkImmGadget w = Gadget { gStart    = fromIntegral w
                       , gAbstract = [Immediate]
                       , gInsts    = []
                       , gDstRegs  = []
                       , gSrcRegs  = []
                       }

testGadget :: Int -> String -> Int -> Int -> IO ()
testGadget seed path gadnum chainsize = do
  secs <- getElfSecs path
  let Just text = L.find ((== ".text") . name) secs
  let gadgets = parseIntoGadgets ArmMode text
  let g = (mkStdGen seed)
  let r = mkRndChains g gadnum chainsize gadgets 
  putStrLn $ show r
  putStrLn "packed:"
  putStrLn $ show $ map unicornPack r
--  let insts = parseInstructions ArmMode (code text)
--  putStrLn $ "Number of rets: " ++ (show $ length $ filter (isRet ArmMode) insts)







