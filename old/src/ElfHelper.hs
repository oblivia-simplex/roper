module ElfHelper where

import Data.Elf
import Data.List
import qualified Data.ByteString as BS
import Data.Word
import GHC.Int
import Control.Monad

data Section = Section { name :: String
                       , addr :: Word64
                       , size :: Word64
                       , code :: BS.ByteString
                       }

getElfSecs :: String -> IO [Section]
getElfSecs filename  = do
  c    <- BS.readFile filename
  let elf = parseElf c
  let secs = elfSections elf
  return $ map (\s -> Section (elfSectionName s) 
                              (elfSectionAddr s)
                              (elfSectionSize s) 
                              (elfSectionData s)) secs

testElf :: IO ()
testElf = do
  si <- getElfSecs "data/ldconfig.real"
  putStrLn $ show $ map name si
  let text = (filter ((== ".text") . name) si) !! 0
  putStrLn $ (show $ name text) ++ ", " ++ (show $ addr text)
  return ()
   
