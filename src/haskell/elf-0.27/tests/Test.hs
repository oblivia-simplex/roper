module Main where

import Data.Elf
import System.IO
import Test.HUnit
import Control.Monad
import qualified Control.Exception as E
import qualified Data.ByteString as B

testEmptyElf = withBinaryFile "./tests/empty.elf" ReadMode $ \h -> do
    fil <- B.hGetContents h
    res <- E.try (E.evaluate (parseElf fil)) :: IO (Either E.SomeException Elf)
    case res of
        Left  e -> return ()
        Right a -> assertFailure "Empty ELF did not cause an exception."

tests = TestList
    [ TestLabel "Empty ELF" $ TestCase testEmptyElf
    ]

main = runTestTT tests
