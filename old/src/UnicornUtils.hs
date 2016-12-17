module UnicornUtils where
import Unicorn
import Unicorn.Hook
import qualified Unicorn.CPU.Arm as Arm
import qualified Unicorn.Internal.Core
import qualified Numeric as N (showHex)
import Control.Monad
import GHC.Int
-- | This module just contains a few handy utility functions
-- | that make coding with unicorn a bit easier for me.

-- | A convenience function for fetching arm registers
r :: Integral a => a -> Arm.Register
r n = case n of
  0  -> Arm.R0
  1  -> Arm.R1
  2  -> Arm.R2
  3  -> Arm.R3
  4  -> Arm.R4
  5  -> Arm.R5
  6  -> Arm.R6
  7  -> Arm.R7
  8  -> Arm.R8
  9  -> Arm.R9
  10 -> Arm.R10
  11 -> Arm.R11
  12 -> Arm.R12
  13 -> Arm.R13 -- SP
  14 -> Arm.R14 -- LR
  15 -> Arm.R15 -- PC
  otherwise -> error $ "Invalid register: " ++ 
               (show . fromIntegral) n

setRegisters :: Engine -> [Maybe Int64] -> Emulator ()
setRegisters _ [] = do
  return ()
setRegisters uc (x:xs) = do
  case x of
    Just n -> regWrite uc (r (length xs)) n
    Nothing -> return ()
  setRegisters uc xs
  return ()
--setRegisters = undefined

setRegisters' :: Integral a => Engine -> [a] -> Emulator ()
setRegisters' uc raws = do
  let xs = map (Just . fromIntegral) raws
  setRegisters uc xs

{-
readRegisters :: Engine -> Emulator [Int64]
readRegisters uc = do
  let regs = map r [0..15]
  vals <- map (regRead uc) regs
  return  vals
 where cleanup v = case v of
                      Left v -> v
                      Right e -> 0 --- fake it till you make it
:w
 pretty-printer for hex (borrowed from SampleArm.hs)
-}
