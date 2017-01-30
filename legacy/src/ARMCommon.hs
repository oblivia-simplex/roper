
module ARMCommon where

import Aux
import Data.Word
import Data.Bits
import Data.List
import Data.Tuple
import Data.Maybe


type Register = Word32
registerSize = 32
type CPSR = Register
type Operation   = (CPSR -> Register -> Register -> Register
                      -> (CPSR, Register))

fp = 11 :: Int
sp = 13 :: Int
lr = 14 :: Int
pc = 15 :: Int

highbit :: Register -> Register
highbit = (.&. bit (registerSize - 1))

data Flag =
    Tflag   -- enables Thumb mode
  | Fflag   -- disables FIQ interrupts
  | Iflag   -- disables IRQ interrupts
  | Aflag   -- disables imprecise aborts
  | Jflag   -- enables Jazelle mode (natively run Java bytecode)
  | Zflag   -- Zero condition
  | Cflag   -- Carry bit
  | Qflag   -- underflow or saturation (in E-variants of ARM)
  | Vflag   -- Overflow condition
  | Nflag   -- Negative condition
  deriving (Eq, Show)
instance Enum Flag where
  fromEnum = fromJust . flip lookup flagTable
  toEnum   = fromJust . flip lookup (map swap flagTable)
flagTable = [
   (Tflag, 5)
  ,(Fflag, 6)
  ,(Iflag, 7)
  ,(Aflag, 8)
  ,(Jflag, 24)
  ,(Qflag, 27)
  ,(Vflag, 28)
  ,(Cflag, 29)
  ,(Zflag, 30)
  ,(Nflag, 31)
  ]

data Cond = C_EQ | C_NE | C_CS | C_CC | C_MI | C_PL | C_VS | C_VC |
            C_HI | C_LS | C_GE | C_LT | C_GT | C_LE | C_AL |
            C_RESERVED deriving (Show, Enum)


-- take a list of flags and pack them into a 32-bit bitmap
-- (the CPSR register)
aspr :: [Flag] -> CPSR
aspr = foldl' (.|.) 0 . map (bit . fromEnum)

testFlag :: CPSR -> Flag -> Bool
testFlag r f = testBit r (fromEnum f)

--  Return Negative? and Zero? flags if they need to be set
--  based on the value in Register r
setNZFlags :: Register -> [Flag]
setNZFlags r = let res = fromIntegral r in
  []
  ++ if (res < 0) then [Nflag] else []
  ++ if (res == 0) then [Zflag] else []



--  Return True if the result of an add (or sub) operation res
--  indicates an overflow with respect to its operands x and y
--  (This is done by testing the high bit in each.)
overflow :: Register -> Register -> Register -> Bool
overflow x y res =
  hx == hy && hy /= hr
  where [hx, hy, hr] = map highbit [x, y, res]


--  It would be nice to have a type class that lets us
--  deal with mnemonics in general. Let's do that.
class (Enum a, Eq a, Show a) => Mnemonic a where
  additive :: a -> Bool
  additive _ = False
  writeR   :: a -> Bool
  writeR   _ = True      -- True if the operation writes to register, False otherwise
  setCPSR  :: a -> Bool
  setCPSR  _ = True
  ctrlFlow :: a -> Bool
  ctrlFlow _ = False

class (Eq a, Show a) => Format a



--  carry over the APSR from the first op to the
--  second, and take the dst reg of the first op
--  as the x (first operand) of the second op
(@<) :: Operation -> Operation -> Operation
op2 @< op1 = compL
  where compL a1 x y d = (op2 a2 d2 y d)
          where (a2, d2) = op1 a1 x y d

--  carry over the APSR from the first op to the
--  second, and take the dst reg of the first op
--  as y (second operand) for the second op
(@>) :: Operation -> Operation -> Operation
op2 @> op1 = compR
  where compR a1 x y d = (op2 a2 x d2 d)
          where (a2, d2) = op1 a1 x y d

--  carry over the APSR from the first op to the
--  second, and take the dst reg of the first op
--  as x and y for the second op
(@<>) :: Operation -> Operation -> Operation
op2 @<> op1 = comp
  where comp a1 x y d = (op2 a2 d2 d2 d)
          where (a2, d2) = op1 a1 x y d

-- It would probably make sense to define a state monad or
-- applicative that carries the APSR information across the
-- operations, and lets us use them as ordinary binary ops.
-- This is on the TODO list.

-- you could also maintain the entire cpu context as a
-- state monad's state. But that's getting a bit heavy handed,
-- and we have an emulator for that. 


-- Now, we need to actually fill in the Operand 1, Operand 2, Dst
-- fields. Maybe this information should be stowed up in the
-- inst record, for easy access. Or perhaps called from an
-- "apply operation" function that populates the operand fields
-- and executes the operation function.

