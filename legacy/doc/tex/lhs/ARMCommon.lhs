\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{amssymb}
\usepackage{amsmath}
\usepackage{listings}
\let\oldemptyset\emptyset
\let\emptyset\varnothing
\usepackage{parskip}
\usepackage{fancyvrb}

\title{Appendix: Code Used by Both Thumb and ARM Grammars}
\author{Olivia Lucca Fraser\\B00109376}
\date{\today}

%include polycode.fmt

\begin{document}

\maketitle

\section{Imports}

There is a considerable amount of code that can be reused between the
Thumb and ARM modules, which I have gathered together in this file.

First, let's begin by importing a few modules.

\begin{code}
module ARMCommon where

import Aux
import Data.Word
import Data.Bits
import Data.List
import Data.Tuple
import Data.Maybe

\end{code}

\section{Types}

Now, let's define some types that we'll be using in each module.
Regardless of whether we're using the ARM or Thumb modes, the size
of the registers remains constant at 32.\footnote{We are sticking to the 32-bit ARM-7 specifications in this parser, though a 64-bit model of the ARM also exists.}

\begin{code}
type Register = Word32
registerSize = 32
type CPSR = Register
type Operation   = (CPSR -> Register -> Register -> Register
                      -> (CPSR, Register))
\end{code}

The same register set is used in both Thumb and ARM mode, so we'll keep
the same register contents in both.

\begin{code}
fp = 11 :: Int
sp = 13 :: Int
lr = 14 :: Int
pc = 15 :: Int

highbit :: Register -> Register
highbit = (.&. bit (registerSize - 1))
\end{code}


The CPSR (flag register) mechanics are the same in both ARM and Thumb
mode, so let's put everything pertaining to the CPSR here.

A few words on the flags:

\begin{itemize}
  \item The M flags are meant to be read together, as a nibble (a 4-bit word),
        and determine the processor mode.
          \begin{tabular}{l | l | l}
          Bits & Mode & Register Set \\
          0000 & User & R0-R14, CPSR, PC \\
          0001 & FIQ (fast interrupt request)  & R0-R7, R8_fiq-R14_fiq, CPSR, SPSR_fiq, PC \\
          0010 & IRQ & R0-R12, R13_irq, CPSR, SPSR_irq, PC \\
          0011 & SVC (supervisor) & R0-R12, R13_abt-R14_abt, CPSR, SPSR_abt, PC \\
          0111 & ABT (abort) & R0-R12, R13_abt-R14_abt, CPSR, SPSR_abt, PC \\
          1101 & HYP (hypervisor, when supported) & ? \\ %%% Not sure. fill in.
          1011 & UND (undefined) & R0-R12, R13_und-R14_und, CPSR, SPSR_und, PC \\
          1111 & SYS (system) & R0-R14, CPSR, PC \\
          \end{tabular} %
        User mode is the only mode in this list with restricted privileges, and
        the only which cannot freely switch to another mode of its own accord.
        The others are reserved for kernel and, where supported, hypervisor
        operations, and enjoy escalated privileges (analogous to Ring 0 and Ring
        -1 on x86/x86_64 architectures).
  \item The T flag is a one-bit flag that indicates whether to parse and execute
        instructions in 16-bit Thumb mode (1) or 32-bit ARM mode (0).  
\footnote{Following \url{www.heyrick.co.uk/armwiki/The_Status_Register}, supplementing with information from \url{www.keil.com/support/man/docs/armasm/armasm_dom1359731126962.htm}, and Ch. 2 of Dang et al, \emph{Practical Reverse Engineering}, [BIBLIO INOFO].}

\end{itemize}

There is another register called the "saved processor status register",
(SPSR) whose layout varies by mode, and which is used in the various
non-user processor modes. We won't be dealing with that just yet.

\begin{code}
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

\end{code}

\section{Higher Order Functions for Manipulating Operation Instances}

As we've seen, the signature of the Operation type is a slightly awkward and ungainly thing, and so it would be convenient to have a few auxiliary functions that will help us smoothly compose and recombine these operations without having to tend too much to their internal structure. The following functions represent the beginning of a solution to this problem.

\begin{code}

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

\end{code}

\end{document}
