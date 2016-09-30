
This file contains the implementation-independent gadget logic.

I'm taking some inspiration from github.com/programma-stic/ropc-llvm and
its predecessor, github.com/pakt/ropc.

We're not going to sweat too much about platform independence just yet,
so we'll do things the easy way and refactor as we go. 
\begin{code}
import ARMCommon (Register
                 ,Operation)
\end{code}

\begin{code}

-- lifting a lot of this from common.ml in ropc-llvm, and translating it from
-- ocaml to haskell.
data AbGad = -- abstract gadget
    LoadConst Register Int    -- reg, stack offset
  | CopyReg Register Register      -- dst reg = src reg
  | BinOp Register Register Op     -- dst reg = src1 `op` src2
  | ReadMem Register Register Int  -- dst = [addr reg + offset]
  | WriteMem Register Int Register -- [addr_reg + offset] = src
  | OpSP Op Register Int      -- SP = SP `op` reg
  | OpPC Op Register Int      -- PC = PC `op` reg
  deriving (Show, Eq)

-- I'll leave out ReadMemOp and WriteMemOp for now, since those aren't
-- ARM primitive anyway, and can be composed from WriteMem * BinOp, etc.

data Gadget = Gadget { g_abstract    :: AbGad  -- the abstract type of gadget
                     , g_codebytes   :: BC.ByteString-- the code of the gadget itself
                     , g_codewords   :: [Word32]-- same, but in 32 bit words
                     , g_start   :: Word64     -- initial address of the gadget
                     , g_stop    :: Word64     -- last address of gadget, incl. 
                     , g_ctrl   :: String      -- a keyword would be better...
                     , g_src  :: [Word32]      -- register indices
                     , g_dst :: [Word32]       -- register indices
                     , g_spD :: Int        -- stack ptr delta
                     }



\end{code}
