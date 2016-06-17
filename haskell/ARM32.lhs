|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|
                _______
 __ _ _ _ _ __ |__ /_  )
/ _` | '_| '  \ |_ \/ /
\__,_|_| |_|_|_|___/___|

|>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<>><<|

All of the ARM-specific code should go into this module, as far as
possible, though shortcuts might be taken in the early stages of dev-
elopment.

Things that need doing:
- functions to classify instructions by type and effects

\begin{code}
module ARM32 where
import Data.Word
import Data.Bits

popPCp :: Word32 -> Bool
popPCp inst = (inst .&. 0xFFFF0000 == 0xe8bd0000) -- is it a POP ?
               && ((inst .&. (shift 1 15)) /= 0)  -- does it pop into PC?



\end{code}
