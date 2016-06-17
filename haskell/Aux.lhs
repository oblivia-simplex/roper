A Collection of auxiliary and convenience functions.

\begin{code}
module Aux where
import Data.Word

bin :: [Char] -> Word32
bin bitstring =
  rbin (reverse $ fmap digitize bitstring) 0
  where rbin [] _ = 0
        rbin (b:bs) e = (b * (2)^e) + rbin bs (e+1)
        digitize c
          | c == '0' = 0
          | c == '1' = 1
          | otherwise = error "Invalid bitstring"

\end{code}
