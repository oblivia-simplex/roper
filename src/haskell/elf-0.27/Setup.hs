import Distribution.Simple
import System.Cmd(system)

main = defaultMainWithHooks $ simpleUserHooks { runTests = runElfTests }

runElfTests a b pd lb = system "runhaskell -i./src ./tests/Test.hs" >> return ()
