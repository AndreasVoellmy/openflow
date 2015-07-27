module Network.Data.Util
       (
         concatIntersperse
       , unConcatIntersperse
       ) where

import Data.List (intersperse)

-- Specifications: 
-- (A) unConcatIntersperse c . concatIntersperse [c] == id

concatIntersperse :: [a] -> [[a]] -> [a]
concatIntersperse xs = concat . intersperse xs

unConcatIntersperse :: Eq a => a -> [a] -> [[a]]
unConcatIntersperse c s =
  let (r,t) = break (==c) s
  in r : case t of { [] -> []; _:t' -> unConcatIntersperse c t' }

