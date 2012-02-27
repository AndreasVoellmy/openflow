{-# LANGUAGE BangPatterns #-}

module Nettle.Topology.Dijkstra where

import Data.PSQueue (PSQ, Binding(..))
import qualified Data.PSQueue as PSQ
import Data.Graph
import Data.Array.IArray
import Data.Array.Unboxed
import Data.List (foldl', sort)

data Distance = Finite !Int !Vertex | Infinite deriving (Show,Eq)

instance Ord Distance where
  compare (Finite n v) (Finite n' v') = compare (n,v) (n',v')
  compare (Finite n _) Infinite    = LT
  compare Infinite   (Finite n' _) = GT
  compare Infinite   Infinite    = EQ
  (Finite n v) <= (Finite n' v') = (n,v) <= (n',v')
  (Finite n _) <= Infinite    = True
  Infinite   <= (Finite n _)  = False
  Infinite   <= Infinite    = True

type Key      = Vertex 
type DijkstraState = (PSQ Key Distance, [(Vertex, Vertex, Int)])


addOneVertex :: Graph -> (Vertex -> Vertex -> Int) -> DijkstraState -> Maybe DijkstraState
addOneVertex graph len (psq, dists) = 
  case ({-# SCC "addOneVertex-findMin" #-} PSQ.findMin psq) of 
    Just (v :-> ed) -> 
      case ed of
        Finite d pred -> 
          let dists' = (v,pred,d):dists
              psq''  = {-# SCC "addOneVertex-psq" #-} foldl' (updateVertex d v) (PSQ.deleteMin psq) (graph ! v)
          in Just (psq'', dists')
        Infinite -> Nothing
    Nothing -> Nothing
  where 
    updateVertex d v psq w = {-# SCC "updateVertex" #-}
      case PSQ.lookup w psq of 
        Just Infinite -> let !d'' = d + len v w 
                         in PSQ.adjust (\_ -> Finite d'' v) w psq
        Just (Finite d' _) -> 
          let !d'' = d + len v w  
          in if d' <= d''
             then psq
             else PSQ.adjust (\_ -> Finite d'' v) w psq
        Nothing -> psq
        

{-
    updateVertex d v psq w = {-# SCC "updateVertex" #-}
      PSQ.adjust adjustment w psq
      where adjustment p@(Finite d' _) = 
              let d'' = d + len v w in if d' <= d'' then p else Finite d'' v
            adjustment Infinite = 
              Finite (d + len v w) v
-}

initState :: Graph -> (Vertex -> Vertex -> Int) -> Vertex -> DijkstraState
initState gr eDict v = (psq, [(v,v,0)])
  where psq = PSQ.fromList ( [ w :-> Finite (eDict v w) v | w <- gr ! v ] ++
                             [ w :-> Infinite | w <- xs, w/=v ] )
        xs = vertices gr `minus` (sort (gr ! v))


-- Warning: This assumes all vertices are reachable.
dijkstra :: Graph -> (Vertex -> Vertex -> Int) -> Vertex -> UArray Vertex Vertex
dijkstra gr eDict v = 
  array (bounds gr) $  
  map (\(a,b,c) -> (a,b)) $ 
  dijkstra_ gr eDict v
  
shortestPath :: UArray Vertex Vertex -> Vertex -> Vertex -> [Vertex]  
shortestPath a s t = go t [t]
  where go u acc
          | u == s    = acc
          | otherwise = let u' = a ! u in go u' (u':acc)

dijkstra_ :: Graph -> (Vertex -> Vertex -> Int) -> Vertex -> [(Vertex, Vertex, Int)]
dijkstra_ gr eDict v = 
  go (initState gr eDict v)
  where 
    go st = case addOneVertex gr eDict st of
      Nothing -> snd st
      Just st' -> go st'

-- assumes both lists are ordered. Both have no repeats.
minus :: Ord a => [a] -> [a] -> [a]              
minus [] _  = []
minus xs [] = xs
minus (x:xs) (y:ys) = 
  case compare x y of
    EQ -> minus xs ys
    LT -> x : minus xs (y:ys)
    GT -> x : minus xs ys

