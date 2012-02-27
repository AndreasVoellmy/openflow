{-# LANGUAGE BangPatterns #-}

-- | Implements the Floyd-Warshall algorithm for computing all-pairs shortest paths 
-- from a weighted directed graph. 
module Nettle.Topology.FloydWarshall (
  floydWarshall
  , floydWarshall2  
  , floydWarshall3
  , shortestPath
  , shortestPath3
  ) where

import Data.Array.MArray
import Data.Array.IArray
import Data.Array.ST
import Control.Monad
import Data.Map (Map)
import qualified Data.Map as Map
import Nettle.Topology.ExtendedDouble
import Nettle.Topology.LabelledGraph


-- import Data.Array.Unboxed
import Control.Monad.ST	( ST, runST )
import Data.Array.Base	( STUArray, castSTUArray, UArray, unsafeFreezeSTUArray )
import Data.Graph (Vertex)
import Nettle.OpenFlow (SwitchID)

import Data.Array.Base
import GHC.Arr (unsafeIndex)


-- type Vertex = SwitchID 

shortestPath3 :: UArray (Vertex,Vertex) Vertex -> Vertex -> Vertex -> [Vertex]
shortestPath3 dp start end = aux start end [end]
  where aux start end acc 
          | start == end = acc
          | otherwise    = let v = dp ! (start,end)
                           in if v<0 then [] else aux start v (v:acc)



-- assume it is not a multi-graph
floydWarshall3 :: LabelledGraph SwitchID e -> (UArray (Vertex,Vertex) Int, UArray (Vertex,Vertex) Vertex)
floydWarshall3 lgraph = 
  let myBounds = ((1,1),(n,n)) in
  runST (do -- initialization
            d <- newArray ((1,1), (n,n)) maxBound
            p <- newArray ((1,1), (n,n)) (-1) 
            
            forM_ (Map.toList $ sourceTarget lgraph) $ \(e, ((u,v), weight)) ->
              do let u_n = node2number Map.! u
                 let v_n = node2number Map.! v
                 let ix = unsafeIndex myBounds (u_n, v_n)
                 unsafeWrite p ix u_n -- writeArray p (u_n,v_n) u_n
                 unsafeWrite d ix (round weight) -- writeArray d (u_n,v_n) (round weight)
                 
            let go0 !i = if i > n then return () else (writeArray d (i,i) 0 >> go0 (i+1))
            go0 1
            -- forM_ [1..n] $ \i -> writeArray d (i,i) 0
            
            -- Main computation
            let go1 !k !i !j = {-# SCC "FW-go1" #-}
                  if j > n 
                  then return ()
                  else do let !ix = unsafeIndex myBounds (i,j)
                          let !ixkj = unsafeIndex myBounds (k,j)
                          !dij <- unsafeRead d ix -- (unsafeIndex myBounds (i,j)) -- readArray d (i,j) 
                          !dik <- unsafeRead d (unsafeIndex myBounds (i,k)) -- readArray d (i,k)
                          !dkj <- unsafeRead d ixkj --(unsafeIndex myBounds (k,j)) -- readArray d (k,j)
                          let !dikj = dik `myAdd` dkj
                          if dikj < dij
                            then do unsafeWrite d ix dikj -- writeArray d (i,j) dikj
                                    !pkj <- unsafeRead p ixkj -- (unsafeIndex myBounds (k,j)) -- readArray p (k,j)
                                    unsafeWrite p ix pkj -- writeArray p (i,j) pkj
                            else return ()
                          go1 k i (j+1)
            let go2 !k !i =                 
                  if i > n 
                  then return ()
                  else go1 k i 1 >> go2 k (i+1) 
            let go3 !k = 
                  if k > n
                  then return ()
                  else do go2 k 1 
                          go3 (k+1) 
            go3 1
            
            
{-            
            forM [1..n] $ \k ->
              forM [1..n] $ \i -> 
              forM [1..n] $ \j -> 
              do dij <- readArray d (i,j)
                 dik <- readArray d (i,k)
                 dkj <- readArray d (k,j)
                 let dikj = dik `myAdd` dkj
                 if dikj < dij
                   then do writeArray d (i,j) dikj
                           pkj <- readArray p (k,j)
                           writeArray p (i,j) pkj
                   else return ()
-}                        
            -- Finish
            d' <- unsafeFreezeSTUArray d
            p' <- unsafeFreezeSTUArray p
            return (d',p')
        )
  where n = numberOfNodes lgraph
        node2number :: Map.Map SwitchID Vertex
        node2number = Map.fromList (zip (nodes lgraph) [1..])
        -- TODO: guard against overflow!

myAdd :: Int -> Int -> Int
myAdd !x !y 
  | x == maxBound = maxBound
  | y == maxBound = maxBound
  | otherwise     = x + y
{-# INLINE myAdd #-}

-- | The input is a matrix where the @(i,j)@ entry contains the distance of a path
-- going from node @i@ to node @j@ in the graph as well as the next hop node in the path and a value
-- (left polymorphic, of type @a@ here) representing the link (e.g. a link identifier, particularly useful if there can
-- more than one link between nodes). If the distance is |Infinity| then the next hop and link identifier should be |Nothing|. 
-- Typically, this function is applied to an array in which @(i,j)@ value contains the distance and the link ID for one link from
-- @i@ to @j@.
floydWarshall ::  Array (Int,Int) (ExtendedDouble, Maybe (Int, a)) -> Array (Int,Int) (ExtendedDouble, Maybe (Int, a))
floydWarshall input = 
  runSTArray $
  do d <- thaw input 
     forM [1..n] $ \k ->
       forM [1..n] $ \i -> 
       forM [1..n] $ \j -> 
         do (dij, predij) <- readArray d (i,j)
            (dik, predik) <- readArray d (i,k)
            (dkj, predkj) <- readArray d (k,j)
            let dikj = dik `addExtendedDouble` dkj
            when (dikj < dij) (writeArray d (i,j) (dikj, predkj))
     return d
  where (_, (n,_)) = bounds input



floydWarshall2 :: Ord n => LabelledGraph n a -> Array (Int,Int) (ExtendedDouble, Maybe (Int, a))
floydWarshall2 lgraph = 
  runSTArray $
  do d <- newArray ((1,1), (n,n)) (Infinity, Nothing)
     forM_ [1..n] $ \i -> 
       writeArray d (i,i) (Finite 0, Nothing)
     forM_ (Map.toList $ sourceTarget lgraph) $ \(e, ((u,v), weight)) ->
       do let u_nbr = node2number Map.! u
          let v_nbr = node2number Map.! v          
          let ed = Finite weight
          (ed', _) <- readArray d (u_nbr, v_nbr)
          if ed < ed'
            then writeArray d (u_nbr,v_nbr) (ed, Just (u_nbr, e))
            else return ()
                 

     let go1 !k !i !j = 
           if j > n 
           then return ()
           else do (dij, predij) <- readArray d (i,j)
                   (dik, predik) <- readArray d (i,k)
                   (dkj, predkj) <- readArray d (k,j)
                   let dikj = dik `addExtendedDouble` dkj
                   when (dikj < dij) (writeArray d (i,j) (dikj, predkj))
                   go1 k i (j+1)
     let go2 !k !i =                 
           if i > n 
           then return ()
           else go1 k i 1 >> go2 k (i+1) 
     let go3 !k = 
           if k > n
           then return ()
           else do go2 k 1 
                   go3 (k+1) 
     go3 1                   
{-
     forM [1..n] $ \k ->
       forM [1..n] $ \i -> 
       forM [1..n] $ \j -> 
         do (dij, predij) <- readArray d (i,j)
            (dik, predik) <- readArray d (i,k)
            (dkj, predkj) <- readArray d (k,j)
            let dikj = dik `addExtendedDouble` dkj
            when (dikj < dij) (writeArray d (i,j) (dikj, predkj))
-}
     return d
  where n = numberOfNodes lgraph 
        node2number = Map.fromList (zip (nodes lgraph) [1..])

-- | Extracts the shortest path from the matrix computed by |floydWarshall|. The path includes the
-- the nodes and the links of the path.
shortestPath :: Array (Int, Int) (ExtendedDouble, Maybe (Int, a)) -> (Int, Int) -> Maybe [a]
shortestPath dp (start, end) = aux start end []
  where aux start end acc 
          | start == end = Just acc
          | otherwise    = 
            case snd (dp ! (start,end)) of 
              Nothing -> Nothing
              Just (prev,a) -> aux start prev (a:acc)


path :: Array (Int, Int) (ExtendedDouble, Maybe Int) -> (Int, Int) -> Maybe [Int]
path dp (start, end) = 
  let (_, mprev) = dp ! (start, end)
  in case mprev of 
    Nothing   -> Nothing
    Just prev -> aux start prev [end]
  where aux start end acc 
          | start == end = Just acc
          | otherwise    = 
            let (_,mprev) = dp ! (start,end) 
            in case mprev of 
              Nothing -> Nothing
              Just prev -> aux start prev (end : acc)

pathMap :: Array (Int, Int) (ExtendedDouble, Maybe Int) -> Map (Int,Int) [Int]
pathMap dp 
  = Map.fromList $ [ (k, p) | (k,_) <- assocs dp, Just p <- [path dp k] ]


