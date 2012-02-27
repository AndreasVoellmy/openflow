{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards, NamedFieldPuns #-}

module Nettle.Topology.DirectedGraphTopology 
       (
         AdjacencyMatrix(..)
       , Weight
       , Vertex
       , toAdjacencyMatrix
       , fromUndirectedEdges
       , floydWarshall
       , shortestPath                    
       , shortestPathV
       , removeEdge
       , addEdge
       , edges
       , fromUndirectedEdgesMinMax
       , floydWarshallMinMax
       ) where

import Nettle.OpenFlow (SwitchID)       
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Array.IO
import Data.Array.Unboxed
import Data.Array.Base (unsafeWrite, unsafeRead)
import GHC.Arr (unsafeIndex)
import Control.Monad (forM_)
import Text.Printf

type Vertex = Int
type Weight = Int
data AdjacencyMatrix = AdjacencyMatrix { weightArray  :: IOUArray (Vertex,Vertex) Int       
                                       , prevHopArray :: IOUArray (Vertex,Vertex) Vertex
                                       , s2vTable :: Map SwitchID Vertex
                                       , v2sTable :: UArray Vertex SwitchID
                                       }
                                         
                       
edges :: AdjacencyMatrix -> IO [(Vertex,Vertex)]                       
edges (AdjacencyMatrix { prevHopArray }) = 
  do (_, (n,_)) <- getBounds prevHopArray                            
     go n 1 []
  where go n !i acc = if i <= n
                      then go1 n i 1 acc
                      else return acc
        go1 n i j acc = if j <= n 
                        then do v <- readArray prevHopArray (i,j)
                                if v < 0 then  go1 n i (j+1) acc else go1 n i (j+1) ((i,j):acc) 
                        else go n (i+1) acc
        

removeEdge :: AdjacencyMatrix -> Vertex -> Vertex -> IO Weight
removeEdge (AdjacencyMatrix {weightArray,prevHopArray}) u v
  = do weight <- readArray weightArray (u,v)
       writeArray weightArray (u,v) maxBound
       writeArray prevHopArray (u,v) (-1)
       return weight

addEdge :: AdjacencyMatrix -> Vertex -> Vertex -> Weight -> IO ()
addEdge adjMat@(AdjacencyMatrix {weightArray,prevHopArray}) u v weight
  = do writeArray weightArray (u,v) weight
       writeArray prevHopArray (u,v) u
       return ()

toAdjacencyMatrix :: [SwitchID] -> [(SwitchID, SwitchID, Weight)] -> IO AdjacencyMatrix
toAdjacencyMatrix switches links 
  = do d <- newArray myBounds maxBound
       p <- newArray myBounds (-1) 
       let go0 !i = if i > n 
                    then return () 
                    else do unsafeWrite d (unsafeIndex myBounds (i,i)) 0
                            go0 (i+1)
       go0 1
       forM_ links $ \(u,v,weight) ->
         do let !u_n = s2vTable' Map.! u
            let !v_n = s2vTable' Map.! v
            let !ix = unsafeIndex myBounds (u_n, v_n)
            unsafeWrite d ix weight
            unsafeWrite p ix u_n
       return (AdjacencyMatrix d p s2vTable' v2sTable')
  where (v2sTable',s2vTable',myBounds,n) = initLookups switches


fromUndirectedEdges :: [SwitchID] -> [(SwitchID, SwitchID, Weight)] -> IO AdjacencyMatrix
fromUndirectedEdges switches links 
  = do d <- newArray myBounds maxBound
       p <- newArray myBounds (-1) 
       let go0 !i = if i > n 
                    then return () 
                    else do unsafeWrite d (unsafeIndex myBounds (i,i)) 0
                            go0 (i+1)
       go0 1
       forM_ links $ \(u,v,weight) ->
         do let !u_n = s2vTable' Map.! u
            let !v_n = s2vTable' Map.! v
            let !ix = unsafeIndex myBounds (u_n, v_n)
            let !ix' = unsafeIndex myBounds (v_n, u_n)
            unsafeWrite d ix weight
            unsafeWrite d ix' weight
            unsafeWrite p ix u_n
            unsafeWrite p ix' v_n
       return (AdjacencyMatrix d p s2vTable' v2sTable')
  where (v2sTable',s2vTable',myBounds,n) = initLookups switches

initLookups :: [SwitchID] -> (UArray Vertex SwitchID, Map SwitchID Vertex, ((Vertex,Vertex),(Vertex,Vertex)), Vertex)
initLookups switches = myZip switches [] Map.empty 0
  where        
    myZip [] acc acc' !n     = (array (1,n) acc, acc',  ((1,1),(n,n)), n)
    myZip (x:xs) acc acc' !n = let !n' = n+1 
                               in myZip xs ((n',x):acc) (Map.insert x n' acc') n'


copyIOUArray :: IOUArray (Vertex, Vertex) Weight -> IO (IOUArray (Vertex,Vertex) Weight)
copyIOUArray a 
  = do a' <- freeze a :: IO (UArray (Vertex,Vertex) Weight)
       unsafeThaw a'
{-# INLINE copyIOUArray #-}       


floydWarshall :: AdjacencyMatrix -> IO (UArray (Vertex,Vertex) Weight, UArray (Vertex,Vertex) Vertex)
floydWarshall (AdjacencyMatrix wmatrix pmatrix _ _) = 
  do myBounds@(_,(!n,_)) <- getBounds wmatrix
     d <- copyIOUArray wmatrix
     p <- copyIOUArray pmatrix
     let go1 !k !i !j = 
           if j > n 
           then return ()
           else do let !ix = unsafeIndex myBounds (i,j)
                   let !ixkj = unsafeIndex myBounds (k,j)
                   !dij <- unsafeRead d ix 
                   !dik <- unsafeRead d (unsafeIndex myBounds (i,k)) 
                   !dkj <- unsafeRead d ixkj
                   let !dikj = dik `myAdd` dkj
                   if dikj < dij
                     then do unsafeWrite d ix dikj 
                             !pkj <- unsafeRead p ixkj
                             unsafeWrite p ix pkj
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
            
     -- Finish
     d' <- unsafeFreeze d
     p' <- unsafeFreeze p
     return (d',p')


myAdd :: Weight -> Weight -> Weight
myAdd !x !y 
  | x == maxBound = maxBound
  | y == maxBound = maxBound
  | otherwise     = x + y
{-# INLINE myAdd #-}


fromUndirectedEdgesMinMax :: [SwitchID] -> [(SwitchID, SwitchID, Weight)] -> IO AdjacencyMatrix
fromUndirectedEdgesMinMax switches links 
  = do d <- newArray myBounds 0
       p <- newArray myBounds (-1) 
       let go0 !i = if i > n 
                    then return () 
                    else do unsafeWrite d (unsafeIndex myBounds (i,i)) maxBound
                            go0 (i+1)
       go0 1
       forM_ links $ \(u,v,weight) ->
         do let !u_n = s2vTable' Map.! u
            let !v_n = s2vTable' Map.! v
            let !ix = unsafeIndex myBounds (u_n, v_n)
            let !ix' = unsafeIndex myBounds (v_n, u_n)
            unsafeWrite d ix weight
            unsafeWrite d ix' weight
            unsafeWrite p ix u_n
            unsafeWrite p ix' v_n
       return (AdjacencyMatrix d p s2vTable' v2sTable')
  where (v2sTable',s2vTable',myBounds,n) = initLookups switches

floydWarshallMinMax :: AdjacencyMatrix -> IO (UArray (Vertex,Vertex) Weight, UArray (Vertex,Vertex) Vertex)
floydWarshallMinMax (AdjacencyMatrix wmatrix pmatrix _ _) = 
  do myBounds@(_,(!n,_)) <- getBounds wmatrix
     d <- copyIOUArray wmatrix
     p <- copyIOUArray pmatrix
     let go1 !k !i !j = 
           if j > n 
           then return ()
           else do let !ix = unsafeIndex myBounds (i,j)
                   let !ixkj = unsafeIndex myBounds (k,j)
                   !dij <- unsafeRead d ix 
                   !dik <- unsafeRead d (unsafeIndex myBounds (i,k)) 
                   !dkj <- unsafeRead d ixkj
                   let !dikj = min dik dkj
                   if dikj > dij
                     then do unsafeWrite d ix dikj 
                             !pkj <- unsafeRead p ixkj
                             unsafeWrite p ix pkj
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
            
     -- Finish
     d' <- unsafeFreeze d
     p' <- unsafeFreeze p
     return (d',p')



shortestPathV :: UArray (Vertex,Vertex) Vertex -> Vertex -> Vertex -> [Vertex]
shortestPathV dp start end = aux start end [end]
  where aux start end acc 
          | start == end = acc
          | otherwise    = let v = dp ! (start,end)
                           in if v<0 then [] else aux start v (v:acc)


shortestPath :: AdjacencyMatrix -> UArray (Vertex,Vertex) Vertex -> SwitchID -> SwitchID -> [SwitchID]
shortestPath (AdjacencyMatrix {..}) dp start end = 
  aux (s2vTable Map.! end) [end]
  where aux w acc 
          | startV == w = acc
          | otherwise   = let v = dp ! (startV,w)
                          in if v<0 
                             then [] 
                             else aux v ((v2sTable ! v):acc)
        startV = s2vTable Map.! start
{-
  map (\v -> v2sTable ! v) $ 
  shortestPathV dp (s2vTable Map.! start) (s2vTable Map.! end)

-}

