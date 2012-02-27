-- | This module implements a data type of directed graphs
-- where there may be multiple edges between a pair of vertices.
-- There are a variety of ways to think of this: 
-- As two finite sets @V@, @E@ with two maps source, target : @E -> V@.
-- As a finite Set @V@, a finite set of labels @L@, and a ternary relation as a subset of @(V,L,V)@. 
module Nettle.Topology.LabelledGraph (
  LabelledGraph (sourceTarget)
  , Weight
    -- * Construction
  , empty
  , addNode
  , addEdge
  , addEdges
  , adjustEdgeWeight
  , deleteNode
  , deleteEdge
    -- * Query
  , nodes
  , numberOfNodes
  , edgesOutOf
  , edgesFromTo
  , edges
    -- * Path tree
  , LTree(..)
  , pathTree
  , mapLTree
  , drawTree
  ) where

import Data.List (minimumBy)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Map (Map, (!))
import qualified Data.Map as Map
import Nettle.Topology.ExtendedDouble
import Data.Maybe

data LabelledGraph n e = 
  LabelledGraph { sourceTarget :: Map e ((n, n), Weight)
                , edgesLeaving :: Map n (Map e (n, Weight))
                }
  deriving (Show)
           

type Weight = Double

nodes :: Ord n => LabelledGraph n e -> [n]
nodes lg = Map.keys $ edgesLeaving lg 

numberOfNodes :: Ord n => LabelledGraph n e -> Int
numberOfNodes lg = Map.size (edgesLeaving lg)

weightOf :: Ord e => e -> LabelledGraph n e -> Weight
weightOf e lg = snd $ sourceTarget lg ! e

source :: (Ord n, Ord e) => LabelledGraph n e -> e -> n
source g e = fst (fst (sourceTarget g ! e))

edges :: LabelledGraph n e -> [(e, Weight)]
edges (LabelledGraph { sourceTarget = sourceTarget }) = Map.assocs $ Map.map snd sourceTarget

shortestEdgeFromTo :: (Ord e, Ord n) => n -> n -> LabelledGraph n e -> Maybe (e,Weight)
shortestEdgeFromTo s t g 
  = case edgesFromTo s t g of
      []     -> Nothing
      (e:es) -> Just (minimumBy (\e1 e2 -> compare (snd e1) (snd e2)) (e:es))

edgesFromTo :: (Ord e, Ord n) => n -> n -> LabelledGraph n e -> [(e,Weight)]
edgesFromTo u v (LabelledGraph { edgesLeaving = edgesLeaving, sourceTarget = sourceTarget })
  = Map.toList $ Map.map snd $ Map.filter (\(v',_) -> v==v') (edgesLeaving ! u)
--  = Map.toList $ Map.map snd $ Map.filter (\((u',v'),_) -> u == u' && v == v') sourceTarget

edgesOutOf :: (Ord e, Ord n) => n -> LabelledGraph n e -> [(e, n)]
edgesOutOf u lg =
    map (\(e, (t,w)) -> (e,t)) (Map.assocs (edgesLeaving lg ! u))

empty :: (Ord n, Ord e) => LabelledGraph n e
empty = LabelledGraph { sourceTarget = Map.empty
                      , edgesLeaving = Map.empty
                      }


addNode :: Ord n => n -> LabelledGraph n e -> LabelledGraph n e
addNode n topology@(LabelledGraph { edgesLeaving = edgesLeaving' }) 
  = topology { edgesLeaving = Map.insert n Map.empty edgesLeaving' 
             }


addEdge :: (Ord n, Ord e) => e -> (n,n) -> Weight -> LabelledGraph n e -> LabelledGraph n e    
addEdge e st weight topology@(LabelledGraph { sourceTarget = sourceTarget', edgesLeaving = edgesLeaving' })
  = let el = Map.unionWith Map.union edgesLeaving' (Map.fromList [(fst st, Map.singleton e (snd st, weight)), (snd st, Map.empty)])
    in topology { sourceTarget = Map.insert e (st, weight) sourceTarget' 
                , edgesLeaving = el
                }

addEdges :: (Ord n, Ord e) => [(e,((n,n),Weight))] -> LabelledGraph n e -> LabelledGraph n e    
addEdges edges topology@(LabelledGraph { sourceTarget = sourceTarget', edgesLeaving = edgesLeaving' })
  = let el = Map.unionWith Map.union edgesLeaving' 
             (Map.fromListWith Map.union $ concat [[(fst st, Map.singleton e (snd st, weight)), (snd st, Map.empty)] | (e, (st,weight)) <- edges])
    in topology { sourceTarget = Map.union sourceTarget' (Map.fromList edges)
                , edgesLeaving = el
                }


adjustEdgeWeight :: (Ord n, Ord e) => e -> (Weight -> Weight) -> LabelledGraph n e -> LabelledGraph n e
adjustEdgeWeight e f graph 
  = let el = Map.adjust (Map.adjust (\(st,weight) -> (st, f weight)) e) (source graph e) (edgesLeaving graph)
    in graph { sourceTarget = Map.adjust (\(st,weight) -> (st, f weight)) e (sourceTarget graph) 
             , edgesLeaving = el
             }


deleteNode :: (Ord e, Ord n) => n -> LabelledGraph n e -> LabelledGraph n e
deleteNode n topo@(LabelledGraph { sourceTarget = sourceTarget', edgesLeaving = edgesLeaving' }) 
  = LabelledGraph { sourceTarget = Map.filter p sourceTarget'
                  , edgesLeaving = Map.delete n edgesLeaving'
                  }
  where p ((s,t),_) = s /= n && t /= n
                                         

deleteEdge :: (Ord n, Ord e) => e -> LabelledGraph n e -> LabelledGraph n e                  
deleteEdge e topology@(LabelledGraph { sourceTarget = sourceTarget', edgesLeaving = edgesLeaving' }) 
  = let el = Map.adjust (Map.delete e) (source topology e) edgesLeaving'
    in topology { edgesLeaving = el } 
    
    
data LTree a b = LNode a [(b, LTree a b)]
               deriving (Show, Eq)

mapLTree :: (a -> c) -> (b -> d) -> LTree a b -> LTree c d
mapLTree f g (LNode a bts) = LNode (f a) [ (g b, mapLTree f g t) | (b, t) <- bts ]

-- | Computes the path tree from one node to another node of the graph. 
-- Each node of the tree is a path in the graph from the source to some node in the graph. 
-- The parent of a node is the node representing the path with one less edge than the node.
pathTree :: (Ord n, Ord e) => LabelledGraph n e -> n -> n -> Maybe (LTree n (e, Weight))
pathTree g s d 
  = search g s []
  where 
    search g u visited 
      | u == d = Just (LNode u [])
      | u /= d = let ets = [ ((e,weightOf e g),t) 
                           | (e,tgt) <- edgesOutOf u g
                           , not (tgt `elem` visited)
                           , Just t <- [search (deleteNode u g) tgt (u:visited)] 
                           ]
                 in if null ets
                    then Nothing
                    else Just (LNode u ets)

-- | Neat 2-dimensional drawing of a tree. Mostly borrowed from code in @Data.Tree@ module. 
drawTree :: LTree String String -> String
drawTree  = unlines . draw

draw :: LTree String String -> [String]
draw (LNode x ts0) = x : drawSubTrees ts0
  where
    drawSubTrees [] = []
    drawSubTrees [(l,t)] =
        "|" : shift ("`" ++ l ++ "- ") "   " (draw t)
    drawSubTrees ((l,t):ts) =
        "|" : shift ("+" ++ l ++ "- ") "|  " (draw t) ++ drawSubTrees ts

    shift first other = zipWith (++) (first : repeat other)
