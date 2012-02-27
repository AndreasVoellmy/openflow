module Nettle.Topology.ExtendedDouble (
  ExtendedDouble(..)
  , addExtendedDouble
  ) where

data ExtendedDouble = Finite !Double 
                    | Infinity 
                      deriving (Show,Read,Eq)
                               
addExtendedDouble :: ExtendedDouble -> ExtendedDouble -> ExtendedDouble
addExtendedDouble (Finite x) (Finite y) = Finite (x + y)
addExtendedDouble _ _                   = Infinity
{-# INLINE addExtendedDouble #-}                               

instance Ord ExtendedDouble where                               
  Finite x <= Finite y = x <= y
  Finite _ <= Infinity = True
  Infinity <= Infinity = True
  Infinity <= Finite _ = False


