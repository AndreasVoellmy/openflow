{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TemplateHaskell #-}
module Network.Data.IPv4.IPAddress
       (
         IPAddress(..)
       , IPAddressPrefix
       , PrefixLength
       , showOctets
       , addressToOctets
       , ipAddressToWord32
       , ipAddress
       , getIPAddress
       , putIPAddress
       , exactPrefix
       , (//)
       , addressPart
       , prefixLength
       , prefixToMask
       , prefixLengthToMask
       , maskToPrefixLength
       , prefixIsExact
       , defaultIPPrefix
       , showPrefix
       , prefixPlus         
       , prefixOverlaps
       , elemOfPrefix
       , intersect
       , intersects
       , disjoint
       , disjoints
       , isSubset
       ) where

import Data.Word
import Data.Bits 
import Data.Maybe
import Data.Binary.Get 
import qualified Data.Binary.Put as Strict
import Network.Data.Util
import GHC.Generics (Generic)
import Data.Hashable
import Control.DeepSeq
import Control.DeepSeq.Generics

import Data.Aeson.TH

newtype IPAddress = IPAddress Word32
                  deriving ( Eq
                           , Ord
                           , Generic
                           , Bits
                           , Integral
                           , Real
                           , Enum
                           , Num
                           )

instance Hashable IPAddress
instance NFData IPAddress where rnf = genericRnf

$(deriveJSON defaultOptions ''IPAddress)

instance Show IPAddress where
  show = concatIntersperse "." . map show . addressToList 

instance Read IPAddress where
  readsPrec _ s = [(readOctets s,"")]

readOctets :: String -> IPAddress
readOctets = listToAddress . map read . unConcatIntersperse '.'

showOctets :: IPAddress -> String
showOctets = show

type IPAddressPrefix = (IPAddress, PrefixLength)
type PrefixLength    = Word8

ipAddressToWord32 :: IPAddress -> Word32
ipAddressToWord32 (IPAddress a) = a
{-# INLINE ipAddressToWord32 #-}

ipAddress :: Word8 -> Word8 -> Word8 -> Word8 -> IPAddress
ipAddress b1 b2 b3 b4 = 
    IPAddress $
        foldl (\a b -> shift a 8 + fromIntegral b) (0 :: Word32) [b1,b2,b3,b4]

getIPAddress :: Get IPAddress
getIPAddress = getWord32be >>= return . IPAddress
{-# INLINE getIPAddress #-}

putIPAddress :: IPAddress -> Strict.Put
putIPAddress (IPAddress a) = Strict.putWord32be a

exactPrefix :: IPAddress -> IPAddressPrefix
exactPrefix !a = (a, 32)
{-# INLINE exactPrefix #-}

(//) :: IPAddress -> PrefixLength -> IPAddressPrefix
(IPAddress a) // len 
  = let !a'   = a .&. mask
        !mask = complement (2^((32::Int) - fromIntegral len) - 1)                    
    in (IPAddress a', len)

addressPart :: IPAddressPrefix -> IPAddress
addressPart (a,_) = a
{-# INLINE addressPart #-}
          
prefixLength :: IPAddressPrefix -> PrefixLength
prefixLength (_,l) = l
{-# INLINE prefixLength #-}

prefixLengthToMask :: Int -> IPAddress
prefixLengthToMask l = IPAddress $ foldr (flip setBit) 0 [31,30..(32 - l)]

prefixToMask :: IPAddressPrefix -> IPAddress
prefixToMask (_ , l) = prefixLengthToMask $ fromIntegral l

maskToPrefixLength :: IPAddress -> Word8
maskToPrefixLength (IPAddress w) = fromIntegral $ popCount w

maxPrefixLen :: Word8
maxPrefixLen = 32

prefixIsExact :: IPAddressPrefix -> Bool
prefixIsExact (_,l) = l==maxPrefixLen

defaultIPPrefix :: IPAddressPrefix
defaultIPPrefix = (IPAddress 0, 0)

addressToOctets :: IPAddress -> (Word8, Word8, Word8, Word8)
addressToOctets (IPAddress addr) = (b1,b2,b3,b4)
    where b4 = fromIntegral $ addr .&. (2 ^ (8::Int) - 1)
          b3 = fromIntegral $ shiftR (addr .&. (2 ^ (16::Int) - 1)) 8
          b2 = fromIntegral $ shiftR (addr .&. (2 ^ (24::Int) - 1)) 16
          b1 = fromIntegral $ shiftR (addr .&. (2 ^ (32::Int) - 1)) 24

addressToList :: IPAddress -> [Word8]
addressToList addr =
  let (b1,b2,b3,b4) = addressToOctets addr
  in [b1,b2,b3,b4]

listToAddress ::  [Word8] -> IPAddress
listToAddress [b1,b2,b3,b4] = ipAddress b1 b2 b3 b4
listToAddress _ = error "incorrect number of bytes provided; expecting 4."

showPrefix :: IPAddressPrefix -> String
showPrefix (addr, len) = show addr ++ "/" ++ show len

prefixPlus :: IPAddressPrefix -> Word32 -> IPAddress
prefixPlus (IPAddress addr,_) x = IPAddress (addr + x)

prefixOverlaps :: IPAddressPrefix -> IPAddressPrefix -> Bool
prefixOverlaps (IPAddress addr, len) (IPAddress addr', len') 
    | addr .&. mask == addr' .&. mask = True
    | otherwise                       = False
    where len'' = min len len'
          -- mask  = foldl setBit (0 :: Word32) [(32 - fromIntegral len'')..31]
          -- !mask = complement (2^(32 - fromIntegral len'') - 1)
          !mask = complement (2^(32 - len'') - 1)
          
elemOfPrefix :: IPAddress -> IPAddressPrefix -> Bool
elemOfPrefix addr prefix  = (addr // 32) `prefixOverlaps` prefix

intersect :: IPAddressPrefix -> IPAddressPrefix -> Maybe IPAddressPrefix
intersect p1@(_, len1) p2@(_, len2) 
    | p1 `prefixOverlaps` p2 = Just longerPrefix
    | otherwise              = Nothing
    where longerPrefix = if len1 < len2 then p2 else p1

intersects :: [IPAddressPrefix] -> Maybe IPAddressPrefix
intersects = foldl f (Just defaultIPPrefix)
    where f mpref pref = maybe Nothing (intersect pref) mpref

disjoint :: IPAddressPrefix -> IPAddressPrefix -> Bool
disjoint p1 p2 = not (p1 `prefixOverlaps` p2)

disjoints :: [IPAddressPrefix] -> Bool
disjoints = isNothing . intersects

-- isSubset p1 p2 is True iff p2 is a subset of p1.
-- The order of the arguments seems unintuitive.
isSubset :: IPAddressPrefix -> IPAddressPrefix -> Bool
isSubset p1@(_,l) p2@(_,l') = l <= l' && (p1 `prefixOverlaps` p2)

