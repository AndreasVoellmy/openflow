{-# LANGUAGE BangPatterns #-}

module Nettle.IPv4.IPAddress where

import Data.Word
import Data.Bits 
import Data.Binary.Put
import Text.ParserCombinators.Parsec
import Data.Maybe
import Nettle.OpenFlow.Get 
import qualified Nettle.OpenFlow.StrictPut as Strict
import qualified Data.Binary.Get as Binary


newtype IPAddress    = IPAddress Word32 deriving (Read, Eq, Show, Ord)
type IPAddressPrefix = (IPAddress, PrefixLength)
type PrefixLength    = Word8

ipAddressToWord32 :: IPAddress -> Word32
ipAddressToWord32 (IPAddress a) = a
{-# INLINE ipAddressToWord32 #-}

ipAddress :: Word8 -> Word8 -> Word8 -> Word8 -> IPAddress
ipAddress b1 b2 b3 b4 = 
    IPAddress $ foldl (\a b -> shift a 8 + fromIntegral b) (0 :: Word32) [b1,b2,b3,b4]

getIPAddress :: Get IPAddress
getIPAddress = getWord32be >>= return . IPAddress
{-# INLINE getIPAddress #-}

getIPAddress2 :: Binary.Get IPAddress
getIPAddress2 = Binary.getWord32be >>= return . IPAddress

putIPAddress :: IPAddress -> Strict.Put
putIPAddress (IPAddress a) = Strict.putWord32be a

exactPrefix :: IPAddress -> IPAddressPrefix
exactPrefix !a = (a, 32)
{-# INLINE exactPrefix #-}

(//) :: IPAddress -> PrefixLength -> IPAddressPrefix
(IPAddress a) // len 
  | len == 32 = (IPAddress a, 32)
  | len ==  0 = (IPAddress 0, 0)
  | otherwise = let !a'   = a .&. mask
                    !mask = complement (2^(32 - fromIntegral len) - 1)                    
                in (IPAddress a', len)

        

addressPart :: IPAddressPrefix -> IPAddress
addressPart (IPAddress a,l) = IPAddress a
{-# INLINE addressPart #-}
          
prefixLength :: IPAddressPrefix -> PrefixLength
prefixLength (_,l) = l
{-# INLINE prefixLength #-}

maxPrefixLen :: Word8
maxPrefixLen = 32

prefixIsExact :: IPAddressPrefix -> Bool
prefixIsExact (_,l) = l==maxPrefixLen

defaultIPPrefix = (IPAddress 0, 0)

addressToOctets :: IPAddress -> (Word8, Word8, Word8, Word8)
addressToOctets (IPAddress addr) = (b1,b2,b3,b4)
    where b4 = fromIntegral $ addr .&. (2^8 - 1)
          b3 = fromIntegral $ shiftR (addr .&. (2^16 - 1)) 8
          b2 = fromIntegral $ shiftR (addr .&. (2^24 - 1)) 16
          b1 = fromIntegral $ shiftR (addr .&. (2^32 - 1)) 24

showOctets :: IPAddress -> String
showOctets addr = show b1 ++ "." ++ show b2 ++ "." ++ show b3 ++ "." ++ show b4
    where (b1,b2,b3,b4) = addressToOctets addr

showPrefix :: IPAddressPrefix -> String
showPrefix (addr, len) = showOctets addr ++ "/" ++ show len

prefixPlus :: IPAddressPrefix -> Word32 -> IPAddress
prefixPlus (IPAddress addr,_) x = IPAddress (addr + x)

prefixOverlaps :: IPAddressPrefix -> IPAddressPrefix -> Bool
prefixOverlaps p1@(IPAddress addr, len) p2@(IPAddress addr', len') 
    | addr .&. mask == addr' .&. mask = True
    | otherwise                       = False
    where len'' = min len len'
          mask  = foldl setBit (0 :: Word32) [(32 - fromIntegral len'')..31]

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

isSubset :: IPAddressPrefix -> IPAddressPrefix -> Bool
isSubset p1@(_,l) p2@(_,l') = l <= l' && (p1 `prefixOverlaps` p2)

parseIPAddress :: String -> Maybe IPAddress
parseIPAddress s = case parse ipAddressParser "" s of 
                     Right a -> Just a
                     Left _  -> Nothing

ipAddressParser :: CharParser () IPAddress
ipAddressParser = do a <- many1 digit
                     char '.'
                     b <- many1 digit
                     char '.'
                     c <- many1 digit
                     char '.'
                     d <- many1 digit
                     return $ ipAddress (read a) (read b) (read c) (read d)
