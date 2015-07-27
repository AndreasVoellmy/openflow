module Network.Data.IPv4.UDP
       (
         UDPHeader
       , UDPPortNumber
       , getUDPHeader
       ) where

import Data.Binary.Get
import Data.Word

type UDPHeader     = (UDPPortNumber, UDPPortNumber)
type UDPPortNumber = Word16

getUDPHeader :: Get UDPHeader
getUDPHeader = do 
  srcp <- getWord16be
  dstp <- getWord16be
  return (srcp,dstp)
{-# INLINE getUDPHeader #-}  


