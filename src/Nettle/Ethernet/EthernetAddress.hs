{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
module Nettle.Ethernet.EthernetAddress ( 
  -- * Ethernet address
  EthernetAddress
  , ethernetAddress
  , ethernetAddress64
  , unpack
  , unpack64
  , pack_32_16
  , isReserved
  , broadcastAddress
    
    -- * Parsers and unparsers
  , getEthernetAddress
  , getEthernetAddress2    
  , putEthernetAddress
  , putEthernetAddress2
  ) where

import Data.Word
import Data.Bits
import Data.Binary
import Data.Binary.Put as P
import qualified Nettle.OpenFlow.Get as Strict
import qualified Nettle.OpenFlow.StrictPut as Strict
import Data.Generics
import qualified Data.Binary.Get as Binary
import GHC.Base
import GHC.Word


-- | An Ethernet address consists of 6 bytes. It is stored in a single 64-bit value.
newtype EthernetAddress = EthernetAddress Word64 
                        deriving (Show,Read,Eq,Ord, Data, Typeable)
                                
-- | Builds an ethernet address from a Word64 value. 
-- The two most significant bytes are irrelevant; only the bottom 6 bytes are used.
ethernetAddress64 :: Word64 -> EthernetAddress
ethernetAddress64 w64 = EthernetAddress (w64 `mod` 0x01000000000000)
{-# INLINE ethernetAddress64 #-}

ethernetAddress :: Word8 -> Word8 -> Word8 -> Word8 -> Word8 -> Word8 -> EthernetAddress                                
ethernetAddress w1 w2 w3 w4 w5 w6  
  = let w64 = (shiftL (fromIntegral w1) 40) .|.
              (shiftL (fromIntegral w2) 32) .|.
              (shiftL (fromIntegral w3) 24) .|.                       
              (shiftL (fromIntegral w4) 16) .|.                                              
              (shiftL (fromIntegral w5)  8) .|.                                              
              (fromIntegral w6)
    in EthernetAddress w64
                                
pack_32_16 :: Word32 -> Word16 -> Word64
pack_32_16 w32 w16 
  = (fromIntegral w32 `shiftL` 16) .|. fromIntegral w16
{-# INLINE pack_32_16 #-}

--  (W32# w32) (W16# w16) 
--  = W64# ((w32 `uncheckedShiftL#` 16#) `or#` w16)

unpack :: EthernetAddress -> (Word8,Word8,Word8,Word8,Word8,Word8)
unpack (EthernetAddress w64) = 
  let a1 = fromIntegral (shiftR w64 40)
      a2 = fromIntegral (shiftR w64 32 `mod` 0x0100)
      a3 = fromIntegral (shiftR w64 24 `mod` 0x0100)
      a4 = fromIntegral (shiftR w64 16 `mod` 0x0100)
      a5 = fromIntegral (shiftR w64 8 `mod` 0x0100)
      a6 = fromIntegral (w64 `mod` 0x0100)
  in (a1,a2,a3,a4,a5,a6)
{-# INLINE unpack #-}

unpack64 :: EthernetAddress -> Word64
unpack64 (EthernetAddress e) = e
{-# INLINE unpack64 #-}

-- | Parse an Ethernet address from a ByteString
getEthernetAddress :: Strict.Get EthernetAddress                                
getEthernetAddress = 
  do w32 <- Strict.getWord32be  
     w16 <- Strict.getWord16be
     return (EthernetAddress (pack_32_16 w32 w16))
{-# INLINE getEthernetAddress #-}     

getEthernetAddress2 :: Binary.Get EthernetAddress                                
getEthernetAddress2 = 
  do w32 <- Binary.getWord32be  
     w16 <- Binary.getWord16be
     return (EthernetAddress (pack_32_16 w32 w16))


-- | Unparse an Ethernet address to a ByteString     
putEthernetAddress :: EthernetAddress -> Strict.Put     
putEthernetAddress (EthernetAddress w64) 
  = Strict.putWord32be (fromIntegral (shiftR w64 16)) >>
    Strict.putWord16be (fromIntegral (w64 `mod` 0x010000))
{-# INLINE putEthernetAddress #-}    


-- | Unparse an Ethernet address to a ByteString     
putEthernetAddress2 :: EthernetAddress -> P.Put     
putEthernetAddress2 (EthernetAddress w64) -- a1 a2 a3 a4 a5 a6) = 
  = P.putWord32be (fromIntegral (shiftR w64 16)) >>
    P.putWord16be (fromIntegral (w64 `mod` 0x010000))
{-# INLINE putEthernetAddress2 #-}    


isReserved :: EthernetAddress -> Bool
isReserved e = 
  let (a1, a2, a3, a4, a5, a6) = unpack e
  in 
    a1 == 0x01 && 
    a2 == 0x80 && 
    a3 == 0xc2 && 
    a4 == 0 && 
    ((a5 .&. 0xf0) == 0)

broadcastAddress :: EthernetAddress
broadcastAddress = EthernetAddress 0xffffffffffff
