{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE DeriveGeneric #-}

module Network.Data.Ethernet.EthernetAddress ( 
  -- * Ethernet address
  EthernetAddress
  , ethernetAddress
  , ethernetAddress64
  , unpack
  , unpack64
  , toList
  , pack_32_16
  , isReserved
  , broadcastAddress
  , prettyPrintEthernetAddress
    
    -- * Parsers and unparsers
  , getEthernetAddress
  , putEthernetAddress
  ) where

import Data.Aeson
import Data.Word
import Data.Bits
import qualified Data.Binary.Get as Strict
import qualified Data.Binary.Put as Strict
import Numeric (showHex, readHex)
import Network.Data.Util
import GHC.Generics (Generic)
import Data.Hashable
import Data.Typeable
import Control.DeepSeq
import Control.DeepSeq.Generics

-- | An Ethernet address consists of 6 bytes. It is stored in a single 64-bit value.
newtype EthernetAddress = EthernetAddress Word64 
                        deriving ( Eq
                                 , Ord
                                 , Generic
                                 , Typeable
                                 , Bits
                                 , Integral
                                 , Real
                                 , Enum
                                 , Num
                                 )

instance Hashable EthernetAddress
instance ToJSON EthernetAddress                                 
instance FromJSON EthernetAddress
instance NFData EthernetAddress where rnf = genericRnf

{-
prettyPrintEthernetAddress :: EthernetAddress -> String
prettyPrintEthernetAddress eth
  = concat $ intersperse ":" (map (\n -> showHex n "") 
                              [w0,w1,w2,w3,w4,w5])
  where (w0,w1,w2,w3,w4,w5) = unpack eth
-}
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
  let !a1 = fromIntegral (shiftR w64 40)
      !a2 = fromIntegral (shiftR w64 32 `mod` 0x0100)
      !a3 = fromIntegral (shiftR w64 24 `mod` 0x0100)
      !a4 = fromIntegral (shiftR w64 16 `mod` 0x0100)
      !a5 = fromIntegral (shiftR w64 8 `mod` 0x0100)
      !a6 = fromIntegral (w64 `mod` 0x0100)
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

-- | Unparse an Ethernet address to a ByteString     
putEthernetAddress :: EthernetAddress -> Strict.Put     
putEthernetAddress (EthernetAddress w64) 
  = do Strict.putWord32be (fromIntegral (shiftR w64 16))
       Strict.putWord16be (fromIntegral (w64 `mod` 0x010000))
{-# INLINE putEthernetAddress #-}    

isReserved :: EthernetAddress -> Bool
isReserved e = 
  let (a1, a2, a3, a4, a5, _) = unpack e
  in 
    a1 == 0x01 && 
    a2 == 0x80 && 
    a3 == 0xc2 && 
    a4 == 0 && 
    ((a5 .&. 0xf0) == 0)

broadcastAddress :: EthernetAddress
broadcastAddress = EthernetAddress 0xffffffffffff


-- Show & Read instances
--
-- Specifications: 
-- (A) unConcatIntersperse c . concatIntersperse [c] == id
-- (B) parseHex1 . unparseHex1 == id
-- (C) fromList . toList == id
--
-- Then, we reason: 
--
--   hexParseEthernetAddress . prettyPrintEthernetAddress
--
--    { expanding definitions }
--
-- == fromList . map parseHex1
--    . unConcatIntersperse ':' . concatIntersperse ":"
--    . map (\n -> showHex n "") . toList
--
--    { By prop (A) }
--
-- == fromList . map parseHex1 . map unparseHex1 . toList
--
--    { map-map fusion }
--
-- == fromList . map (parseHex1 . unparseHex1) . toList
--
--    { By prop (B) }
--
-- == fromList . map id . toList
--
--    { map functor law }
--
-- == fromList . toList
--
--    { By prop (C) }
--
-- == id

prettyPrintEthernetAddress :: EthernetAddress -> String
prettyPrintEthernetAddress =
  concatIntersperse ":" . map unparseHex1 . toList

hexParseEthernetAddress :: String -> EthernetAddress
hexParseEthernetAddress = fromList . hexParseWords 

hexParseWords :: String -> [Word8]
hexParseWords = map parseHex1 . unConcatIntersperse ':' 

parseHex1 :: String -> Word8
parseHex1 = fst . head . readHex

unparseHex1 :: Word8 -> String
unparseHex1 n
  | n < 16    = '0' : showHex n ""
  | otherwise = showHex n ""             

toList :: EthernetAddress -> [Word8]
toList eth = [w0,w1,w2,w3,w4,w5]
  where (w0,w1,w2,w3,w4,w5) = unpack eth

fromList :: [Word8] -> EthernetAddress
fromList [w0,w1,w2,w3,w4,w5] = ethernetAddress w0 w1 w2 w3 w4 w5
fromList _ = error "Incorrect number of bytes to construct EthernetAddress."

instance Show EthernetAddress where
  show = prettyPrintEthernetAddress

instance Read EthernetAddress where
  readsPrec _ s = [(hexParseEthernetAddress s,"")]

