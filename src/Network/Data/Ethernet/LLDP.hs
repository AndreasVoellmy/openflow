{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

-- | This module defines the data type of LLDP messages and defines LLDP parser
-- and serialization functions. This module is very, very far from complete.
-- In particular it parses only LLDP messages that contain only the three
-- mandatory time-length-value (TLV) structures, namely Chassis ID, Port ID
-- and Time-To-Live (TTL) TLVs. In addition, both the ChassisID and Port ID
-- TLVs have multiple variants, but we only support a single variant in both
-- of these TLVs.
-- 
-- This was developed according to reference IEEE Std 802.1AB-2009.
module Network.Data.Ethernet.LLDP 
       (
         LLDPDU ( .. )
         , ChassisID
         , TLVPortID
         , PortIDSubType(..)
         , TTL
         , getLLDPDU
         , putLLDPDU
       ) where

import Data.Word
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString as B
import Control.Exception (assert)
import Data.Bits (shiftR, shiftL, (.&.), (.|.))
import Text.Printf (printf)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

-- | An LLDP Data Unit (LLDP) consists of three values: chassis id, port id,
-- and time-to-live.
data LLDPDU = LLDPDU { chassisIDTLV  :: !ChassisID
                     , portIDTLV     :: !(PortIDSubType, TLVPortID)
                     , timeToLiveTLV :: !TTL
                     } deriving (Eq, Show, Generic)

instance NFData LLDPDU

type TLVType = Word8
type TLVLength = Word16

getTLVHeader :: Get (TLVType, TLVLength)
getTLVHeader =
  do !x <- getWord16be
     let !tlvType = fromIntegral (shiftR x 9) :: Word8
     let !tlvLen  = x .&. typeMask
     return (tlvType, tlvLen)

typeMask :: Word16
typeMask = 2 ^ (9 :: Int) - 1

putTLVHeader :: TLVType -> TLVLength -> Put
putTLVHeader tlvType tlvLen
  = let x = shiftL (fromIntegral tlvType) 9 :: Word16
        y = tlvLen .&. typeMask
        z = x .|. y
    in putWord16be z

type ChassisID = B.ByteString
type ChassisIDSubType = Word8

getChassisIDTLV :: Get ChassisID
getChassisIDTLV =
  do (!tlvType,!tlvLen) <- getTLVHeader
     assert (tlvType == 1) $
       do cidSubType <- getWord8
          cid <- getChassisID tlvLen cidSubType
          return cid

getChassisID :: TLVLength -> ChassisIDSubType -> Get ChassisID
getChassisID tlvLen cidSubType
  | cidSubType == 4 = do bs <- getByteString (fromIntegral tlvLen - 1)
                         return bs
  | otherwise = fail $
                printf
                  "No support for Chassis TLV with subtype %d and length %d."
                  cidSubType
                  tlvLen

putChassisIDTLV :: ChassisID -> Put
putChassisIDTLV cid =
  assert (B.length cid == 8) $ 
    putTLVHeader 1 9 >>
    putWord8 4       >>
    putByteString cid

type TLVPortID = B.ByteString
type PortIDSubTypeCode = Word8
data PortIDSubType = InterfaceAlias
                   | PortComponent
                   | MACAddress
                   | NetworkAddress
                   | InterfaceName
                   | AgentCircuitID
                   | LocallyAssigned
                   | Reserved
                   deriving (Show,Read,Eq,Ord,Enum,Generic,NFData)

portIDSubTypeCode_2_type :: PortIDSubTypeCode -> PortIDSubType
portIDSubTypeCode_2_type c
  | c == 1    = InterfaceAlias
  | c == 2    = PortComponent
  | c == 3    = MACAddress
  | c == 4    = NetworkAddress             
  | c == 5    = InterfaceName
  | c == 6    = AgentCircuitID
  | c == 7    = LocallyAssigned
  | otherwise = Reserved

portIDSubType_2_code :: PortIDSubType -> PortIDSubTypeCode
portIDSubType_2_code t = case t of
  InterfaceAlias  -> 1
  PortComponent   -> 2
  MACAddress      -> 3
  NetworkAddress  -> 4
  InterfaceName   -> 5    
  AgentCircuitID  -> 6
  LocallyAssigned -> 7 
  Reserved        -> 0

getPortIDTLV :: Get (PortIDSubType, TLVPortID)
getPortIDTLV = 
  do (!tlvType,!tlvLen) <- getTLVHeader
     assert (tlvType == 2) $
       do pidSubType <- getWord8
          getPortID tlvLen pidSubType

getPortID :: TLVLength -> PortIDSubTypeCode -> Get (PortIDSubType, TLVPortID)
getPortID tlvLen pidSubType = do
  bs <- getByteString (fromIntegral tlvLen - 1)
  return (portIDSubTypeCode_2_type pidSubType, bs)

putPortID :: (PortIDSubType, TLVPortID) -> Put
putPortID (typ,pid) =
  assert (B.length pid == 2 && typ == LocallyAssigned) $
  putTLVHeader 2 3 >>
  putWord8 (portIDSubType_2_code LocallyAssigned) >>
  putByteString pid

type TTL = Word16

getTTLTLV :: Get TTL
getTTLTLV = do
  (!tlvType,!tlvLen) <- getTLVHeader
  assert (tlvType == 3 && tlvLen == 2) getWord16be

putTTLTLV :: TTL -> Put
putTTLTLV ttl = putTLVHeader 3 2 >> putWord16be ttl

getEndTLV :: Get ()
getEndTLV = do x <- getWord16be
               assert (x == 0) $ return ()

putEndTLV :: Put
putEndTLV = putWord16be 0

-- | Parser for LLDPDU messages; i.e. this parses the body of an Ethernet frame
-- that contains an LLDP message.
getLLDPDU :: Get LLDPDU
getLLDPDU = do
  cid <- getChassisIDTLV
  pid <- getPortIDTLV
  ttl <- getTTLTLV
  getEndTLV
  return LLDPDU { chassisIDTLV  = cid
                , portIDTLV     = pid
                , timeToLiveTLV = ttl
                }

-- | Serialization method for LLDPDU messages; i.e. this serializes the body
-- of an Ethernet frame carrying an LLDP message.
putLLDPDU :: LLDPDU -> Put
putLLDPDU LLDPDU { chassisIDTLV = cid, portIDTLV = pid, timeToLiveTLV = ttl }
  = putChassisIDTLV cid >> putPortID pid >> putTTLTLV ttl >> putEndTLV  
