{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE MultiParamTypeClasses #-} 
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE BangPatterns #-}

-- | This module provides data structures for Ethernet frames
-- as well as parsers and unparsers for Ethernet frames. 
module Network.Data.Ethernet.EthernetFrame ( 
  
  -- * Data types
  EthernetFrame
  , EthernetHeader(..)  
  , EthernetBody(..)
  , EthernetTypeCode
  , UnknownFrame(..)
  , MagellanP4Packet(..)

  , lldpFrame
  , typeCode
  , ethTypeVLAN
  , ethTypeIP
  , ethTypeIPv6
  , ethType8021X    
  , ethTypeARP
  , ethTypeLLDP
  , ethTypeMagellanP4
  , typeEth2Cutoff
  , VLANPriority
  , VLANID

    -- * Parsers and unparsers 
  , getEthernetFrame
  , getEthHeader
  , putEthHeader
  , putEthFrame
    
    -- * ARP frames    
  , arpQuery
  , arpReply
    
  ) where

import Data.Binary.Get (Get, getWord8, getWord16be)
import Data.Binary.Put (Put, putWord8, putWord16be, putByteString)
import Data.Bits (shiftL, shiftR, testBit, setBit, (.&.))
import qualified Data.ByteString as S
import Data.Word (Word8, Word16)
import Network.Data.Ethernet.AddressResolutionProtocol
import Network.Data.Ethernet.EthernetAddress (EthernetAddress, getEthernetAddress, putEthernetAddress, broadcastAddress, ethernetAddress64)
import Network.Data.Ethernet.LLDP
import Network.Data.IPv4.IPAddress
import Network.Data.IPv4.IPPacket
import Text.Printf (printf)

-- | An Ethernet frame is either an IP packet, an ARP packet, or an uninterpreted @ByteString@.
-- Based on http://en.wikipedia.org/wiki/File:Ethernet_Type_II_Frame_format.svg
type EthernetFrame = (EthernetHeader, EthernetBody)

data EthernetHeader   = EthernetHeader { etherDst :: !EthernetAddress, 
                                         etherSrc :: !EthernetAddress }
                      | Ethernet8021Q {  etherDst                 :: !EthernetAddress, 
                                         etherSrc                 :: !EthernetAddress, 
                                         priorityCodePoint        :: !VLANPriority, 
                                         canonicalFormatIndicator :: !Bool, 
                                         vlanId                   :: !VLANID }
                        deriving (Read,Show,Eq)

-- | Ethernet type code, determines the type of payload carried by an Ethernet frame.
type EthernetTypeCode = Word16

type VLANID           = Word16
type VLANPriority     = Word8

data EthernetBody   = IPInEthernet !IPPacket
                    | ARPInEthernet !ARPPacket
                    | LLDPInEthernet !LLDPDU
                    | MagellanP4Packet MagellanP4Packet
                    | OtherEthernetBody UnknownFrame
                   deriving (Show,Eq)

class IsEthernetBody a where
  etherTypeCode :: a -> EthernetTypeCode
  putEtherBody  :: a -> Put

data UnknownFrame = UnknownFrame !EthernetTypeCode !S.ByteString
                  deriving (Show,Read,Eq)

data MagellanP4Packet = MagellanP4PacketIn Word8 EthernetFrame
                      | MagellanP4PacketOut (Either Word8 Word16) EthernetFrame
                      deriving (Show,Eq)

instance IsEthernetBody UnknownFrame where
  etherTypeCode (UnknownFrame c _) = c
  putEtherBody (UnknownFrame _ body) = putByteString body

instance IsEthernetBody MagellanP4Packet where
  etherTypeCode _ = ethTypeMagellanP4
  putEtherBody (MagellanP4PacketIn ingress frame) = do
    putWord8 1
    putWord8 ingress
    putWord8 0
    putWord16be 0
    putEthFrame frame
  putEtherBody (MagellanP4PacketOut out frame) = do
    putWord8 2
    putWord8 0
    case out of
      Left egress -> putWord8 egress >> putWord16be 0
      Right mcgroup -> putWord8 0 >> putWord16be mcgroup
    putEthFrame frame

getMagellanP4Packet :: Get MagellanP4Packet
getMagellanP4Packet = do
  typ <- getWord8
  ingress <- getWord8  -- ingress
  egr <- getWord8  -- egress
  mc <- getWord16be -- mcgroup
  frame <- getEthernetFrame
  if typ == 1
    then return $ MagellanP4PacketIn ingress frame
    else if typ == 2
         then let out = if mc == 0
                        then Left egr
                        else Right mc
              in return $ MagellanP4PacketOut out frame
         else error $ "unexpected MagellanP4 packet type: " ++ show typ

unknownFrameParser :: EthernetHeader -> EthernetTypeCode -> Get UnknownFrame
unknownFrameParser _ tcode = return (UnknownFrame tcode S.empty)
{-# INLINE unknownFrameParser #-}

-- Internal
ethernetFrame :: EthernetHeader -> EthernetBody -> EthernetFrame
ethernetFrame hdr body = (hdr, body)

-- | Make an LLDP frame
lldpFrame :: EthernetAddress -> LLDPDU -> EthernetFrame
lldpFrame src lldp = ethernetFrame hdr (LLDPInEthernet lldp)
  where
    multicastAddr = ethernetAddress64 0x0180c2000000
    hdr = EthernetHeader { etherDst = multicastAddr, etherSrc = src }

arpQuery :: EthernetAddress   -- ^ source hardware address
            -> IPAddress      -- ^ source IP address
            -> IPAddress      -- ^ target IP address
            -> EthernetFrame
arpQuery sha spa tpa = (hdr, ARPInEthernet body)
  where hdr = EthernetHeader { etherDst  = broadcastAddress, etherSrc  = sha }
        body = ARPQuery $ ARPQueryPacket { querySenderEthernetAddress = sha
                                         , querySenderIPAddress       = spa
                                         , queryTargetIPAddress       = tpa
                                         }

arpReply :: EthernetAddress     -- ^ source hardware address
            -> IPAddress        -- ^ source IP address
            -> EthernetAddress  -- ^ target hardware address
            -> IPAddress        -- ^ target IP address
            -> EthernetFrame
arpReply sha spa tha tpa = (hdr, ARPInEthernet body)
  where hdr = EthernetHeader { etherDst  = tha, etherSrc  = sha }
        body = ARPReply $ ARPReplyPacket { replySenderEthernetAddress = sha
                                         , replySenderIPAddress       = spa
                                         , replyTargetEthernetAddress = tha
                                         , replyTargetIPAddress       = tpa
                                         } 

-- | Parser for Ethernet frames.
getEthernetFrame :: Get EthernetFrame
getEthernetFrame = do
  let getOther = unknownFrameParser
  (hdr, tc) <- getEthHeader
  case tc of
    _ | tc == ethTypeIP  -> do ipPacket <- getIPPacket
                               return (hdr, IPInEthernet ipPacket)
      | tc == ethTypeARP -> do mArpPacket <- getARPPacket
                               case mArpPacket of
                                 Just arpPacket -> return (hdr, ARPInEthernet arpPacket)
                                 Nothing        -> error "failed parsing ARP packet"
      | tc == ethTypeLLDP -> do lldp <- getLLDPDU
                                return (hdr, LLDPInEthernet lldp)
      | tc == ethTypeMagellanP4 -> do p <- getMagellanP4Packet
                                      return (hdr, MagellanP4Packet p)
      | otherwise -> do a <- getOther hdr tc
                        return (hdr, OtherEthernetBody a)
{-# INLINE getEthernetFrame #-}

getEthHeader :: Get (EthernetHeader, EthernetTypeCode)
getEthHeader = do 
  !dstAddr <- getEthernetAddress
  !srcAddr <- getEthernetAddress
  !tcode   <- getWord16be
  continue dstAddr srcAddr tcode
  where
    continue :: EthernetAddress -> EthernetAddress -> EthernetTypeCode -> Get (EthernetHeader, EthernetTypeCode)
    continue dstAddr srcAddr tcode
      | tcode < typeEth2Cutoff = fail (printf "unrecognized eth header %s %s %d" (show dstAddr) (show srcAddr) tcode)
      | tcode == ethTypeVLAN   = do x <- getWord16be
                                    etherType <- getWord16be
                                    let pcp = fromIntegral (shiftR x 13)
                                    let cfi = testBit x 12
                                    let vid = x .&. 0x0fff
                                    return (Ethernet8021Q dstAddr srcAddr pcp cfi vid, etherType)
      | otherwise = return (EthernetHeader dstAddr srcAddr, tcode)
{-# INLINE getEthHeader #-}


-- | Unparser for Ethernet headers.
putEthHeader :: EthernetHeader -> EthernetTypeCode -> Put 
putEthHeader (EthernetHeader dstAddr srcAddr) tcode =  
  putEthernetAddress dstAddr >>
  putEthernetAddress srcAddr >>
  putWord16be tcode
putEthHeader (Ethernet8021Q dstAddr srcAddr pcp cfi vid) tcode = 
  putEthernetAddress dstAddr >>
  putEthernetAddress srcAddr >>
  putWord16be ethTypeVLAN >>
  putWord16be x >>
  putWord16be tcode
    where x = let y = shiftL (fromIntegral pcp :: Word16) 13
                  y' = if cfi then setBit y 12 else y
              in y' + fromIntegral vid
 
putEthFrame :: EthernetFrame -> Put
putEthFrame (hdr, body) = case body of
  IPInEthernet ip      -> putEthHeader hdr ethTypeIP >> putIP ip
  ARPInEthernet arpPacket -> putEthHeader hdr ethTypeARP >> putARPPacket arpPacket
  LLDPInEthernet lldp -> putEthHeader hdr ethTypeLLDP >> putLLDPDU lldp
  MagellanP4Packet a -> putEthHeader hdr (etherTypeCode a) >> putEtherBody a  
  OtherEthernetBody a -> putEthHeader hdr (etherTypeCode a) >> putEtherBody a

ethTypeIP, ethTypeIPv6, ethType8021X, ethTypeARP, ethTypeLLDP, ethTypeVLAN, typeEth2Cutoff, ethTypeMagellanP4 :: EthernetTypeCode
ethTypeIP      = 0x0800
ethTypeIPv6    = 0x86DD
ethType8021X   = 0x888E
ethTypeARP     = 0x0806
ethTypeLLDP    = 0x88CC
ethTypeVLAN    = 0x8100
typeEth2Cutoff = 0x0600
ethTypeMagellanP4 = 0x9999


typeCode :: EthernetBody -> EthernetTypeCode
typeCode (IPInEthernet _)      = ethTypeIP
typeCode (ARPInEthernet _)     = ethTypeARP
typeCode (LLDPInEthernet _)    = ethTypeLLDP
typeCode (MagellanP4Packet _ ) = ethTypeMagellanP4
typeCode (OtherEthernetBody a) = etherTypeCode a
