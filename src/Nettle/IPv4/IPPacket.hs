{-# LANGUAGE TypeSynonymInstances, TypeOperators, MultiParamTypeClasses, FunctionalDependencies, RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

{-|

This module provides @Get@ values for parsing various 
IP packets and headers from ByteStrings into a byte-sequence-independent 
representation as Haskell datatypes. 

Warning: 

These are incomplete. The headers may not contain all the information
that the protocols specify. For example, the Haskell representation of an IP Header
only includes source and destination addresses and IP protocol number, even though
an IP packet has many more header fields. More seriously, an IP header may have an optional 
extra headers section after the destination address. We assume this is not present. If it is present, 
then the transport protocol header will not be directly after the destination address, but will be after 
these options. Therefore functions that assume this, such as the getExactMatch function below, will give 
incorrect results when applied to such IP packets. 

The Haskell representations of the headers for the transport protocols are similarly incomplete. 
Again, the Get instances for the transport protocols may not parse through the end of the 
transport protocol header. 

-}
module Nettle.IPv4.IPPacket ( 
  -- * IP Packet 
  IPPacket(..)
  , IPHeader(..)
  , DifferentiatedServicesCodePoint
  , FragOffset
  , IPProtocol
  , IPTypeOfService
  , TransportPort
  , ipTypeTcp 
  , ipTypeUdp 
  , ipTypeIcmp
  , IPBody(..)
  , fromTCPPacket
  , fromUDPPacket
  , withIPPacket
  , foldIPPacket
  , foldIPBody
    
    -- * Parsers
  , getIPPacket
  , getIPPacket2
  , getIPHeader
  , ICMPHeader
  , ICMPType
  , ICMPCode
  , getICMPHeader
  , TCPHeader
  , TCPPortNumber
  , getTCPHeader
  , UDPHeader
  , UDPPortNumber
  , getUDPHeader
  ) where

import Nettle.IPv4.IPAddress
import Data.Bits
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.HList
import Nettle.OpenFlow.Get
import Data.ByteString as S
import qualified Data.Binary.Get as Binary

-- | An IP packet consists of a header and a body.
type IPPacket = IPHeader :*: IPBody :*: HNil


-- | An IP Header includes various information about the packet, including the type of payload it contains. 
-- Warning: this definition does not include every header field included in an IP packet. 
data IPHeader = IPHeader { ipSrcAddress  :: !IPAddress
                         , ipDstAddress  :: !IPAddress
                         , ipProtocol    :: !IPProtocol  
                         , headerLength  :: !Int
                         , totalLength   :: !Int
                         , dscp          :: !DifferentiatedServicesCodePoint -- ^ differentiated services code point - 6 bit number
                         }
                deriving (Read,Show,Eq)

type DifferentiatedServicesCodePoint = Word8
type FragOffset      = Word16
type IPProtocol      = Word8
type IPTypeOfService = Word8
type TransportPort   = Word16

ipTypeTcp, ipTypeUdp, ipTypeIcmp :: IPProtocol

ipTypeTcp  = 6
ipTypeUdp  = 17
ipTypeIcmp = 1

-- | The body of an IP packet can be either a TCP, UDP, ICMP or other packet. 
-- Packets other than TCP, UDP, ICMP are represented as unparsed @ByteString@ values.
data IPBody   = TCPInIP !TCPHeader
              | UDPInIP !UDPHeader 
              | ICMPInIP !ICMPHeader
              | UninterpretedIPBody
              deriving (Show,Eq)


foldIPPacket :: (IPHeader -> IPBody -> a) -> IPPacket -> a
foldIPPacket f (HCons h (HCons b HNil)) = f h b

foldIPBody :: (TCPHeader -> a) -> (UDPHeader -> a) -> (ICMPHeader -> a) -> a -> IPBody -> a
foldIPBody f g h k (TCPInIP x) = f x
foldIPBody f g h k (UDPInIP x) = g x
foldIPBody f g h k (ICMPInIP x) = h x
foldIPBody f g h k UninterpretedIPBody = k 


fromTCPPacket :: IPBody -> Maybe (TCPHeader :*: HNil)
fromTCPPacket (TCPInIP body) = Just (hCons body hNil)
fromTCPPacket _ = Nothing


fromUDPPacket :: IPBody -> Maybe (UDPHeader :*: HNil)
fromUDPPacket (UDPInIP hdr) = Just (hCons hdr hNil)
fromUDPPacket _ = Nothing


withIPPacket :: HList l => (IPBody -> Maybe l) -> IPPacket -> Maybe (IPHeader :*: l)
withIPPacket f pkt = fmap (hCons (hOccurs pkt)) (f (hOccurs pkt))

getIPHeader :: Get IPHeader
getIPHeader = do 
  b1                 <- getWord8
  diffServ           <- getWord8
  totalLen           <- getWord16be
  ident              <- getWord16be
  flagsAndFragOffset <- getWord16be
  ttl                <- getWord8
  nwproto            <- getIPProtocol
  hdrChecksum        <- getWord16be
  nwsrc              <- getIPAddress
  nwdst              <- getIPAddress
  let hdrLen = fromIntegral (b1 .&. 0x0f)
  when (hdrLen > 5) (skip (hdrLen - 5))
  return (IPHeader { ipSrcAddress = nwsrc 
                   , ipDstAddress = nwdst 
                   , ipProtocol   = nwproto
                   , headerLength = hdrLen
                   , totalLength  = fromIntegral totalLen
                   , dscp         = shiftR diffServ 2
                   } 
         )
{-# INLINE getIPHeader #-}

getIPHeader2 :: Binary.Get IPHeader
getIPHeader2 = do 
  b1                 <- Binary.getWord8
  diffServ           <- Binary.getWord8
  totalLen           <- Binary.getWord16be
  ident              <- Binary.getWord16be
  flagsAndFragOffset <- Binary.getWord16be
  ttl                <- Binary.getWord8
  nwproto            <- getIPProtocol2
  hdrChecksum        <- Binary.getWord16be
  nwsrc              <- getIPAddress2
  nwdst              <- getIPAddress2
  return (IPHeader { ipSrcAddress = nwsrc 
                   , ipDstAddress = nwdst 
                   , ipProtocol = nwproto
                   , headerLength = fromIntegral (b1 .&. 0x0f)
                   , totalLength  = fromIntegral totalLen
                   , dscp = shiftR diffServ 2
                   } )


getIPProtocol :: Get IPProtocol 
getIPProtocol = getWord8
{-# INLINE getIPProtocol #-}

getIPProtocol2 :: Binary.Get IPProtocol 
getIPProtocol2 = Binary.getWord8


getIPPacket :: Get IPPacket 
getIPPacket = do 
  hdr  <- getIPHeader
  body <- getIPBody hdr
  return body
    where getIPBody hdr@(IPHeader {..}) 
              | ipProtocol == ipTypeTcp  = do tcpHdr <- getTCPHeader
                                              return (hCons hdr (hCons (TCPInIP tcpHdr) hNil))
              | ipProtocol == ipTypeUdp  = do udpHdr <- getUDPHeader  
                                              -- body <- getByteString (fromIntegral (totalLength - (4 * headerLength)) - 4)
                                              return (hCons hdr (hCons (UDPInIP udpHdr) hNil))
              | ipProtocol == ipTypeIcmp = do icmpHdr <- getICMPHeader 
                                              return (hCons hdr (hCons (ICMPInIP icmpHdr) hNil))
              | otherwise                = do bs <- return S.empty {- getByteString (fromIntegral (totalLength - (4 * headerLength))) -} 
                                              return (hCons hdr (hCons UninterpretedIPBody hNil))
{-# INLINE getIPPacket #-}
          
getIPPacket2 :: Binary.Get IPPacket 
getIPPacket2 = do 
  hdr  <- getIPHeader2
  body <- getIPBody hdr
  return body
    where getIPBody hdr@(IPHeader {..}) 
              | ipProtocol == ipTypeTcp  = getTCPHeader2  >>= return . (\tcpHdr -> hCons hdr (hCons (TCPInIP tcpHdr) hNil))
              | ipProtocol == ipTypeUdp  = do udpHdr <- getUDPHeader2  
                                              body <- Binary.getByteString (fromIntegral (totalLength - (4 * headerLength)))
                                              return (hCons hdr (hCons (UDPInIP udpHdr) hNil))
              | ipProtocol == ipTypeIcmp = getICMPHeader2 >>= return . (\icmpHdr -> hCons hdr (hCons (ICMPInIP icmpHdr) hNil))
              | otherwise                = Binary.getByteString (fromIntegral (totalLength - (4 * headerLength))) >>= 
                                           return . (\bs -> hCons hdr (hCons UninterpretedIPBody hNil))

-- Transport Header

type ICMPHeader = (ICMPType, ICMPCode)
type ICMPType = Word8
type ICMPCode = Word8

getICMPHeader :: Get ICMPHeader
getICMPHeader = do 
  icmp_type <- getWord8
  icmp_code <- getWord8
  skip 6
  return (icmp_type, icmp_code)
{-# INLINE getICMPHeader #-}  

getICMPHeader2 :: Binary.Get ICMPHeader
getICMPHeader2 = do 
  icmp_type <- Binary.getWord8
  icmp_code <- Binary.getWord8
  Binary.skip 6
  return (icmp_type, icmp_code)

type TCPHeader  = (TCPPortNumber, TCPPortNumber)
type TCPPortNumber = Word16

getTCPHeader :: Get TCPHeader
getTCPHeader = do 
  srcp <- getWord16be
  dstp <- getWord16be
  return (srcp,dstp)
{-# INLINE getTCPHeader #-}  

getTCPHeader2 :: Binary.Get TCPHeader
getTCPHeader2 = do 
  srcp <- Binary.getWord16be
  dstp <- Binary.getWord16be
  return (srcp,dstp)

type UDPHeader     = (UDPPortNumber, UDPPortNumber)
type UDPPortNumber = Word16

getUDPHeader :: Get UDPHeader
getUDPHeader = do 
  srcp <- getWord16be
  dstp <- getWord16be
  return (srcp,dstp)
{-# INLINE getUDPHeader #-}  

getUDPHeader2 :: Binary.Get UDPHeader
getUDPHeader2 = do 
  srcp <- Binary.getWord16be
  dstp <- Binary.getWord16be
  return (srcp,dstp)

