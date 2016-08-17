{-# LANGUAGE TypeSynonymInstances, TypeOperators, MultiParamTypeClasses, FunctionalDependencies, RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

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
module Network.Data.IPv4.IPPacket ( 
  -- * IP Packet 
  IPPacket
  , IPHeader(..)
  , DifferentiatedServicesCodePoint
  , FragOffset
  , IPProtocol
  , IPTypeOfService
  , TransportPort
  , ipProtocol
  , ipBodyLength
  , ipTypeTcp 
  , ipTypeUdp 
  , ipTypeIcmp
  , IPBody(..)
    
    -- * Parsers
  , getIPPacket
  , getIPHeader
  , ICMPHeader
  , ICMPType
  , ICMPCode
  , getICMP
  , TCPHeader
  , TCPPortNumber
  , getTCPHeader
  , UDPHeader
  , UDPPortNumber
  , getUDPHeader
  , putIP
  , csum16
  ) where

import Network.Data.IPv4.IPAddress
-- import Network.Data.IPv4.DHCP
import Network.Data.IPv4.UDP
import Data.Bits
import Data.Word
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Control.Exception (assert)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

-- | An IP packet consists of a header and a body.
type IPPacket = (IPHeader, IPBody)

-- | An IP Header includes various information about the packet, including the type of payload it contains. 
-- Warning: this definition does not include every header field included in an IP packet. 
data IPHeader = IPHeader { ipSrcAddress  :: !IPAddress
                         , ipDstAddress  :: !IPAddress
                         , headerLength  :: !Int
                         , totalLength   :: !Int
                         , dscp          :: !DifferentiatedServicesCodePoint -- ^ differentiated services code point - 6 bit number
                         , ecn           :: !Word8 -- Explicit congestion notification (ECN); 2 bits.
                         , ttl           :: !Word8 -- ^ time-to-live.
                         , ipChecksum    :: !Word16
                         , ident :: !Word16
                         , flags :: !Word16
                         }
                deriving (Read,Show,Eq,Generic,NFData)

type DifferentiatedServicesCodePoint = Word8
type FragOffset      = Word16
type IPProtocol      = Word8
type IPTypeOfService = Word8
type TransportPort   = Word16

ipProtocol :: IPBody -> IPProtocol
ipProtocol (TCPInIP _ _) = ipTypeTcp
ipProtocol (UDPInIP _ _) = ipTypeUdp
ipProtocol (ICMPInIP _ _ _) = ipTypeIcmp
ipProtocol (UninterpretedIPBody proto) = proto
{-# INLINE ipProtocol #-}

ipBodyLength :: IPHeader -> Int
ipBodyLength (IPHeader {..})
  = totalLength - (4 * headerLength)
{-# INLINE ipBodyLength #-}

ipTypeTcp, ipTypeUdp, ipTypeIcmp :: IPProtocol

ipTypeTcp  = 6
ipTypeUdp  = 17
ipTypeIcmp = 1

-- | The body of an IP packet can be either a TCP, UDP, ICMP or other packet. 
-- Packets other than TCP, UDP, ICMP are represented as unparsed @ByteString@ values.
data IPBody   = TCPInIP !TCPPortNumber !TCPPortNumber
              | UDPInIP !UDPPortNumber !UDPPortNumber 
              | ICMPInIP !ICMPHeader B.ByteString Word16
              | UninterpretedIPBody !IPProtocol
              deriving (Show,Eq,Generic,NFData)


getIPHeader :: Get (IPHeader, IPProtocol)
getIPHeader = do 
  b1                 <- getWord8
  let version = shiftR b1 4
  assert (version == 4) $ do      
    diffServ           <- getWord8
    totalLen           <- getWord16be
    ident              <- getWord16be     -- ident
    flags              <- getWord16be     -- flagsAndFragOffset
    ttl                <- getWord8        -- ttl
    nwproto            <- getIPProtocol
    ipChecksum         <- getWord16be     -- hdrChecksum
    nwsrc              <- getIPAddress
    nwdst              <- getIPAddress
    let hdrLen = fromIntegral (b1 .&. 0x0f)
    skip (max 0 (4 * (hdrLen - 5)))
    return (IPHeader { ipSrcAddress = nwsrc 
                     , ipDstAddress = nwdst 
                     , headerLength = hdrLen
                     , totalLength  = fromIntegral totalLen
                     , dscp         = shiftR diffServ 2
                     , ecn          = diffServ .&. 3
                     , ttl          = ttl
                     , ipChecksum   = ipChecksum
                     , ident        = ident
                     , flags        = flags
                     }, nwproto)
{-# INLINE getIPHeader #-}

getIPProtocol :: Get IPProtocol 
getIPProtocol = getWord8
{-# INLINE getIPProtocol #-}

getIPPacket :: Get IPPacket 
getIPPacket = getIPHeader >>= getIPBody 
{-# INLINE getIPPacket #-}

getIPBody :: (IPHeader, IPProtocol) -> Get IPPacket
getIPBody (hdr@(IPHeader {..}), nwproto) 
  | nwproto == ipTypeTcp  = do (s,d) <- getTCPHeader (ipBodyLength hdr)
                               return (hdr, TCPInIP s d)
  | nwproto == ipTypeUdp  = do (s,d) <- getUDPHeader
                               skip $ ipBodyLength hdr - 4
                               let bdy = UDPInIP s d
                               return (hdr, bdy)
  | nwproto == ipTypeIcmp = do (icmpHdr, bs, check) <- getICMP (ipBodyLength hdr)
                               return (hdr, ICMPInIP icmpHdr bs check)
  | otherwise             = return (hdr, UninterpretedIPBody nwproto)
{-# INLINE getIPBody #-}

-- ipChecksum_ :: IPHeader -> Word8 -> Word16
-- ipChecksum_ hdr nwproto = csum16 $ runPut $ putIPHeader hdr nwproto 0

csum16 :: L.ByteString -> Word16
csum16 bs = complement $ x + y
  where
    x, y :: Word16
    x = fromIntegral (shiftR (z .&. 0xff00) 8)
    y = fromIntegral (z .&. 0x00ff)
    z :: Word32
    z = foldl (+) 0 ws
    ws :: [Word32]
    ws = runGet (sequence $ replicate (fromIntegral (L.length bs) `div` 4) getWord32be) bs

putIP :: IPPacket -> Put
putIP (hdr, body) = do
  let nwproto = ipProtocol body
  putIPHeader hdr nwproto $ ipChecksum hdr --(ipChecksum hdr nwproto)
  putIPBody (ipBodyLength hdr) body

putIPHeader :: IPHeader -> Word8 -> Word16 -> Put
putIPHeader (IPHeader {..}) nwproto chksum = do
  putWord8 b1
  putWord8 diffServ
  putWord16be $ fromIntegral totalLength
  putWord16be ident -- identification
  putWord16be flags -- flags and offset
  putWord8 ttl
  putWord8 nwproto
  putWord16be chksum
  putIPAddress ipSrcAddress
  putIPAddress ipDstAddress
  -- assume no options.
  where
    b1 = shiftL vERSION_4 4 .|. fromIntegral headerLength
    diffServ = shiftL dscp 2 .|. ecn

vERSION_4 :: Word8
vERSION_4 = 4

putIPBody :: Int -> IPBody -> Put
putIPBody _ (ICMPInIP (icmpType, icmpCode) bs check) = do
  putWord8 icmpType
  putWord8 icmpCode
  putWord16be check -- $ csum16 $ L.fromStrict bs to L.pack [icmpType, icmpCode]
  -- putWord16be $ csum16 $ L.append (L.pack [icmpType, icmpCode]) (L.fromStrict bs)

--    L.fromStrict bs to L.pack [icmpType, icmpCode]
  putByteString bs
putIPBody _ body = error $ "putIPBody: not yet handling IP body: " ++ show body

-- Transport Header
type ICMPHeader = (ICMPType, ICMPCode)
type ICMPType = Word8
type ICMPCode = Word8

getICMP :: Int -> Get (ICMPHeader, B.ByteString, Word16)
getICMP len = do 
  icmp_type <- getWord8
  icmp_code <- getWord8
  check <- getWord16be
  bs <- getByteString $ len - 4
  return ((icmp_type, icmp_code), bs, check)
{-# INLINE getICMP #-}  


type TCPHeader  = (TCPPortNumber, TCPPortNumber)
type TCPPortNumber = Word16

getTCPHeader :: Int -> Get TCPHeader
getTCPHeader len = do 
  srcp <- getWord16be
  dstp <- getWord16be
  skip $ len - 4
  return (srcp,dstp)
{-# INLINE getTCPHeader #-}  
