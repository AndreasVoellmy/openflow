{-# LANGUAGE CPP, DisambiguateRecordFields, RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}

module Nettle.OpenFlow.Match ( 
  Match (..)
  , matchAny
  , isExactMatch
  , getExactMatch
  , frameToExactMatch
  , frameToExactMatchNoPort
  , ofpVlanNone
  , matches
  ) where

import Nettle.Ethernet.EthernetAddress
import Nettle.Ethernet.EthernetFrame 
import Nettle.Ethernet.AddressResolutionProtocol
import Nettle.IPv4.IPAddress
import qualified Nettle.IPv4.IPPacket as IP
import Nettle.IPv4.IPPacket (IPHeader(..))
import Nettle.OpenFlow.Port
import Data.Maybe (isJust)
import Control.Monad.Error
import Data.HList 
import qualified Nettle.OpenFlow.Get as Strict
import Data.Bits
import Data.Word


-- | Each flow entry includes a match, which essentially defines packet-matching condition. 
-- Fields that are left Nothing are "wildcards".
data Match = Match { inPort                             :: !(Maybe PortID), 
                     srcEthAddress, dstEthAddress       :: !(Maybe EthernetAddress), 
                     vLANID                             :: !(Maybe VLANID), 
                     vLANPriority                       :: !(Maybe VLANPriority), 
                     ethFrameType                       :: !(Maybe EthernetTypeCode),
                     ipTypeOfService                    :: !(Maybe IP.IPTypeOfService), 
                     matchIPProtocol                    :: !(Maybe IP.IPProtocol), 
                     srcIPAddress, dstIPAddress         :: !IPAddressPrefix,
                     srcTransportPort, dstTransportPort :: !(Maybe IP.TransportPort) 
                   }
           | ExactMatch 
             !PortID 
             !EthernetAddress !EthernetAddress !VLANID !VLANPriority !EthernetTypeCode 
             !IP.IPTypeOfService !IP.IPProtocol !IPAddressPrefix !IPAddressPrefix  !IP.TransportPort  !IP.TransportPort 
             deriving (Show,Read,Eq)


-- |A match that matches every packet.
matchAny :: Match
matchAny = Match { inPort           = Nothing, 
                   srcEthAddress    = Nothing, 
                   dstEthAddress    = Nothing, 
                   vLANID           = Nothing, 
                   vLANPriority     = Nothing, 
                   ethFrameType     = Nothing, 
                   ipTypeOfService  = Nothing, 
                   matchIPProtocol  = Nothing, 
                   srcIPAddress     = defaultIPPrefix,
                   dstIPAddress     = defaultIPPrefix, 
                   srcTransportPort = Nothing, 
                   dstTransportPort = Nothing
                 }

-- | Return True if given 'Match' represents an exact match, i.e. no
--   wildcards and the IP addresses' prefixes cover all bits.
isExactMatch :: Match -> Bool
isExactMatch (Match {..}) =
    (isJust inPort) &&
    (isJust srcEthAddress) &&
    (isJust dstEthAddress) &&
    (isJust vLANID) &&
    (isJust vLANPriority) &&
    (isJust ethFrameType) &&
    (isJust ipTypeOfService) &&
    (isJust matchIPProtocol) &&
    (prefixIsExact srcIPAddress) &&
    (prefixIsExact dstIPAddress) &&
    (isJust srcTransportPort) &&
    (isJust dstTransportPort)

ofpVlanNone         = 0xffff


frameToExactMatch :: PortID -> EthernetFrame -> Match
frameToExactMatch inPort (HCons h (HCons body HNil)) = 
  ExactMatch inPort srcEthAddress dstEthAddress vLANID vLANPriority ethFrameType iptos ipproto srcip dstip tsrc tdst 
  where (srcEthAddress, dstEthAddress, vLANID, vLANPriority, ethFrameType) = 
          case h of 
            (EthernetHeader {..}) -> 
              (sourceMACAddress, destMACAddress, fromIntegral ofpVlanNone, 0, typeCode)
            (Ethernet8021Q {..})  -> 
              (sourceMACAddress, destMACAddress, vlanId, priorityCodePoint, typeCode)
        
        (iptos, ipproto, srcip, dstip, tsrc, tdst) = 
          case body of
            (IPInEthernet (HCons (IPHeader {dscp,ipProtocol,ipSrcAddress,ipDstAddress}) (HCons ipbody HNil))) -> 
              let (tsrc,tdst) = 
                    case ipbody of 
                      (IP.TCPInIP thdr)                 -> thdr
                      (IP.UDPInIP thdr _)               -> thdr
                      (IP.ICMPInIP (icmpType,icmpCode)) -> (fromIntegral icmpType, 0)
                      (IP.UninterpretedIPBody _)        -> (0,0)
              in (dscp, ipProtocol, exactPrefix ipSrcAddress, exactPrefix ipDstAddress, tsrc, tdst)
              
            (ARPInEthernet arpPacket) -> 
              let (ipproto, srcip, dstip) = 
                    case arpPacket of 
                      (ARPQuery (ARPQueryPacket {..})) -> (1, exactPrefix querySenderIPAddress, exactPrefix queryTargetIPAddress)
                      (ARPReply (ARPReplyPacket {..})) -> (2, exactPrefix replySenderIPAddress, exactPrefix replyTargetIPAddress)
              in (0, ipproto, srcip, dstip, 0, 0)
    
            (UninterpretedEthernetBody x) -> 
              (0, 0, defaultIPPrefix, defaultIPPrefix, 0, 0)




frameToExactMatchNoPort :: EthernetFrame -> Match
frameToExactMatchNoPort (HCons h (HCons body HNil)) = 
  Match { inPort           = Nothing, 
          srcEthAddress    = Just srcEthAddress, 
          dstEthAddress    = Just dstEthAddress, 
          vLANID           = Just vLANID, 
          vLANPriority     = Just vLANPriority, 
          ethFrameType     = Just ethFrameType, 
          ipTypeOfService  = Just iptos, 
          matchIPProtocol  = Just ipproto, 
          srcIPAddress     = srcip,
          dstIPAddress     = dstip, 
          srcTransportPort = Just tsrc, 
          dstTransportPort = Just tdst
        }

  where (srcEthAddress, dstEthAddress, vLANID, vLANPriority, ethFrameType) = 
          case h of 
            (EthernetHeader {..}) -> 
              (sourceMACAddress, destMACAddress, fromIntegral ofpVlanNone, 0, typeCode)
            (Ethernet8021Q {..})  -> 
              (sourceMACAddress, destMACAddress, vlanId, priorityCodePoint, typeCode)
        
        (iptos, ipproto, srcip, dstip, tsrc, tdst) = 
          case body of
            (IPInEthernet (HCons (IPHeader {dscp,ipProtocol,ipSrcAddress,ipDstAddress}) (HCons ipbody HNil))) -> 
              let (tsrc,tdst) = 
                    case ipbody of 
                      (IP.TCPInIP thdr)                 -> thdr
                      (IP.UDPInIP thdr _)               -> thdr
                      (IP.ICMPInIP (icmpType,icmpCode)) -> (fromIntegral icmpType, 0)
                      (IP.UninterpretedIPBody _)        -> (0,0)
              in (dscp, ipProtocol, exactPrefix ipSrcAddress, exactPrefix ipDstAddress, tsrc, tdst)
              
            (ARPInEthernet arpPacket) -> 
              let (ipproto, srcip, dstip) = 
                    case arpPacket of 
                      (ARPQuery (ARPQueryPacket {..})) -> (1, exactPrefix querySenderIPAddress, exactPrefix queryTargetIPAddress)
                      (ARPReply (ARPReplyPacket {..})) -> (2, exactPrefix replySenderIPAddress, exactPrefix replyTargetIPAddress)
              in (0, ipproto, srcip, dstip, 0, 0)
    
            (UninterpretedEthernetBody x) -> 
              (0, 0, defaultIPPrefix, defaultIPPrefix, 0, 0)






-- | Utility function to get an exact match corresponding to 
-- a packet (as given by a byte sequence).
getExactMatch :: PortID -> Strict.Get Match
getExactMatch inPort = do
  frame <- getEthernetFrame
  return (frameToExactMatch inPort frame)


-- | Models the match semantics of an OpenFlow switch.
matches :: (PortID, EthernetFrame) -> Match -> Bool
matches (inPort, frame) (m@Match { inPort=inPort', ipTypeOfService=ipTypeOfService',..}) = 
    and [maybe True matchesInPort           inPort', 
         maybe True matchesSrcEthAddress    srcEthAddress,
         maybe True matchesDstEthAddress    dstEthAddress, 
         maybe True matchesVLANID           vLANID, 
         maybe True matchesVLANPriority     vLANPriority,
         maybe True matchesEthFrameType     ethFrameType, 
         maybe True matchesIPProtocol       matchIPProtocol, 
         maybe True matchesIPToS            ipTypeOfService',
         matchesIPSourcePrefix srcIPAddress,
         matchesIPDestPrefix dstIPAddress,
         maybe True matchesSrcTransportPort srcTransportPort, 
         maybe True matchesDstTransportPort dstTransportPort ]
        where
          ethHeader = hOccurs frame
          matchesInPort p = p == inPort
          matchesSrcEthAddress a = sourceMACAddress ethHeader == a 
          matchesDstEthAddress a = destMACAddress ethHeader == a 
          matchesVLANID a = 
              case ethHeader of 
                EthernetHeader {} -> True
                Ethernet8021Q {..}-> a == vlanId
          matchesVLANPriority a = 
              case ethHeader of 
                EthernetHeader {}  -> True
                Ethernet8021Q {..} -> a == priorityCodePoint
          matchesEthFrameType  t = t == typeCode ethHeader
          matchesIPProtocol protCode = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipProtocol (hOccurs pkt) == protCode
                _        -> True
          matchesIPToS tos =
                case eth_ip_packet frame of 
                  Just pkt -> tos == IP.dscp (hOccurs pkt)
                  _        -> True
          matchesIPSourcePrefix prefix = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipSrcAddress (hOccurs pkt) `elemOfPrefix` prefix
                Nothing  -> True
          matchesIPDestPrefix prefix = 
              case eth_ip_packet frame of 
                Just pkt -> IP.ipSrcAddress (hOccurs pkt) `elemOfPrefix` prefix
                Nothing  -> True
          matchesSrcTransportPort sp = 
                case eth_ip_packet frame of
                  Just pkt -> 
                    case hOccurs pkt of
                      IP.TCPInIP (srcPort, _) -> srcPort == sp
                      IP.UDPInIP (srcPort, _) body -> srcPort == sp
                      _ -> True
                  Nothing -> True
          matchesDstTransportPort dp = 
                case eth_ip_packet frame of
                  Just ipPacket ->
                    case hOccurs ipPacket of 
                      IP.TCPInIP (_, dstPort) -> dstPort == dp
                      IP.UDPInIP (_, dstPort) body -> dstPort == dp
                      _                       -> True
                  Nothing -> True
