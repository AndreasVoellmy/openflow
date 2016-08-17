{-# LANGUAGE DisambiguateRecordFields, RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OpenFlow.Match ( 
  Match (..)
  , MatchHeader(..)
  , MatchBody(..)
  , matchAny
  , matchAnyHeader
  , matchAnyBody
  , isExactMatch
  , exactMatchPacketNoPort
  , frameToExactMatchNoPort
  , ofpVlanNone
  , matches
  , overlap
  , matchIntersection
  , prettyPrintMatch
  ) where

import Network.Data.Ethernet.EthernetAddress
import Network.Data.Ethernet.EthernetFrame 
import Network.Data.Ethernet.AddressResolutionProtocol
import Network.Data.IPv4.IPAddress hiding (intersect)
import qualified Network.Data.IPv4.IPAddress as IPAddress
import qualified Network.Data.IPv4.IPPacket as IP
import Network.Data.IPv4.IPPacket (IPHeader(..))
import Network.Data.OpenFlow.Port
import Network.Data.OpenFlow.Packet

import Data.Aeson
import qualified Data.List as List
import Data.Maybe (isJust, catMaybes)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)


-- | Each flow entry includes a match, which essentially defines packet-matching condition. 
-- Fields that are left Nothing are "wildcards".
data Match = Match !(Maybe PortID) !MatchHeader !MatchBody
           deriving (Show,Read,Eq,Ord,Generic,NFData)

instance ToJSON Match
instance FromJSON Match

data MatchHeader = MatchHeader { srcEthAddress, dstEthAddress       :: !(Maybe EthernetAddress), 
                                 vLANID                             :: !(Maybe VLANID), 
                                 vLANPriority                       :: !(Maybe VLANPriority), 
                                 ethFrameType                       :: !(Maybe EthernetTypeCode) }
                 deriving (Show,Read,Eq,Ord, Generic,NFData)
instance ToJSON MatchHeader
instance FromJSON MatchHeader

data MatchBody = MatchBody { ipTypeOfService                    :: !(Maybe IP.IPTypeOfService), 
                             matchIPProtocol                    :: !(Maybe IP.IPProtocol), 
                             srcIPAddress, dstIPAddress         :: !IPAddressPrefix,
                             srcTransportPort, dstTransportPort :: !(Maybe IP.TransportPort) 
                           }
               deriving (Show,Read,Eq,Ord, Generic,NFData)
instance ToJSON MatchBody
instance FromJSON MatchBody
                        
prettyPrintMatch :: Match -> String
prettyPrintMatch (Match ip (MatchHeader seth deth vid vpr etht) (MatchBody tos prot sip dip stp dtp)) = 
    let mshow _ Nothing = Nothing
        mshow prefix (Just v) = Just (prefix ++ show v)
        mshowIP _ (_, 0) = Nothing
        mshowIP prefix ipPref = Just (prefix ++ IPAddress.showPrefix ipPref)
        lst = [ mshow "inPort=" ip,
                fmap (\eth -> "srcEth=" ++ prettyPrintEthernetAddress eth) seth,
                fmap (\eth -> "dstEth=" ++ prettyPrintEthernetAddress eth) deth,                
                mshow "vid=" vid, 
                mshow "vpr=" vpr, 
                mshow "ethtyp=" etht,
                mshow "tos=" tos,
                mshow "prot=" prot,
                mshowIP "sip=" sip,
                mshowIP "dip=" dip,
                mshow "stp=" stp,
                mshow "dtp=" dtp ]
      in "<" ++ List.concat (List.intersperse "," (catMaybes lst)) ++ ">"
-- |A match that matches every packet.
matchAny :: Match
matchAny = Match Nothing matchAnyHeader matchAnyBody

matchAnyHeader :: MatchHeader
matchAnyHeader = MatchHeader { srcEthAddress    = Nothing, 
                               dstEthAddress    = Nothing, 
                               vLANID           = Nothing, 
                               vLANPriority     = Nothing, 
                               ethFrameType     = Nothing }

matchAnyBody :: MatchBody
matchAnyBody = MatchBody { ipTypeOfService  = Nothing, 
                           matchIPProtocol  = Nothing, 
                           srcIPAddress     = defaultIPPrefix,
                           dstIPAddress     = defaultIPPrefix, 
                           srcTransportPort = Nothing, 
                           dstTransportPort = Nothing
                         }

matchIntersection :: Match -> Match -> Maybe Match
matchIntersection
  (Match inp (MatchHeader seth deth vid vp etp) (MatchBody tos pr sh dh sp dp))
  (Match inp' (MatchHeader seth' deth' vid' vp' etp') (MatchBody tos' pr' sh' dh' sp' dp')) = do
  let inter lhs      Nothing  = Just lhs
      inter Nothing  rhs      = Just rhs
      inter (Just l) (Just r) 
        | l == r    = Just (Just l)
        | otherwise = Nothing
  inPort <- inter inp inp'
  srcEth <- inter seth seth'
  dstEth <- inter deth deth'
  vlanID <- inter vid vid'
  vlanPrio <- inter vp vp'
  ethTyp <- inter etp etp'
  ipTOS <- inter tos tos'
  ipProto <- inter pr pr'
  srcIP <- IPAddress.intersect sh sh'
  dstIP <- IPAddress.intersect dh dh'
  srcPort <- inter sp sp'
  dstPort <- inter dp dp'
  return (Match inPort (MatchHeader srcEth dstEth vlanID vlanPrio ethTyp) (MatchBody ipTOS ipProto srcIP dstIP srcPort dstPort))

overlap :: Match -> Match -> Bool
overlap (Match inp (MatchHeader seth deth vid vp etp) (MatchBody tos pr sh dh sp dp))
       (Match inp' (MatchHeader seth' deth' vid' vp' etp') (MatchBody tos' pr' sh' dh' sp' dp')) =
  let inm (Just l) (Just r) = l == r
      inm _ _ = True
      ip = IPAddress.prefixOverlaps
    in inm inp inp' && inm seth seth' && inm deth deth' && inm vid vid' &&
       inm vp vp' && inm etp etp' && inm tos tos' && inm pr pr' && ip sh sh' &&
       ip dh dh' && inm sp sp' && inm dp dp'

-- | Return True if given 'Match' represents an exact match, i.e. no
--   wildcards and the IP addresses' prefixes cover all bits.
isExactMatch :: Match -> Bool
isExactMatch (Match inPort (MatchHeader {..}) (MatchBody {..})) =
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

ofpVlanNone :: Int
ofpVlanNone = 0xffff

exactMatchPacketNoPort :: PacketInfo -> Match
exactMatchPacketNoPort = frameToExactMatchNoPort . enclosedFrame 

frameToExactMatchNoPort :: EthernetFrame -> Match
frameToExactMatchNoPort (h, body) = 
  Match Nothing hdr bdy
  where
    hdr = MatchHeader { srcEthAddress    = Just srcEthAddress, 
                        dstEthAddress    = Just dstEthAddress, 
                        vLANID           = Just vLANID, 
                        vLANPriority     = Just vLANPriority, 
                        ethFrameType     = Just ethFrameType }
    bdy = MatchBody { ipTypeOfService  = Just iptos, 
                      matchIPProtocol  = Just ipproto, 
                      srcIPAddress     = srcip,
                      dstIPAddress     = dstip, 
                      srcTransportPort = Just tsrc, 
                      dstTransportPort = Just tdst
                    }

    ethFrameType = typeCode body
    (srcEthAddress, dstEthAddress, vLANID, vLANPriority) = 
          case h of 
            (EthernetHeader {..}) -> 
              (etherSrc, etherDst, fromIntegral ofpVlanNone, 0)
            (Ethernet8021Q {..})  -> 
              (etherSrc, etherDst, vlanId, priorityCodePoint)
        
    (iptos, ipproto, srcip, dstip, tsrc, tdst) = 
          case body of
            (IPInEthernet (IPHeader {dscp,ipSrcAddress,ipDstAddress}, ipbody)) -> 
              let (tsrc',tdst') = 
                    case ipbody of 
                      (IP.TCPInIP s d)           -> (s,d)
                      (IP.UDPInIP s d)           -> (s,d)
                      (IP.ICMPInIP (icmpType,_) _ _) -> (fromIntegral icmpType, 0)
                      (IP.UninterpretedIPBody _) -> (0,0)
              in (dscp, IP.ipProtocol ipbody, exactPrefix ipSrcAddress, exactPrefix ipDstAddress, tsrc', tdst')
              
            (ARPInEthernet arpPacket) -> 
              let (ipproto', srcip', dstip') = 
                    case arpPacket of 
                      (ARPQuery (ARPQueryPacket {..})) -> (1, exactPrefix querySenderIPAddress, exactPrefix queryTargetIPAddress)
                      (ARPReply (ARPReplyPacket {..})) -> (2, exactPrefix replySenderIPAddress, exactPrefix replyTargetIPAddress)
              in (0, ipproto', srcip', dstip', 0, 0)
    
            _ -> (0, 0, defaultIPPrefix, defaultIPPrefix, 0, 0)


-- | Models the match semantics of an OpenFlow switch.
matches :: (PortID, EthernetFrame) -> Match -> Bool
matches (inPort, (ethHeader,ethBody)) (Match mInPort (MatchHeader {..}) (MatchBody {..})) = 
  noneOrEq mInPort inPort 
  && noneOrEq srcEthAddress (etherSrc ethHeader) 
  && noneOrEq dstEthAddress (etherDst ethHeader)  
  && noneOrEq ethFrameType (typeCode ethBody)    
  && case ethHeader of
      {  EthernetHeader {}   ->  True;
         Ethernet8021Q {..}  ->  noneOrEq vLANID vlanId 
                                 && noneOrEq vLANPriority priorityCodePoint}
  && case ethBody of
       {  IPInEthernet (hdr,bdy) -> 
            noneOrEq matchIPProtocol (IP.ipProtocol bdy) 
            && noneOrEq ipTypeOfService (IP.dscp hdr)  
            && IP.ipSrcAddress hdr `elemOfPrefix` srcIPAddress 
            && IP.ipDstAddress hdr `elemOfPrefix` dstIPAddress 
            && case bdy of
                 { IP.TCPInIP srcPort dstPort ->
                      noneOrEq srcTransportPort srcPort
                      && noneOrEq dstTransportPort dstPort  ;
                   IP.UDPInIP srcPort dstPort ->
                      noneOrEq srcTransportPort srcPort 
                      && noneOrEq dstTransportPort dstPort  ;
                   _ -> True }; 
          _ -> True }    

noneOrEq :: Eq a => Maybe a -> a -> Bool
noneOrEq Nothing _   = True
noneOrEq (Just a) a' = a == a'
