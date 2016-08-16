{-# LANGUAGE GADTs #-}

module Network.Data.OpenFlow.MatchBuilder
       (
         MatchBuilder
       , Error
       , Attribute
       , match
       , matchOrError
       , (.&&.)
       , (.==.)
       , true
       , in_port
       , vlan_id
       , vlan_priority
       , eth_src
       , eth_dst
       , eth_type
       , arp
       , arp_ip_src
       , arp_ip_dst         
       , ip
       , ip_dst
       , ip_src
       , ip_prot
       , ip_dscp
       , icmp
       , tcp
       , tcp_src
       , tcp_dst
       , udp
       , udp_src
       , udp_dst
       ) where

import Network.Data.Ethernet.EthernetAddress
import Network.Data.Ethernet.EthernetFrame
import Network.Data.IPv4.IPAddress
import Network.Data.IPv4.IPPacket
import Network.Data.OpenFlow.Match
import Network.Data.OpenFlow.Port
import Data.Bits
import Text.Printf (printf)

{-
data Match = Match !(Maybe PortID) !MatchHeader !MatchBody

data MatchHeader = MatchHeader { srcEthAddress, dstEthAddress       :: !(Maybe EthernetAddress), 
                                 vLANID                             :: !(Maybe VLANID), 
                                 vLANPriority                       :: !(Maybe VLANPriority), 
                                 ethFrameType                       :: !(Maybe EthernetTypeCode) }

data MatchBody = MatchBody { ipTypeOfService                    :: !(Maybe IP.IPTypeOfService), 
                             matchIPProtocol                    :: !(Maybe IP.IPProtocol), 
                             srcIPAddress, dstIPAddress         :: !IPAddressPrefix,
                             srcTransportPort, dstTransportPort :: !(Maybe IP.TransportPort) 
                           }
-}

updSrcEthAddress :: MatchHeader -> Maybe EthernetAddress -> MatchHeader
updSrcEthAddress h ma = h { srcEthAddress = ma }

updDstEthAddress :: MatchHeader -> Maybe EthernetAddress -> MatchHeader
updDstEthAddress h ma = h { dstEthAddress = ma }

emptyMatch :: Match
emptyMatch = Match Nothing matchAnyHeader matchAnyBody

true :: MatchBuilder
true = liftBuilder Right

in_port_ :: PortID -> MatchBuilder
in_port_ pid = liftBuilder $ \m@(Match mInPort hdr bdy) ->
  case mInPort of
    Nothing   -> Right (Match (Just pid) hdr bdy)
    Just pid' -> if pid==pid' then Right m else Left "conflicing in_port ids"

eth_addr_set :: EthernetAddress
                -> String
                -> (MatchHeader -> Maybe EthernetAddress -> MatchHeader)
                -> (MatchHeader -> Maybe EthernetAddress)
                -> MatchBuilder
eth_addr_set addr name set get =
  liftBuilder $ \m@(Match mInPort hdr bdy) ->
  case get hdr of
    Nothing    -> Right (Match mInPort (set hdr (Just addr)) bdy)
    Just addr' -> if addr==addr' then Right m else Left (printf "conflicing %s addresses" name)

eth_src_ :: EthernetAddress -> MatchBuilder
eth_src_ addr = eth_addr_set addr "eth_src" updSrcEthAddress srcEthAddress

eth_dst_ :: EthernetAddress -> MatchBuilder
eth_dst_ addr = eth_addr_set addr "eth_dst" updDstEthAddress dstEthAddress

updateSrcIPAddress, updateDstIPAddress :: IPAddressPrefix -> MatchBody -> MatchBody
updateSrcIPAddress prefix body = body { srcIPAddress = prefix}
updateDstIPAddress prefix body = body { dstIPAddress = prefix}

vlan_id_ :: VLANID -> MatchBuilder
vlan_id_ vid = liftBuilder $ \m@(Match mInPort hdr bdy) ->
  case vLANID hdr of
    Nothing -> Right (Match mInPort (hdr { vLANID = Just vid }) bdy)
    Just vid' | vid' == vid  -> Right m
              | otherwise    -> Left $ printf "conflicting vlan ids. Was %d, expecting %d" vid' vid

vlan_priority_ :: VLANPriority -> MatchBuilder
vlan_priority_ pcp = liftBuilder $ \m@(Match mInPort hdr bdy) ->
  case vLANPriority hdr of
    Nothing -> Right (Match mInPort (hdr { vLANPriority = Just pcp }) bdy)
    Just pcp' | pcp' == pcp  -> Right m
              | otherwise    -> Left $ printf "conflicting vlan priorities. Was %d, expecting %d" pcp' pcp

eth_type_ :: EthernetTypeCode -> MatchBuilder
eth_type_ c = liftBuilder $ \m@(Match mInPort hdr bdy) ->
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just c }) bdy)
    Just typ | typ == c  -> Right m
             | otherwise -> Left $ printf "conflicting eth types. Was %d, expecting %d" typ c

arp :: MatchBuilder
arp = liftBuilder $ \(Match mInPort hdr bdy) ->
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just ethTypeARP }) bdy)
    Just typ | typ == ethTypeARP -> Right (Match mInPort hdr bdy)
             | otherwise        -> Left "ACK conflicting L3 packet types"

arp_ip_src_ :: IPAddressPrefix -> MatchBuilder
arp_ip_src_ prefix = liftBuilder $ \(Match mInPort hdr bdy) ->
  let bdy' = bdy { srcIPAddress = prefix} in
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just ethTypeARP }) bdy')
    Just typ | typ == ethTypeARP -> Right (Match mInPort hdr bdy')
             | otherwise        -> Left "ACK conflicting L3 packet types"

arp_ip_dst_ :: IPAddressPrefix -> MatchBuilder
arp_ip_dst_ prefix = liftBuilder $ \(Match mInPort hdr bdy) ->
  let bdy' = bdy { dstIPAddress = prefix} in
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just ethTypeARP }) bdy')
    Just typ | typ == ethTypeARP -> Right (Match mInPort hdr bdy')
             | otherwise        -> Left "ACK conflicting L3 packet types"

ip :: MatchBuilder
ip = liftBuilder $ \(Match mInPort hdr bdy) ->
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just ethTypeIP }) bdy)
    Just typ | typ == ethTypeIP -> Right (Match mInPort hdr bdy)
             | otherwise        -> Left "conflicting L3 packet types"

set_ip_field :: (MatchBody -> MatchBody) -> MatchBuilder
set_ip_field set = liftBuilder $ \(Match mInPort hdr bdy) ->
  case ethFrameType hdr of
    Nothing -> Right (Match mInPort (hdr { ethFrameType = Just ethTypeIP }) (set bdy))
    Just typ | typ == ethTypeIP -> Right (Match mInPort hdr (set bdy))
             | otherwise        -> Left "conflicting L3 packet types"
                                   
ip_dst_ :: IPAddressPrefix -> MatchBuilder
ip_dst_ = set_ip_field . updateDstIPAddress

ip_src_ :: IPAddressPrefix -> MatchBuilder
ip_src_ = set_ip_field . updateSrcIPAddress

dscp_ :: DifferentiatedServicesCodePoint -> MatchBuilder
dscp_ x = set_ip_field (\bdy -> bdy { ipTypeOfService = Just (shiftL x 2) })

icmp :: MatchBuilder
icmp = set_ip_field (\bdy -> bdy { matchIPProtocol = Just ipTypeIcmp })

tcp :: MatchBuilder
tcp  = set_ip_field (\bdy -> bdy { matchIPProtocol = Just ipTypeTcp })

udp :: MatchBuilder
udp  = set_ip_field (\bdy -> bdy { matchIPProtocol = Just ipTypeUdp })

ip_prot_ :: IPProtocol -> MatchBuilder
ip_prot_ p = set_ip_field (\bdy -> bdy { matchIPProtocol = Just p })

tcp_src_ :: TCPPortNumber -> MatchBuilder
tcp_src_ = set_tcp_field . updateTransportSrc

tcp_dst_ :: TCPPortNumber -> MatchBuilder
tcp_dst_ = set_tcp_field . updateTransportDst

udp_src_ :: TCPPortNumber -> MatchBuilder
udp_src_ = set_udp_field . updateTransportSrc

udp_dst_ :: TCPPortNumber -> MatchBuilder
udp_dst_ = set_udp_field . updateTransportDst

updateTransportSrc :: TCPPortNumber -> MatchBody -> MatchBody
updateTransportSrc s bdy = bdy { srcTransportPort = Just s }

updateTransportDst :: TCPPortNumber -> MatchBody -> MatchBody
updateTransportDst s bdy = bdy { dstTransportPort = Just s }

set_tcp_field :: (MatchBody -> MatchBody) -> MatchBuilder
set_tcp_field = set_transport_field ipTypeTcp 

set_udp_field :: (MatchBody -> MatchBody) -> MatchBuilder
set_udp_field = set_transport_field ipTypeUdp

set_transport_field :: IPProtocol -> (MatchBody -> MatchBody) -> MatchBuilder
set_transport_field prot' set = liftBuilder $ \(Match mInPort hdr bdy) ->
  case ethFrameType hdr of
    Nothing ->
      let hdr' = hdr { ethFrameType = Just ethTypeIP }
          bdy' = set (bdy { matchIPProtocol = Just prot' })
      in Right $ Match mInPort hdr' bdy'
    Just typ
      | typ == ethTypeIP ->
      case matchIPProtocol bdy of
        Nothing -> let bdy' = set (bdy { matchIPProtocol = Just prot' })
                   in Right $ Match mInPort hdr bdy'
        Just prot | prot == prot' -> Right $ Match mInPort hdr (set bdy)
                  | otherwise     -> Left "conflicting transport layer types"
      | otherwise -> Left "Cannot set transport field of non-IP frame"

newtype MatchBuilder = MatchBuilder (Either Error Match -> Either Error Match)
type Error = String

instance Monoid MatchBuilder where
  mempty = MatchBuilder id
  mappend (MatchBuilder f) (MatchBuilder g) = MatchBuilder (f.g)

(.&&.) :: MatchBuilder -> MatchBuilder -> MatchBuilder
(.&&.) = mappend

data Attribute a where
  ETH_SRC :: Attribute EthernetAddress
  ETH_DST :: Attribute EthernetAddress
  ETH_TYP :: Attribute EthernetTypeCode
  VLAN_ID :: Attribute VLANID
  VLAN_PRIORITY :: Attribute VLANPriority
  ARP_IP_SRC :: Attribute IPAddressPrefix
  ARP_IP_DST :: Attribute IPAddressPrefix    
  IP_SRC :: Attribute IPAddressPrefix
  IP_DST :: Attribute IPAddressPrefix
  IP_PROT :: Attribute IPProtocol
  IP_DSCP :: Attribute DifferentiatedServicesCodePoint
  TCP_SRC :: Attribute TCPPortNumber
  TCP_DST :: Attribute TCPPortNumber  
  UDP_SRC :: Attribute TCPPortNumber
  UDP_DST :: Attribute TCPPortNumber  
  IN_PORT :: Attribute PortID

in_port :: Attribute PortID
in_port = IN_PORT

vlan_id :: Attribute VLANID
vlan_id = VLAN_ID

vlan_priority :: Attribute VLANPriority
vlan_priority = VLAN_PRIORITY

eth_src :: Attribute EthernetAddress
eth_src = ETH_SRC

eth_dst :: Attribute EthernetAddress
eth_dst = ETH_DST

eth_type :: Attribute EthernetTypeCode
eth_type = ETH_TYP

arp_ip_src :: Attribute IPAddressPrefix
arp_ip_src  = ARP_IP_SRC

arp_ip_dst :: Attribute IPAddressPrefix
arp_ip_dst  = ARP_IP_DST

ip_src :: Attribute IPAddressPrefix
ip_src  = IP_SRC

ip_dst :: Attribute IPAddressPrefix
ip_dst  = IP_DST

ip_prot :: Attribute IPProtocol
ip_prot = IP_PROT

ip_dscp :: Attribute DifferentiatedServicesCodePoint
ip_dscp = IP_DSCP

tcp_src :: Attribute TCPPortNumber
tcp_src = TCP_SRC

tcp_dst :: Attribute TCPPortNumber
tcp_dst = TCP_DST

udp_src :: Attribute TCPPortNumber
udp_src = UDP_SRC

udp_dst :: Attribute TCPPortNumber
udp_dst = UDP_DST

(.==.) :: Attribute a -> a -> MatchBuilder
(.==.) VLAN_ID vid = vlan_id_ vid
(.==.) VLAN_PRIORITY pcp = vlan_priority_ pcp
(.==.) IN_PORT p = in_port_ p
(.==.) ETH_DST addr = eth_dst_ addr
(.==.) ETH_SRC addr = eth_src_ addr
(.==.) ETH_TYP c    = eth_type_ c
(.==.) ARP_IP_SRC addr = arp_ip_src_ addr
(.==.) ARP_IP_DST addr = arp_ip_dst_ addr
(.==.) IP_DST addr = ip_dst_ addr
(.==.) IP_SRC addr = ip_src_ addr
(.==.) IP_PROT p   = ip_prot_ p
(.==.) IP_DSCP x   = dscp_ x
(.==.) TCP_DST s   = tcp_dst_ s
(.==.) TCP_SRC s   = tcp_src_ s
(.==.) UDP_DST s   = udp_dst_ s
(.==.) UDP_SRC s   = udp_src_ s

infixr 4 .&&.
infix 6 .==.


liftBuilder :: (Match -> Either Error Match) -> MatchBuilder
liftBuilder f = MatchBuilder $ \x ->
  case x of
    Left e -> Left e
    Right m -> f m

match :: MatchBuilder -> Match
match b =
  case matchOrError b of
    Left e -> error e
    Right m -> m

matchOrError :: MatchBuilder -> Either Error Match
matchOrError (MatchBuilder f) = f (Right emptyMatch)

        
