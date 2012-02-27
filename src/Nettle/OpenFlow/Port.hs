module Nettle.OpenFlow.Port (
  Port (..) 
  , PortID
  , SpanningTreePortState (..)
  , PortConfigAttribute (..)
  , PortFeature (..)
  , PortFeatures 
  , PortMod (..)
  , PortStatus
  , PortStatusUpdateReason (..)
  , portAttributeOn
  , portAttributeOff
  ) where

import Data.Word
import Data.Map (Map)
import qualified Data.Map as Map
import Nettle.Ethernet.EthernetAddress

-- ^ A switch receives and sends packets on a port; The Port data type models attributes of a physical port.
data Port 
    = Port { 
        portID                 :: PortID,                -- ^value datapath associates with a physical port
        portName               :: String,                -- ^human-readable interface name
        portAddress            :: EthernetAddress,       -- ^the Ethernet address of the port
        portConfig             :: [PortConfigAttribute], -- ^describes spanning tree and administrative settings      
        portLinkDown           :: Bool,                  -- ^describes whether the link is down
        portSTPState           :: SpanningTreePortState, -- ^describes spanning tree state
        portCurrentFeatures    :: Maybe PortFeatures,    -- ^port's current features
        portAdvertisedFeatures :: Maybe PortFeatures,    -- ^features advertised by port
        portSupportedFeatures  :: Maybe PortFeatures,    -- ^features supported by port
        portPeerFeatures       :: Maybe PortFeatures     -- ^features advertised by peer 
      } deriving (Show,Read,Eq)

type PortID = Word16

data SpanningTreePortState = STPListening 
                           | STPLearning 
                           | STPForwarding 
                           | STPBlocking 
                             deriving (Show,Read,Eq,Ord,Enum)

-- | Possible behaviors of a physical port. Specification:
--   @ofp_port_config@.
data PortConfigAttribute
    = PortDown       -- ^port is administratively down
    | STPDisabled    -- ^disable 802.1D spanning tree on this port
    | OnlySTPackets  -- ^drop all packets except 802.1D spanning tree packets
    | NoSTPackets    -- ^drop received 802.1D STP packets
    | NoFlooding     -- ^do not include this port when flooding
    | DropForwarded  -- ^drop packets forwarded to port
    | NoPacketInMsg  -- ^do not send packet-in messages for this port
    deriving (Show,Read,Eq,Ord,Enum)

-- | Possible port features. Specification @ofp_port_features@.
data PortFeature
    = Rate10MbHD  -- ^10 Mb half-duplex rate support
    | Rate10MbFD  -- ^10 Mb full-duplex rate support
    | Rate100MbHD -- ^100 Mb half-duplex rate support
    | Rate100MbFD -- ^100 Mb full-duplex rate support
    | Rate1GbHD   -- ^1 Gb half-duplex rate support
    | Rate1GbFD   -- ^1 Gb full-duplex rate support
    | Rate10GbFD  -- ^10 Gb full-duplex rate support
    | Copper
    | Fiber
    | AutoNegotiation
    | Pause
    | AsymmetricPause
    deriving (Show,Read,Eq)

-- | Set of 'PortFeature's. Specification: bitmap of members in @enum
--   ofp_port_features@.
type PortFeatures = [PortFeature]

-- |A port can be configured with a @PortMod@ message.
data PortMod 
    = PortModRecord { 
        portNumber        :: PortID,                      -- ^ port number of port to modify
        hwAddr            :: EthernetAddress,             -- ^ hardware address of the port 
                                                          -- (redundant with the port number above; both are required)
        attributesToSet   :: Map PortConfigAttribute Bool -- ^ attributes mapped to true will be set on, 
                                                          -- attributes mapped to false will be turned off, 
                                                          -- and attributes missing will be unchanged
      } deriving (Show,Read,Eq)

-- | The @PortStatus@ represents information regarding
-- a change to a port state on a switch.
type PortStatus  = (PortStatusUpdateReason, Port)

-- | The reason that a port status update message
-- was sent.
data PortStatusUpdateReason = PortAdded 
                            | PortDeleted 
                            | PortModified 
                              deriving (Show,Read,Eq,Ord,Enum)

portAttributeOn :: PortID -> EthernetAddress -> PortConfigAttribute -> PortMod
portAttributeOn portID addr attr = PortModRecord portID addr (Map.singleton attr True)

portAttributeOff :: PortID -> EthernetAddress -> PortConfigAttribute -> PortMod
portAttributeOff portID addr attr = PortModRecord portID addr (Map.singleton attr False)
