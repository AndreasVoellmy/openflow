{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OpenFlow.Switch ( 
  SwitchFeatures (..)
  , SwitchID
  , SwitchCapability (..)
  , maxNumberPorts
  , QueueConfigRequest (..)
  , QueueConfigReply (..)
  , QueueConfig (..)
  , QueueLength
  , QueueProperty (..)
  , QueueRate (..)
  , showSwID
  ) where

import Data.Word
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)
import Network.Data.OpenFlow.Port
import Network.Data.OpenFlow.Action
import Numeric (showHex)

-- |The switch features record, summarizes information about a switch
data SwitchFeatures 
    = SwitchFeatures  { 
        switchID           :: SwitchID,           -- ^unique switch identifier 
        packetBufferSize   :: Integer,             -- ^maximum number of packets buffered at the switch
        numberFlowTables   :: Integer,              -- ^number of flow tables
        capabilities :: [SwitchCapability], -- ^switch's capabilities
        supportedActions   :: [ActionType],       -- ^switch's supported actions
        ports        :: [Port]              -- ^description of each port on switch
      } deriving (Show,Read,Eq,Generic,NFData)

-- |A unique identifier for a switch, also known as DataPathID.
type SwitchID = Word64

showSwID :: SwitchID -> String
showSwID sid = "0x" ++ showHex sid ""

-- | Maximum number of ports on a switch
maxNumberPorts :: PortID
maxNumberPorts = 0xff00


-- |The switch capabilities are denoted with these symbols
data SwitchCapability = HasFlowStats                               -- ^can provide flow statistics
                      | HasTableStats                              -- ^can provide table statistics
                      | HasPortStats                               -- ^can provide port statistics
                      | SpanningTree                               -- ^supports the 802.1d spanning tree protocol
                      | MayTransmitOverMultiplePhysicalInterfaces
                      | HasQueueStatistics                         -- ^can provide queue statistics
                      | CanMatchIPAddressesInARPPackets            -- ^match IP addresses in ARP packets
                      | CanReassembleIPFragments                   -- ^can reassemble IP fragments
                        deriving (Show,Read,Eq,Ord,Enum,Generic,NFData)

data QueueConfigRequest = QueueConfigRequest PortID        
                        deriving (Show,Read,Eq,Generic,NFData)

data QueueConfigReply = PortQueueConfig PortID [QueueConfig]
                      deriving (Show,Read,Eq,Generic,NFData)
                               
data QueueConfig = QueueConfig QueueID [QueueProperty]
                 deriving (Show,Read,Eq,Generic,NFData)

type QueueLength = Word16

data QueueProperty = MinRateQueue QueueRate 
                   deriving (Show,Read,Eq,Generic,NFData)
data QueueRate = Disabled | Enabled Word16
               deriving (Show, Read, Eq, Generic, NFData)


