{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OpenFlow.Action (
  -- * Actions
  Action (..)
  , ActionType (..)
  , PseudoPort (..)
  , MaxLenToSendController
  , VendorID
  , QueueID
  -- * Action sequences
  , ActionSequence(..)
  , actionSequenceToList
  , actionSequenceSizeInBytes
  , sendOnPort, phyPort, sendOnInPort, flood, drop, allPhysicalPorts, processNormally, sendToController, processWithTable
  , setVlanVID, setVlanPriority, stripVlanHeader, setEthSrcAddr, setEthDstAddr
  , setIPSrcAddr, setIPDstAddr
  , setIPToS
  , setTransportSrcPort
  , setTransportDstPort
  , enqueue
  , vendorAction
  ) where

import Control.DeepSeq (NFData)
import GHC.Generics (Generic)
import Prelude hiding (drop)
import Network.Data.OpenFlow.Port
import Network.Data.Ethernet.EthernetAddress
import Network.Data.Ethernet.EthernetFrame
import Network.Data.IPv4.IPAddress
import Network.Data.IPv4.IPPacket
import Data.Word

-- |The supported switch actions are denoted with these symbols.
data ActionType = OutputToPortType    
                | SetVlanVIDType      
                | SetVlanPriorityType 
                | StripVlanHeaderType 
                | SetEthSrcAddrType   
                | SetEthDstAddrType   
                | SetIPSrcAddrType    
                | SetIPDstAddrType    
                | SetIPTypeOfServiceType        
                | SetTransportSrcPortType
                | SetTransportDstPortType
                | EnqueueType            
                | VendorActionType
                  deriving (Show,Read,Eq,Ord,Enum,Generic,NFData)

-- | Each flow table entry contains a list of actions that will
-- be executed when a packet matches the entry. 
-- Specification: @ofp_action_header@ and all @ofp_action_*@ structures.
data Action
    = SendOutPort !PseudoPort        -- ^send out given port
    | SetVlanVID VLANID             -- ^set the 802.1q VLAN ID
    | SetVlanPriority VLANPriority  -- ^set the 802.1q priority
    | StripVlanHeader               -- ^strip the 802.1q header
    | SetEthSrcAddr EthernetAddress -- ^set ethernet source address
    | SetEthDstAddr EthernetAddress -- ^set ethernet destination address
    | SetIPSrcAddr IPAddress        -- ^set IP source address
    | SetIPDstAddr IPAddress        -- ^set IP destination address
    | SetIPToS IPTypeOfService      -- ^IP ToS (DSCP field)
    | SetTransportSrcPort TransportPort -- ^set TCP/UDP source port
    | SetTransportDstPort TransportPort -- ^set TCP/UDP destination port
    | Enqueue {
        enqueuePort :: PortID,       -- ^port the queue belongs to
        queueID     :: QueueID       -- ^where to enqueue the packets
      } -- ^output to queue
    | VendorAction VendorID [Word8] 
    deriving (Show,Eq,Ord,Generic,NFData)
           

-- | A @PseudoPort@ denotes the target of a forwarding
-- action. 
data PseudoPort = Flood                               -- ^send out all physical ports except input port and those disabled by STP
                | PhysicalPort PortID                 -- ^send out physical port with given id
                | InPort                              -- ^send packet out the input port
                | AllPhysicalPorts                    -- ^send out all physical ports except input port
                | ToController MaxLenToSendController -- ^send to controller
                | NormalSwitching                     -- ^process with normal L2/L3 switching
                | WithTable                           -- ^process packet with flow table
                  deriving (Show,Read, Eq, Ord, Generic, NFData)

-- | A send to controller action includes the maximum
-- number of bytes that a switch will send to the 
-- controller.
type MaxLenToSendController = Word16

type VendorID = Word32
type QueueID  = Word32
       
-- | Sequence of actions, represented as finite lists. The Monoid instance of
-- lists provides methods for denoting the do-nothing action (@mempty@) and for concatenating action sequences @mconcat@. 
-- type ActionSequence = [Action]
data ActionSequence = ActionSequence !Int ![Action]
                    deriving (Show, Eq, Ord, Generic, NFData)
                             
instance Monoid ActionSequence where                             
  mempty = drop
  mappend (ActionSequence s1 a1) (ActionSequence s2 a2) = ActionSequence (s1 + s2) (a1 ++ a2)
                             
actionSequenceToList :: ActionSequence -> [Action]                             
actionSequenceToList (ActionSequence _ as) = as

actionSequenceSizeInBytes :: ActionSequence -> Int
actionSequenceSizeInBytes (ActionSequence !sz _) = sz

-- | send p is a packet send action.
send :: PseudoPort -> ActionSequence
send p = ActionSequence 8 [SendOutPort p]

sendOnPort :: PortID -> ActionSequence
sendOnPort = phyPort

phyPort :: PortID -> ActionSequence
phyPort p = ActionSequence 8 [SendOutPort $ PhysicalPort p]
{-# INLINE phyPort #-}

sendOnInPort, flood, drop, allPhysicalPorts, processNormally, processWithTable :: ActionSequence
sendOnInPort = send InPort
flood = send Flood
drop  = ActionSequence 0 []
allPhysicalPorts = send AllPhysicalPorts
processNormally = send NormalSwitching
processWithTable = send WithTable

sendToController :: MaxLenToSendController -> ActionSequence
sendToController maxlen = send (ToController maxlen)

setVlanVID :: VLANID -> ActionSequence
setVlanVID vlanid = ActionSequence 8 [SetVlanVID vlanid]

setVlanPriority :: VLANPriority -> ActionSequence
setVlanPriority x = ActionSequence 8 [SetVlanPriority x]

stripVlanHeader :: ActionSequence
stripVlanHeader = ActionSequence 8 [StripVlanHeader]

setEthSrcAddr :: EthernetAddress -> ActionSequence
setEthSrcAddr addr = ActionSequence 16 [SetEthSrcAddr addr]

setEthDstAddr :: EthernetAddress -> ActionSequence
setEthDstAddr addr =ActionSequence 16 [SetEthDstAddr addr]

setIPSrcAddr ::  IPAddress -> ActionSequence
setIPSrcAddr addr = ActionSequence 8 [SetIPSrcAddr addr]

setIPDstAddr ::  IPAddress -> ActionSequence
setIPDstAddr addr = ActionSequence 8 [SetIPDstAddr addr]

setIPToS :: IPTypeOfService -> ActionSequence
setIPToS tos = ActionSequence 8 [SetIPToS tos]

setTransportSrcPort ::  TransportPort -> ActionSequence
setTransportSrcPort port = ActionSequence 8 [SetTransportSrcPort port]

setTransportDstPort ::  TransportPort -> ActionSequence
setTransportDstPort port = ActionSequence 8 [SetTransportDstPort port]

enqueue :: PortID -> QueueID -> ActionSequence
enqueue portid queueid = ActionSequence 16 [Enqueue portid queueid]    

vendorAction :: VendorID -> [Word8] -> ActionSequence
vendorAction vid bytes = ActionSequence (length bytes + 8) [VendorAction vid bytes]




