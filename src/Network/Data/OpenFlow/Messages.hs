{-# LANGUAGE DeriveGeneric #-}

{-| 
This module provides a logical representation of OpenFlow switches and protocol messages. 
An OpenFlow message is either a switch-to-controller message or controller-to-switch message. 
In either case, each message is tagged with a unique message identifier. 
-} 
module Network.Data.OpenFlow.Messages ( 
  TransactionID
  , SCMessage (..)
  , CSMessage (..)
  ) where

import Control.DeepSeq (NFData)
import Data.Word
import GHC.Generics
import qualified Network.Data.OpenFlow.Port as Port
import qualified Network.Data.OpenFlow.Packet as Packet
import Network.Data.OpenFlow.Switch
import qualified Network.Data.OpenFlow.FlowTable as FlowTable
import Network.Data.OpenFlow.Statistics
import Network.Data.OpenFlow.Error

-- | Every OpenFlow message is tagged with a MessageID value.
type TransactionID = Word32

-- | The Switch can send the following messages to 
-- the controller.
data SCMessage    = SCHello TransactionID        -- ^ Sent after a switch establishes a TCP connection to the controller
                  | SCEchoRequest TransactionID ![Word8] -- ^ Switch requests an echo reply
                  | SCEchoReply   TransactionID ![Word8] -- ^ Switch responds to an echo request
                  | Features      TransactionID !SwitchFeatures -- ^ Switch reports its features
                  | PacketIn      TransactionID !Packet.PacketInfo -- ^ Switch sends a packet to the controller
                  | PortStatus    TransactionID !Port.PortStatus   -- ^ Switch sends port status
                  | FlowRemoved   TransactionID !FlowTable.FlowRemoved -- ^ Switch reports that a flow has been removed
                  | StatsReply    TransactionID !StatsReply -- ^ Switch reports statistics
                  | Error         TransactionID !SwitchError -- ^ Switch reports an error
                  | BarrierReply TransactionID  -- ^ Switch responds that a barrier has been processed
                  | QueueConfigReply TransactionID !QueueConfigReply
                  deriving (Generic,Show,Eq)

instance NFData SCMessage                       

-- |The controller can send these messages to the switch.
data CSMessage 
    = CSHello TransactionID  -- ^ Controller must send hello before sending any other messages
    | CSEchoRequest TransactionID  ![Word8] -- ^ Controller requests a switch echo
    | CSEchoReply  TransactionID   ![Word8] -- ^ Controller responds to a switch echo request
    | FeaturesRequest TransactionID        -- ^ Controller requests features information
    | PacketOut   TransactionID     !Packet.PacketOut -- ^ Controller commands switch to send a packet
    | FlowMod    TransactionID      !FlowTable.FlowMod -- ^ Controller modifies a switch flow table
    | PortMod    TransactionID      !Port.PortMod -- ^ Controller configures a switch port
    | StatsRequest TransactionID    !StatsRequest -- ^ Controller requests statistics
    | BarrierRequest TransactionID -- ^ Controller requests a barrier
    | SetConfig TransactionID
    | ExtQueueModify TransactionID !Port.PortID ![QueueConfig]
    | ExtQueueDelete TransactionID !Port.PortID ![QueueConfig]
    | Vendor TransactionID
    | GetQueueConfig TransactionID !QueueConfigRequest
      deriving (Show,Eq)
