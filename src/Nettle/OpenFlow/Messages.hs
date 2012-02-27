{-# LANGUAGE CPP, ScopedTypeVariables #-}

{-| 
This module provides a logical representation of OpenFlow switches and protocol messages. 
An OpenFlow message is either a switch-to-controller message or controller-to-switch message. 
In either case, each message is tagged with a unique message identifier. 
-} 
module Nettle.OpenFlow.Messages ( 
  TransactionID
  , SCMessage (..)
  , CSMessage (..)
  ) where

import Data.Word
import qualified Nettle.OpenFlow.Port as Port
import Nettle.OpenFlow.Action
import qualified Nettle.OpenFlow.Packet as Packet
import Nettle.OpenFlow.Switch
import Nettle.OpenFlow.Match
import qualified Nettle.OpenFlow.FlowTable as FlowTable
import Nettle.OpenFlow.Statistics
import Nettle.OpenFlow.Error

-- | Every OpenFlow message is tagged with a MessageID value.
type TransactionID = Word32

-- | The Switch can send the following messages to 
-- the controller.
data SCMessage = SCHello               -- ^ Sent after a switch establishes a TCP connection to the controller
               | SCEchoRequest ![Word8] -- ^ Switch requests an echo reply
               | SCEchoReply   ![Word8] -- ^ Switch responds to an echo request
               | Features      !SwitchFeatures -- ^ Switch reports its features
               | PacketIn      !Packet.PacketInfo -- ^ Switch sends a packet to the controller
               | PortStatus    !Port.PortStatus   -- ^ Switch sends port status
               | FlowRemoved   !FlowTable.FlowRemoved -- ^ Switch reports that a flow has been removed
               | StatsReply    !StatsReply -- ^ Switch reports statistics
               | Error         !SwitchError -- ^ Switch reports an error
               | BarrierReply  -- ^ Switch responds that a barrier has been processed
               | QueueConfigReply !QueueConfigReply
      deriving (Show,Eq)

-- |The controller can send these messages to the switch.
data CSMessage 
    = CSHello  -- ^ Controller must send hello before sending any other messages
    | CSEchoRequest   ![Word8] -- ^ Controller requests a switch echo
    | CSEchoReply     ![Word8] -- ^ Controller responds to a switch echo request
    | FeaturesRequest         -- ^ Controller requests features information
    | PacketOut        !Packet.PacketOut -- ^ Controller commands switch to send a packet
    | FlowMod          !FlowTable.FlowMod -- ^ Controller modifies a switch flow table
    | PortMod          !Port.PortMod -- ^ Controller configures a switch port
    | StatsRequest     !StatsRequest -- ^ Controller requests statistics
    | BarrierRequest  -- ^ Controller requests a barrier
    | SetConfig
    | Vendor
    | GetQueueConfig !QueueConfigRequest
      deriving (Show,Eq)


