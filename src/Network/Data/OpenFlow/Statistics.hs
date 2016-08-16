{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OpenFlow.Statistics (
  StatsRequest (..)
  , TableQuery (..)
  , PortQuery (..) 
  , QueueQuery (..)
  , StatsReply (..) 
  , MoreToFollowFlag
  , FlowStats (..) 
  , AggregateFlowStats (..) 
  , TableStats (..)
  , PortStats (..) 
  , nullPortStats
  , zeroPortStats
  , liftIntoPortStats1
  , liftIntoPortStats2
  , Description (..)
  , QueueStats (..)
  ) where

import Network.Data.OpenFlow.Port
import Network.Data.OpenFlow.Match
import Network.Data.OpenFlow.Action
import Network.Data.OpenFlow.FlowTable
import Control.Monad (liftM,liftM2)
import Data.Aeson.TH
import Data.Int
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

data StatsRequest
    = FlowStatsRequest {
        statsRequestMatch   :: Match,           -- ^fields to match
        statsRequestTableID :: TableQuery,      -- ^ID of table to read
        statsRequestPort    :: Maybe PseudoPort -- ^if present, require matching entries to include this as an output port
      }
    | AggregateFlowStatsRequest { 
        statsRequestMatch   :: Match,           -- ^fields to match
        statsRequestTableID :: TableQuery,      -- ^ID of table to read
        statsRequestPort    :: Maybe PseudoPort -- ^if present, require matching entries to include this as an output port
      }
    | TableStatsRequest
    | DescriptionRequest
    | PortStatsRequest {
        portStatsQuery :: PortQuery
      }
    | QueueStatsRequest { queueStatsPort :: PortQuery, queueStatsQuery:: QueueQuery }
    deriving (Show,Eq,Generic,NFData)    

data PortQuery = AllPorts | SinglePort PortID deriving (Show,Eq,Ord,Generic,NFData)
data QueueQuery = AllQueues | SingleQueue QueueID deriving (Show,Eq,Ord,Generic,NFData)

data TableQuery = AllTables 
                | EmergencyTable
                | Table FlowTableID 
                  deriving (Show,Eq,Generic,NFData)



data StatsReply
    = DescriptionReply Description
    | FlowStatsReply !MoreToFollowFlag [FlowStats]
    | AggregateFlowStatsReply AggregateFlowStats
    | TableStatsReply !MoreToFollowFlag [TableStats]
    | PortStatsReply !MoreToFollowFlag [(PortID,PortStats)]
    | QueueStatsReply !MoreToFollowFlag [QueueStats]
      deriving (Show,Eq,Generic,NFData)

type MoreToFollowFlag = Bool

data Description = Description { manufacturerDesc :: String
                                 , hardwareDesc     :: String
                                 , softwareDesc     :: String
                                 , serialNumber     :: String 
                                 , datapathDesc     :: String 
                                 } deriving (Show,Eq,Generic,NFData)

data AggregateFlowStats = 
  AggregateFlowStats { aggregateFlowStatsPacketCount :: Integer, 
                       aggregateFlowStatsByteCount   :: Integer, 
                       aggregateFlowStatsFlowCount   :: Integer
                     } deriving (Show, Eq,Generic,NFData)
                       

data FlowStats = FlowStats {
      flowStatsTableID             :: !FlowTableID, -- ^ Table ID of the flow
      flowStatsMatch               :: Match,       -- ^ Match condition of the flow
      flowStatsActions             :: [Action],    -- ^ Actions for the flow
      flowStatsPriority            :: !Priority,    -- ^ Priority of the flow entry (meaningful when the match is not exact).
      flowStatsCookie              :: !Cookie,      -- ^ Cookie associated with the flow.
      flowStatsDurationSeconds     :: !Int,     
      flowStatsDurationNanoseconds :: !Int,
      flowStatsIdleTimeout         :: !Int,
      flowStatsHardTimeout         :: !Int,
      flowStatsPacketCount         :: !Int64,
      flowStatsByteCount           :: !Int64
    }
    deriving (Show,Eq,Generic,NFData)

data TableStats = 
  TableStats { 
    tableStatsTableID      :: FlowTableID, 
    tableStatsTableName    :: String,
    tableStatsMaxEntries   :: Integer, 
    tableStatsActiveCount  :: Integer, 
    tableStatsLookupCount  :: Integer, 
    tableStatsMatchedCount :: Integer } deriving (Show,Eq,Generic,NFData)

data PortStats 
    = PortStats { 
        portStatsReceivedPackets      :: Maybe Double, 
        portStatsSentPackets          :: Maybe Double, 
        portStatsReceivedBytes        :: Maybe Double, 
        portStatsSentBytes            :: Maybe Double, 
        portStatsReceiverDropped      :: Maybe Double, 
        portStatsSenderDropped        :: Maybe Double, 
        portStatsReceiveErrors        :: Maybe Double, 
        portStatsTransmitError        :: Maybe Double, 
        portStatsReceivedFrameErrors  :: Maybe Double, 
        portStatsReceiverOverrunError :: Maybe Double, 
        portStatsReceiverCRCError     :: Maybe Double, 
        portStatsCollisions           :: Maybe Double
      } deriving (Show,Eq,Generic,NFData)

-- | A port stats value with all fields missing.
nullPortStats :: PortStats
nullPortStats = PortStats { 
  portStatsReceivedPackets      = Nothing,
  portStatsSentPackets          = Nothing,
  portStatsReceivedBytes        = Nothing,
  portStatsSentBytes            = Nothing,
  portStatsReceiverDropped      = Nothing,
  portStatsSenderDropped        = Nothing,
  portStatsReceiveErrors        = Nothing,
  portStatsTransmitError        = Nothing,
  portStatsReceivedFrameErrors  = Nothing,
  portStatsReceiverOverrunError = Nothing,
  portStatsReceiverCRCError     = Nothing,
  portStatsCollisions           = Nothing
  }

-- | A port stats value with all fields present, but set to 0.
zeroPortStats :: PortStats
zeroPortStats = 
    PortStats { 
      portStatsReceivedPackets      = Just 0, 
      portStatsSentPackets          = Just 0, 
      portStatsReceivedBytes        = Just 0, 
      portStatsSentBytes            = Just 0, 
      portStatsReceiverDropped      = Just 0, 
      portStatsSenderDropped        = Just 0, 
      portStatsReceiveErrors        = Just 0, 
      portStatsTransmitError        = Just 0, 
      portStatsReceivedFrameErrors  = Just 0, 
      portStatsReceiverOverrunError = Just 0, 
      portStatsReceiverCRCError     = Just 0, 
      portStatsCollisions           = Just 0
      }
    
-- | Lift a unary function and apply to every member of a PortStats record.    
liftIntoPortStats1 :: (Double -> Double) -> PortStats -> PortStats
liftIntoPortStats1 f pr1 = 
  PortStats { portStatsReceivedPackets      = liftM f (portStatsReceivedPackets pr1),
              portStatsSentPackets          = liftM f (portStatsSentPackets pr1),
              portStatsReceivedBytes        = liftM f (portStatsReceivedBytes pr1),
              portStatsSentBytes            = liftM f (portStatsSentBytes pr1),
              portStatsReceiverDropped      = liftM f (portStatsReceiverDropped pr1),
              portStatsSenderDropped        = liftM f (portStatsSenderDropped pr1),
              portStatsReceiveErrors        = liftM f (portStatsReceiveErrors pr1),
              portStatsTransmitError        = liftM f (portStatsTransmitError pr1),
              portStatsReceivedFrameErrors  = liftM f (portStatsReceivedFrameErrors pr1),
              portStatsReceiverOverrunError = liftM f (portStatsReceiverOverrunError pr1),
              portStatsReceiverCRCError     = liftM f (portStatsReceiverCRCError pr1),
              portStatsCollisions           = liftM f (portStatsCollisions pr1)
            }

-- | Lift a binary function and apply to every member of a PortStats record.    
liftIntoPortStats2 :: (Double -> Double -> Double) -> PortStats -> PortStats -> PortStats
liftIntoPortStats2 f pr1 pr2 = 
    PortStats { portStatsReceivedPackets      = liftM2 f (portStatsReceivedPackets pr1) (portStatsReceivedPackets pr2),
                portStatsSentPackets          = liftM2 f (portStatsSentPackets pr1) (portStatsSentPackets pr2),
                portStatsReceivedBytes        = liftM2 f (portStatsReceivedBytes pr1) (portStatsReceivedBytes pr2),
                portStatsSentBytes            = liftM2 f (portStatsSentBytes pr1) (portStatsSentBytes pr2),
                portStatsReceiverDropped      = liftM2 f (portStatsReceiverDropped pr1) (portStatsReceiverDropped pr2),
                portStatsSenderDropped        = liftM2 f (portStatsSenderDropped pr1) (portStatsSenderDropped pr2),
                portStatsReceiveErrors        = liftM2 f (portStatsReceiveErrors pr1) (portStatsReceiveErrors pr2),
                portStatsTransmitError        = liftM2 f (portStatsTransmitError pr1) (portStatsTransmitError pr2),
                portStatsReceivedFrameErrors  = liftM2 f (portStatsReceivedFrameErrors pr1) (portStatsReceivedFrameErrors pr2),
                portStatsReceiverOverrunError = liftM2 f (portStatsReceiverOverrunError pr1) (portStatsReceiverOverrunError pr2),
                portStatsReceiverCRCError     = liftM2 f (portStatsReceiverCRCError pr1) (portStatsReceiverCRCError pr2),
                portStatsCollisions           = liftM2 f (portStatsCollisions pr1) (portStatsCollisions pr2)
              }
    




data QueueStats = QueueStats { queueStatsPortID             :: PortID, 
                               queueStatsQueueID            :: QueueID, 
                               queueStatsTransmittedBytes   :: Integer, 
                               queueStatsTransmittedPackets :: Integer, 
                               queueStatsTransmittedErrors  :: Integer } deriving (Show,Eq,Generic,NFData)

$(deriveJSON defaultOptions ''PortStats)

