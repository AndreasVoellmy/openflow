{-# LANGUAGE CPP, DisambiguateRecordFields #-}
{-# LANGUAGE BangPatterns #-}

-- | A switch has some number of flow tables. Each flow table is a 
-- prioritized list of entries containing a @Match@, a list of 
-- @Action@s, and other options affecting the behavior of the switch.
-- This module represents the OpenFlow messages that can be used
-- to modify flow tables.
module Nettle.OpenFlow.FlowTable ( 
  FlowTableID
  , FlowMod (..)
  , Cookie
  , Priority
  , TimeOut (..)
  , FlowRemoved (..)
  , FlowRemovalReason (..)
  ) where

import Nettle.OpenFlow.Switch
import Nettle.OpenFlow.Action
import Nettle.OpenFlow.Match
import Nettle.OpenFlow.Packet
import Data.Word
import Data.List as List

type FlowTableID = Word8

data FlowMod = AddFlow { match             :: !Match     
                       , priority          :: !Priority  
                       , actions           :: !ActionSequence
                       , cookie            :: !Cookie
                       , idleTimeOut       :: !TimeOut 
                       , hardTimeOut       :: !TimeOut 
                       , notifyWhenRemoved :: !Bool
                       , applyToPacket     :: !(Maybe BufferID)
                       , overlapAllowed    :: !Bool
                       } 
             | AddEmergencyFlow { match          :: !Match
                                , priority       :: !Priority
                                , actions        :: !ActionSequence
                                , cookie         :: !Cookie                                       
                                , overlapAllowed :: !Bool
                                }
                                        
             | ModifyFlows { match                      :: !Match
                           , newActions                 :: !ActionSequence
                           , ifMissingPriority          :: !Priority 
                           , ifMissingCookie            :: !Cookie                                
                           , ifMissingIdleTimeOut       :: !TimeOut 
                           , ifMissingHardTimeOut       :: !TimeOut
                           , ifMissingNotifyWhenRemoved :: !Bool 
                           , ifMissingOverlapAllowed    :: !Bool
                           }
             | ModifyExactFlow { match                      :: !Match 
                               , priority                   :: !Priority
                               , newActions                 :: !ActionSequence
                               , ifMissingCookie            :: !Cookie                                       
                               , ifMissingIdleTimeOut       :: !TimeOut
                               , ifMissingHardTimeOut       :: !TimeOut
                               , ifMissingNotifyWhenRemoved :: !Bool 
                               , ifMissingOverlapAllowed    :: !Bool                                      
                               }
             | DeleteFlows { match   :: !Match, 
                             outPort :: !(Maybe PseudoPort)
                           } 
             | DeleteExactFlow { match    :: !Match, 
                                 outPort  :: !(Maybe PseudoPort), 
                                 priority :: !Priority
                               } 
                     deriving (Show, Eq)

type Cookie = Word64

-- |The priority of a flow entry is a 16-bit integer. Flow entries with higher numeric priorities match before lower ones.
type Priority = Word16

-- | Each flow entry has idle and hard timeout values
-- associated with it.
data TimeOut  = Permanent 
              | ExpireAfter !Word16
                deriving (Show,Eq)


-- | When a switch removes a flow, it may send a message containing the information
-- in @FlowRemovedRecord@ to the controller.
data FlowRemoved = FlowRemovedRecord { flowRemovedMatch         :: !Match, 
                                       flowRemovedCookie        :: !Word64,
                                       flowRemovedPriority      :: !Priority, 
                                       flowRemovedReason        :: !FlowRemovalReason,
                                       flowRemovedDuration      :: !Integer,
                                       flowRemovedDurationNSecs :: !Integer,
                                       flowRemovedIdleTimeout   :: !Integer, 
                                       flowRemovedPacketCount   :: !Integer, 
                                       flowRemovedByteCount     :: !Integer }
                 deriving (Show,Eq)

data FlowRemovalReason = IdleTimerExpired
                       | HardTimerExpired 
                       | DeletedByController
                         deriving (Show,Eq,Ord,Enum)
