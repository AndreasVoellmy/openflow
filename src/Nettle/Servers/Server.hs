module Nettle.Servers.Server
    (     
      -- * OpenFlow Server
      OpenFlowServer
      , ServerPortNumber 
      , HostName
      , startOpenFlowServer
      , startOpenFlowServerWithParser        
      , acceptSwitch 
      , handshake
      , closeServer
        -- * Switch connection
      , SwitchHandle
      , handle2SwitchID
      , switchSockAddr
      , receiveFromSwitch
      , receiveBatch
      , sendToSwitch        
      , sendBatch
      , sendBatches
      , getBatchAndProcess
      , processBatchStrictList
      , getBatchAndProcess4        
      , processBatchIO
      , StrictList(..)
      , sendToSwitchWithID
      , sendToSwitchWithID2
      , closeSwitchHandle
        -- * Utility
      , untilNothing
    ) where
    
import Nettle.Servers.Server.Internal
