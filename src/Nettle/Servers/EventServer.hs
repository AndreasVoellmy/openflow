module Nettle.Servers.EventServer (
      -- * OpenFlow Server
      OpenFlowEventManager
      , ServerPortNumber 
      , HostName
      , getEventManager
      , openFlowEventManager
      , closeOpenFlowEventManager
        -- * Switch connection
      , SwitchHandle
      , SwitchID
      , handle2SwitchID
      , switchSockAddr
      , sendToSwitch
        -- * Utility
      , untilNothing
)
where

import Nettle.Servers.Server.Internal -- OpenFlow server implementation
import Nettle.OpenFlow
import Network.Socket (fdSocket)
import GHC.Event
import System.Posix.Types(Fd(..))

type SwitchAcceptCallback a = SwitchHandle a -> IO ()
type SCMessageCallback a = ((TransactionID, SCMessage a), SwitchHandle a) -> IO ()

data OpenFlowEventManager a = OpenFlowEventManager (OpenFlowServer a) EventManager

getEventManager :: OpenFlowEventManager a -> EventManager
getEventManager (OpenFlowEventManager _ mgr) = mgr

-- | Initialize an event manager with an OpenFlow server. Other 
openFlowEventManager :: Maybe HostName -> ServerPortNumber -> SwitchAcceptCallback EthernetFrame -> SCMessageCallback EthernetFrame -> IO (OpenFlowEventManager EthernetFrame)
openFlowEventManager mHostname port switchAcceptCB scMessageCB = 
  do manager <- new
     ofServer@(OpenFlowServer (ofSock, _, _)) <- startOpenFlowServer mHostname port
     let serverFD = Fd $ fdSocket ofSock
         fdAccept = (\key evt -> if evt == evtRead
                                 then do swHandle@(SwitchHandle (_, swSock, _, _, _, _, _, _)) <- acceptSwitch ofServer
                                         let switchFD = Fd $ fdSocket swSock
                                             fdSCMsg = (\key evt -> if evt == evtRead
                                                                    then do maybeSCM <- receiveFromSwitch swHandle
                                                                            let maybeSCMandID = fmap (\x -> (x, swHandle)) maybeSCM
                                                                            maybe (return ()) scMessageCB maybeSCMandID
                                                                    else return ()
                                                       )
                                         registerFd manager fdSCMsg switchFD evtRead
                                         switchAcceptCB swHandle
                                 else return ()
                    )
     void $ registerFd manager fdAccept serverFD evtRead
     return $ OpenFlowEventManager ofServer manager
     
closeOpenFlowEventManager :: OpenFlowEventManager a -> IO ()
closeOpenFlowEventManager (OpenFlowEventManager ofs mgr) = do
  closeServer ofs
  shutdown mgr
     

