import Nettle.Servers.Server
import Nettle.OpenFlow
import Control.Concurrent
import System.Environment

main :: IO ()
main =
  do portNum <- getPortNumber
     ofpServer <- startOpenFlowServer Nothing portNum
     forever (do switch <- acceptSwitch ofpServer
                 forkIO (do features <- handshake switch 
                            handleSwitch switch
                        )
             )
     closeServer ofpServer
       
       
getPortNumber :: IO ServerPortNumber       
getPortNumber 
  = do args <- getArgs
       if length args < 1 
         then error "Requires one command-line argument specifying the server port number."
         else return (read (args !! 0))


handleSwitch :: SwitchHandle EthernetFrame -> IO ()
handleSwitch switch 
  = do untilNothing (receiveFromSwitch switch) (messageHandler switch)
       closeSwitchHandle switch


messageHandler :: SwitchHandle EthernetFrame -> (TransactionID, SCMessage EthernetFrame) -> IO ()
messageHandler switch (xid, scmsg) =
  case scmsg of
    PacketIn pktIn      -> sendToSwitch switch (xid, PacketOut (receivedPacketOut pktIn flood))
    _                   -> return ()

