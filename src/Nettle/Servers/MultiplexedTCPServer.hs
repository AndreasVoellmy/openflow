-- | This module provides a TCP server that multiplexes incoming and outgoing messages
-- from many connected peers onto a single pair of input and output channels. The socket address
-- of the peer is used to identify the source and destination of messages.
-- 
-- This interface introduces a new error condition: that a message on the outgoing channel has a 
-- socket address for which no socket exists. This may occur because of incorrect usage of this library, 
-- or because a peer disconnected after the client placed a message on the outgoing channel, 
-- but before that message was sent. Currently, the server does not notify its caller of the occurrence of this error.
module Nettle.Servers.MultiplexedTCPServer 
    (     
      muxedTCPServer, 
      TCPMessage(..), 
      ServerPortNumber
      
    ) where

import Prelude hiding (interact, catch)
import Network.Socket (SockAddr)
import Nettle.OpenFlow.Messages
import Control.Concurrent
import Control.Exception 
import Control.Monad
import qualified Data.Map as Map
import Nettle.Servers.Server

-- | The type of externally visible events that may occur for the multiplexed TCP server.
data TCPMessage a = ConnectionEstablished SockAddr            -- ^ A connection to a peer with the given address is established.
                  | ConnectionTerminated SockAddr             -- ^ A connection with the given address is terminated, due to the given exception.
                  | PeerMessage SockAddr a                    -- ^ A message of type @a@ has been received from the peer with the given address.
                  deriving (Show,Eq)
                           
instance Functor TCPMessage where
  fmap f (ConnectionEstablished a) = ConnectionEstablished a
  fmap f (ConnectionTerminated a)  = ConnectionTerminated a 
  fmap f (PeerMessage a x)         = PeerMessage a (f x)

-- | Runs a server that returns two commands, one to receive the next message from any connected client, 
-- and one that sends a message to a client. 
muxedTCPServer :: ServerPortNumber
                  -> IO (IO (TCPMessage (TransactionID,SCMessage)), 
                         SockAddr -> (TransactionID,CSMessage) -> IO ())
muxedTCPServer pstring = do
  server             <- startOpenFlowServer Nothing pstring
  addressToClientMap <- newMVar Map.empty
  incomingChan       <- newChan  
  let enqIncoming clientHandle =
        do mm <- receiveFromSwitch clientHandle
           case mm of 
             Nothing -> do modifyMVar_ addressToClientMap (return . Map.delete (switchSockAddr clientHandle))
                           writeChan incomingChan (ConnectionTerminated (switchSockAddr clientHandle))
                           return ()
             Just m -> do writeChan incomingChan (PeerMessage (switchSockAddr clientHandle) m) 
                          enqIncoming clientHandle
  let getIncoming = readChan incomingChan
  let postOutgoing sockAddress msg = 
        withMVar addressToClientMap $ \dict -> 
        case Map.lookup sockAddress dict of
          Just switchHandle -> sendToSwitch switchHandle msg
          Nothing -> error ("handle disappeared before message " ++ show msg ++ " was sent.")
  let acceptLoop = 
        forever (do client <- acceptSwitch server
                    _ <- handshake client
                    modifyMVar_ addressToClientMap (return . Map.insert (switchSockAddr client) client)
                    writeChan incomingChan (ConnectionEstablished (switchSockAddr client))
                    forkIO (enqIncoming client)
                )
  
  forkIO acceptLoop                   

  return (getIncoming, postOutgoing)                               
