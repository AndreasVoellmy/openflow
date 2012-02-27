{-# LANGUAGE BangPatterns #-}

-- | This module provides methods to connect to an OpenFlow control server, 
-- and send and receive messages to the server.
module Nettle.Servers.Client
    (     
      ClientHandle      
      , connectToController
      , connectToHandles
      , closeClient
      , receiveControlMessage
      , sendMessage
      , flushClient
    ) where

import Network 
import System.IO
import qualified Data.ByteString as S
import Nettle.OpenFlow hiding (PortID)
import Nettle.OpenFlow.Get
import qualified Nettle.OpenFlow.StrictPut as Strict
import Data.Word
import Foreign

-- | Abstract type representing the state of the connection to the control server.
newtype ClientHandle = ClientHandle (Handle, Handle, ForeignPtr Word8)

-- | Established a connection to the control server with the given 'Network.HostName' 
-- and 'Network.PortID' and returns its 'ClientHandle'.
connectToController :: HostName -> PortID -> IO ClientHandle
connectToController host port = 
  do h <- connectTo host port
     hSetBuffering h (BlockBuffering (Just (4 * 1024)))
     connectToHandles h h

-- | Creates a 'ClientHandle' based on a handle to read from and one to write to.
connectToHandles :: Handle -> Handle -> IO ClientHandle
connectToHandles h h' = 
  do let bufferSize = 32 * 1024
     outBufferPtr <- mallocForeignPtrBytes bufferSize :: IO (ForeignPtr Word8)
     return (ClientHandle (h,h',outBufferPtr))

-- | Close client, closing read and write handles.
closeClient :: ClientHandle -> IO ()
closeClient (ClientHandle (h,h',_)) = hClose h >> hClose h'

-- | Blocks until a new control message arrives or the connection is terminated, in which 
-- the return value is 'Nothing'.
receiveControlMessage :: ClientHandle -> IO (Maybe (TransactionID, CSMessage))
receiveControlMessage (ClientHandle (h,_,_)) 
  = do eof <- hIsEOF h
       if eof 
         then return Nothing
         else do hdrbs <- S.hGet h headerSize
                 when (headerSize /= S.length hdrbs) (error "error reading header")
                 let header = fst (runGet getHeader hdrbs) 
                 let expectedBodyLen = fromIntegral (msgLength header) - S.length hdrbs
                 bodybs <- S.hGet h expectedBodyLen
                 when (expectedBodyLen /= S.length bodybs) (error "error reading body")
                 let msg = fst (runGet (getCSMessageBody header) bodybs) 
                 return (Just msg)
  where headerSize = 8        
{-# INLINE receiveControlMessage #-}
        
-- | Sends a message to the controller.        
sendMessage :: ClientHandle -> (TransactionID, SCMessage) -> IO ()
sendMessage (ClientHandle (_,h,fptr)) msg =
  withForeignPtr fptr $ \ptr -> 
  do bytes <- Strict.runPut ptr (putSCMessage msg)
     hPutBuf h ptr bytes
{-# INLINE sendMessage #-}    
     
flushClient :: ClientHandle -> IO ()     
flushClient (ClientHandle (_,h,_)) = hFlush h


