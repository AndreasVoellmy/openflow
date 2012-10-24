{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE CPP, ForeignFunctionInterface #-}
{-# LANGUAGE MagicHash #-}

-- | Provides a simple, basic, and efficient server which provides methods
-- to listen for new switches to connect, and to receive and send OpenFlow
-- messages to switches. This server handles the initialization procedure with switches
-- and handles echo requests from switches.
module Nettle.Servers.Server.Internal
    (     
      -- * OpenFlow Server
      OpenFlowServer(..)
      , ServerPortNumber 
      , HostName
      , startOpenFlowServer
      , startOpenFlowServerWithParser        
      , acceptSwitch 
      , handshake
      , closeServer
        -- * Switch connection
      , SwitchHandle(..)
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


import Control.Exception
import Network.Socket hiding (recv, send)
import Network.Socket.ByteString (recv, send, sendAll, sendMany)
import qualified Data.ByteString as S
import System.IO
import Nettle.OpenFlow.Get
import Nettle.OpenFlow
import qualified Nettle.OpenFlow.StrictPut as Strict
import Data.Word
import Foreign
import qualified Data.ByteString.Internal as S
import Data.Map (Map)
import qualified Data.Map as Map
import Text.Printf
import Control.Concurrent
import Data.IORef
import Data.CAS
import Data.Array.IArray hiding ((!))
import qualified Data.Array.IArray as A
import Foreign.C.Types
import Network.Socket.Internal (throwSocketErrorIfMinus1RetryMayBlock)
import GHC.Base
import GHC.Ptr
import GHC.Exts (traceEvent)

data StrictList a = Cons !a (StrictList a) | Nil 
                  deriving (Show,Eq)
                           
mapM_' :: Monad m => (a -> m ()) -> StrictList a -> m ()
mapM_' f Nil = return ()
mapM_' f (Cons a rest) = f a >> mapM_' f rest

type ServerPortNumber = Word16

-- | Abstract type containing the state of the OpenFlow server.
newtype OpenFlowServer a = OpenFlowServer (Socket, IORef (Map SwitchID (SwitchHandle a)), FrameParser a)

defaultParser :: FrameParser EthernetFrame
defaultParser = getEthernetFrame

headerSize :: Int
headerSize = 8        

batchSize :: Int
batchSize = 1024

outBufferSize :: Int
outBufferSize = 8 * 1024 



-- | Starts an OpenFlow server. 
-- The server socket will be bound to a wildcard IP address if the first argument is 'Nothing' and will be bound to a particular 
-- address if the first argument is 'Just' something. The 'HostName' value can either be an IP address in dotted quad notation, 
-- like 10.1.30.127, or a host name, whose IP address will be looked up. The server port must be specified.
startOpenFlowServer :: Maybe HostName -> ServerPortNumber -> IO (OpenFlowServer EthernetFrame)
startOpenFlowServer = startOpenFlowServerWithParser defaultParser

-- | Like 'startOpenFlowServer', but with a specific frame parser.
startOpenFlowServerWithParser :: FrameParser a -> Maybe HostName -> ServerPortNumber -> IO (OpenFlowServer a)
startOpenFlowServerWithParser parser mHostName portNumber = 
  do addrinfos  <- getAddrInfo (Just (defaultHints {addrFlags = [AI_PASSIVE]})) mHostName (Just $ show portNumber)
     let serveraddr = head addrinfos
     sock <- socket (addrFamily serveraddr) Stream defaultProtocol
     setSocketOption sock ReuseAddr 1
     -- setSocketOption sock RecvBuffer 262143
     -- setSocketOption sock SendBuffer 262143     
     bindSocket sock (addrAddress serveraddr)
     listen sock queueLength
     switchHandleMapRef <- newIORef Map.empty
     return (OpenFlowServer (sock, switchHandleMapRef, parser))
    where 
      queueLength = 8192 --2048


-- | Closes the OpenFlow server.
closeServer :: OpenFlowServer a -> IO ()
closeServer (OpenFlowServer (s,_,_)) = 
  do sClose s

-- | Abstract type managing the state of the switch connection.
data SwitchHandle a = SwitchHandle !(SockAddr, Socket, ForeignPtr Word8, Buffer, IORef S.ByteString, SwitchID, Lock, OpenFlowServer a)

-- WARNING: Make sure that whenever we do receive, 
-- the possible bytes unprocessed < buffer size - batch size
type Buffer = (ForeignPtr Word8, Int, IORef Int, IORef Int)
-- head point
-- size
-- freePos
-- readPos

unprocessedByteString :: Buffer -> IO S.ByteString
unprocessedByteString (head, size, freePosRef, readPosRef) = 
  do freePos <- readIORef freePosRef 
     readPos <- readIORef readPosRef 
     return (S.fromForeignPtr head readPos (freePos - readPos))

updateReadPos :: Buffer -> Int -> IO ()
updateReadPos (_, _, _, readPosRef) n = writeIORef readPosRef n


modReadPos :: Buffer -> (Int -> Int) -> IO ()
modReadPos (_, _, _, readPosRef) f = 
  do x <- readIORef readPosRef
     let y = f x
     y `seq` writeIORef readPosRef y


spaceLeft :: Buffer -> IO Int
spaceLeft (head, size, freePosRef, readPosRef) = 
  do freePos <- readIORef freePosRef
     return (size - freePos)

unprocessedLength :: Buffer -> IO Int
unprocessedLength (head, size, freePosRef, readPosRef) = 
  do freePos <- readIORef freePosRef 
     readPos <- readIORef readPosRef 
     return (freePos - readPos)

recvIntoBuffer :: Socket -> Buffer -> Int -> IO Int
recvIntoBuffer socket (head,size,freePosRef, readPosRef) nbytes = 
  do freePos <- readIORef freePosRef  
     withForeignPtr head $ \headPtr ->
       do nbytes' <- recv' socket (headPtr `plusPtr` freePos) nbytes
          let freePos' = freePos + nbytes'
          freePos' `seq` writeIORef freePosRef freePos'
          return nbytes'

recvIntoBuffer' :: Socket -> Buffer -> IO Int
recvIntoBuffer' socket buffer = 
  do space <- spaceLeft buffer
     when (space < batchSize) (copyDown buffer)
     recvIntoBuffer socket buffer batchSize


copyDown :: Buffer -> IO ()
copyDown (head, size, freePosRef, readPosRef) = 
  do readPos <- readIORef readPosRef
     freePos <- readIORef freePosRef
     let freePos' = freePos - readPos
     withForeignPtr head $ \base -> S.memcpy base (base `plusPtr` readPos) (fromIntegral freePos')
     writeIORef readPosRef 0
     freePos' `seq` writeIORef freePosRef freePos'

    
recv' :: Socket         -- ^ Connected socket
        -> Ptr Word8
        -> Int            -- ^ Maximum number of bytes to receive
        -> IO Int
recv' socket ptr nbytes
    | nbytes < 0 = error "recv"
    | otherwise  = recvInner (fdSocket socket) nbytes ptr
        
recvInner :: CInt -> Int -> Ptr Word8 -> IO Int
recvInner s nbytes ptr =
    fmap fromIntegral $
        throwSocketErrorIfMinus1RetryMayBlock "recv"
        (traceEvent ("Read wait socket " ++ show s) >> threadWaitRead (fromIntegral s)) $
        c_recv s (castPtr ptr) (fromIntegral nbytes) 0

foreign import ccall unsafe "recv"
  c_recv :: CInt -> Ptr CChar -> CSize -> CInt -> IO CInt

newBuffer :: Int -> IO Buffer
newBuffer size = 
  do head <- mallocForeignPtrBytes size
     freeRef <- newIORef 0
     readRef <- newIORef 0
     return (head, size, freeRef, readRef)
               
-- | Blocks until a switch connects to the server and returns the 
-- switch handle.
acceptSwitch :: OpenFlowServer a -> IO (SwitchHandle a)
acceptSwitch ofps@(OpenFlowServer (s,shmr,_)) = 
  do (connsock, clientaddr) <- accept s
     let bufferSize = (8 * 1024) - 128 -- 1024 * 1024
     outBufferPtr <- mallocForeignPtrBytes bufferSize :: IO (ForeignPtr Word8)
     inBuffer <- newBuffer bufferSize
     inBufferRef <- newIORef S.empty
     casLock <- newLock
     let sh = SwitchHandle (clientaddr, connsock, outBufferPtr, inBuffer, inBufferRef, -1, casLock, ofps)
     return sh
    
handshake :: Show a => SwitchHandle a -> IO SwitchFeatures
handshake switch@(SwitchHandle (_,_,_,_,_,_,_, OpenFlowServer (_,shmr,_)))
  = do sendToSwitch switch (0, CSHello)
       m <- receiveFromSwitch switch
       case m of 
         Nothing -> error ("switch broke connection")
         Just (xid, msg) -> 
           case msg of 
             SCHello -> go2 switch
             _       -> error ("received unexpected message during handshake: " ++ show (xid, msg))
  where go2 switch = go2'
          where go2' = do sendToSwitch switch (0, FeaturesRequest)
                          m <- receiveFromSwitch switch
                          case m of 
                            Nothing -> error "switch broke connection during handshake"
                            Just (xid, msg) -> 
                              case msg of 
                                Features (sfr@(SwitchFeatures { switchID })) ->
                                  do atomicModifyIORef shmr (\switchHandleMap -> (Map.insert switchID switch switchHandleMap, ()))
                                     return sfr
                                SCEchoRequest bytes -> 
                                  do sendToSwitch switch (xid, CSEchoReply bytes) 
                                     go2'
                                _ -> 
                                  do putStrLn ("ignoring non feature message while waiting for features: " ++ show (xid, msg))
                                     go2'
    
     

-- | Returns the socket address of the switch connection. 
switchSockAddr :: SwitchHandle a -> SockAddr
switchSockAddr (SwitchHandle (a,_,_,_,_,_,_,_)) = a

getBatchAndProcess :: SwitchHandle a -> 
                      ((TransactionID, SCMessage a) -> IO [(TransactionID, CSMessage)]) -> 
                      IO Bool
getBatchAndProcess sh@(SwitchHandle (_, s, _,_,inBufferRef,_,_,_)) f = 
  do newBatchBS <- recv s batchSize
     if S.length newBatchBS == 0
       then return False
       else do inBuffer <- readIORef inBufferRef
               let batchBS = {-# SCC "getBatchAndProcess-append" #-} S.append inBuffer newBatchBS
               remaining <- splitChunks' sh batchBS f
               writeIORef inBufferRef remaining
               return True


processBatchStrictList :: SwitchHandle a -> 
                          ((TransactionID, SCMessage a) -> IO (StrictList (TransactionID, CSMessage))) -> 
                          IO Bool
processBatchStrictList sh@(SwitchHandle (_,s,_,buffer,inBufferRef,_,_,_)) f = 
  do nbytes <- recvIntoBuffer' s buffer
     if nbytes == 0
       then return False
       else do bs <- unprocessedByteString buffer 
               nread <- splitChunks'' sh bs f
               modReadPos buffer (+nread)
               return True


-- Just like getBatchAndProcess' except that it uses splitChunks4.
getBatchAndProcess4 :: SwitchHandle a -> 
                       ((TransactionID, SCMessage a) -> IO (StrictList (TransactionID, CSMessage))) -> 
                       IO Bool
getBatchAndProcess4 sh@(SwitchHandle (_,s,_,_,inBufferRef,_,_,_)) f = 
  do newBatchBS <- recv s batchSize
     if S.length newBatchBS == 0
       then return False
       else do inBuffer <- readIORef inBufferRef
               let batchBS = {-# SCC "getBatchAndProcess-append" #-} S.append inBuffer newBatchBS
               remaining <- splitChunks4 sh batchBS f
               writeIORef inBufferRef remaining
               return True


processBatchIO :: SwitchHandle a -> ((TransactionID, SCMessage a) -> IO ()) -> IO Bool
processBatchIO sh@(SwitchHandle (_, s, _,_,inBufferRef,_,_,_)) f = 
  do newBatchBS <- recv s batchSize
     if S.length newBatchBS == 0
       then return False
       else do inBuffer <- readIORef inBufferRef
               let batchBS = {-# SCC "getBatchAndProcess-append" #-} S.append inBuffer newBatchBS
               remaining <- splitChunks3 sh batchBS f
               writeIORef inBufferRef remaining
               return True


splitChunks' :: SwitchHandle a -> 
                S.ByteString -> 
                ((TransactionID, SCMessage a) -> IO [(TransactionID, CSMessage)]) -> 
                IO S.ByteString
splitChunks' sh@(SwitchHandle(_,s,fptr,_,_,_,_,OpenFlowServer (_,_,parser))) buffer f = 
  go buffer 0
  where 
    go buffer !pos =
      if S.length buffer < headerSize
      then do let bs = S.fromForeignPtr fptr 0 pos
              {-# SCC "splitChunks2-4" #-} sendAll s bs    
              return buffer
      else 
        case  {-# SCC "splitChunks2:runGet1" #-} runGet2 getHeader buffer of
          (# header, buffer' #) ->
            let expectedBodyLen = fromIntegral (msgLength header) - headerSize
            in if expectedBodyLen <= S.length buffer'
               then case {-# SCC "splitChunks2:runGet2" #-} runGet2 (getSCMessageBody parser header) buffer' of
                 (# msg, buffer'' #) -> 
                        case msg of 
                          (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes) 
                                                           go buffer'' pos
                          _ -> do msgs <- {-# SCC "splitChunks2-1" #-} f msg 
                                  bytes <- {-# SCC "splitChunks2-2" #-} 
                                           (withForeignPtr fptr $ \ptr -> 
                                             {-# SCC "splitChunks2-2b" #-} Strict.runPut (ptr `plusPtr` pos) ({-# SCC "splitChunks2-2c" #-} mapM_ putCSMessage msgs)
                                           )
                                  go buffer'' (pos + bytes)
               else do let bs = S.fromForeignPtr fptr 0 pos
                       {-# SCC "splitChunks2-3" #-} sendAll s bs    
                       return buffer

    

splitChunks'' :: SwitchHandle a -> 
                S.ByteString -> 
                ((TransactionID, SCMessage a) -> IO (StrictList (TransactionID, CSMessage))) -> 
                IO Int
splitChunks'' sh@(SwitchHandle(_,s,fptr,_,_,_,_,OpenFlowServer (_,_,parser))) buf f = 
  go buf 0 0
  where 
    go buffer !pos !nread =
      if S.length buffer < headerSize
      then do {-# SCC "splitChunks2-4" #-} sendAll s (S.fromForeignPtr fptr 0 pos)
              return nread
      else 
        case  {-# SCC "splitChunks2:runGet1" #-} runGet2 getHeader buffer of
          (# header, buffer' #) ->
            let msgLen = fromIntegral (msgLength header)
                expectedBodyLen = msgLen - headerSize
            in if expectedBodyLen <= S.length buffer'
               then case {-# SCC "splitChunks2:runGet2" #-} runGet2 (getSCMessageBody parser header) buffer' of
                 (# msg, buffer'' #) -> 
                        case msg of 
                          (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes) 
                                                           go buffer'' pos (nread + msgLen)
                          _ -> do msgs <- {-# SCC "splitChunks2-1" #-} f msg 
                                  bytes <- (withForeignPtr fptr $ \ptr -> 
                                             Strict.runPut (ptr `plusPtr` pos) (mapM_' putCSMessage msgs))
                                  go buffer'' (pos + bytes) (nread + msgLen)
               else do -- printf "body len is %d, buffer has %d\n" expectedBodyLen (S.length buffer')
                       let bs = S.fromForeignPtr fptr 0 pos
                       {-# SCC "splitChunks2-3" #-} sendAll s bs    
                       return nread



-- this one is just like splitChunks'', except that
-- we don't use a buffer. Instead we allocate a new bytestring for 
-- every write. We try to keep the batched send as in splitChunks'', but
-- to do that, we have to collect the byte strings, then reverse them to preserve their order,
-- and then use vectored I/O to send all in a single call.
splitChunks4 :: SwitchHandle a -> 
                S.ByteString -> 
                ((TransactionID, SCMessage a) -> IO (StrictList (TransactionID, CSMessage))) -> 
                IO S.ByteString
splitChunks4 sh@(SwitchHandle(_,s,fptr,_,_,_,_,OpenFlowServer (_,_,parser))) buffer f = 
  go buffer
  where 
    go buffer =
      if S.length buffer < headerSize
      then return buffer
      else 
        case  {-# SCC "splitChunks2:runGet1" #-} runGet2 getHeader buffer of
          (# header, buffer' #) ->
            let expectedBodyLen = fromIntegral (msgLength header) - headerSize
            in if expectedBodyLen <= S.length buffer'
               then case {-# SCC "splitChunks2:runGet2" #-} runGet2 (getSCMessageBody parser header) buffer' of
                 (# msg, buffer'' #) -> 
                        case msg of 
                          (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes) 
                                                           go buffer'' 
                          _ -> do msgs <- {-# SCC "splitChunks2-1" #-} f msg 
                                  let bs = {-# SCC "splitChunks2-2" #-} Strict.runPutToByteString bsSize (mapM_' putCSMessage msgs)
                                  sendAll s bs     
                                  go buffer''
               else do return buffer
      where bsSize      = 1 * 1024 -- can probably make this much, much smaller!


splitChunks3 :: SwitchHandle a -> 
                S.ByteString -> 
                ((TransactionID, SCMessage a) -> IO ()) ->
                IO S.ByteString
splitChunks3 sh@(SwitchHandle(_,s,fptr,_,_,_,_,OpenFlowServer (_,_,parser))) buffer f = 
  go buffer
  where 
    go buffer =
      if S.length buffer < headerSize
      then return buffer
      else 
        case  {-# SCC "splitChunks3:runGet1" #-} runGet2 getHeader buffer of
          (# header, buffer' #) ->
            let expectedBodyLen = fromIntegral (msgLength header) - headerSize
            in if expectedBodyLen <= S.length buffer'
               then case {-# SCC "splitChunks3:runGet2" #-} runGet2 (getSCMessageBody parser header) buffer' of
                 (# msg, buffer'' #) -> 
                        case msg of 
                          (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes) 
                                                           go buffer'' 
                          _ -> do {-# SCC "splitChunks3-1" #-} f msg 
                                  go buffer''
               else return buffer


receiveBatch :: SwitchHandle a -> IO (Maybe [(TransactionID, SCMessage a)])
receiveBatch sh@(SwitchHandle (_, s,_,_,inBufferRef,_,_,_)) = 
  do newBatchBS <- recv s batchSize
     if S.length newBatchBS == 0
       then return Nothing
       else do inBuffer <- readIORef inBufferRef
               let batchBS = S.append inBuffer newBatchBS
               (chunks, remaining) <- splitChunks sh batchBS
               writeIORef inBufferRef remaining
               return (Just chunks)
{-# INLINE receiveBatch #-}

splitChunks :: SwitchHandle a -> 
               S.ByteString -> 
               IO ([(TransactionID, SCMessage a)], S.ByteString)
splitChunks sh@(SwitchHandle (_,_,_,_,_,_,_,OpenFlowServer (_,_,parser))) buffer = go buffer []
  where 
    go buffer chunks =
      if S.length buffer < headerSize
      then return ({-# SCC "splitChunks1" #-} reverse chunks, buffer)
      else 
        let (header, buffer') = {-# SCC "splitChunks2" #-} runGet getHeader buffer
        in 
            let expectedBodyLen = fromIntegral (msgLength header) - headerSize
            in -- putStrLn ("msg len: " ++ show expectedBodyLen) >> 
               if expectedBodyLen <= S.length buffer'
               then let (msg, buffer'') = {-# SCC "splitChunks3" #-} runGet (getSCMessageBody parser header) buffer'
                    in case msg of 
                          (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes) 
                                                           go buffer'' chunks
                          _ -> go buffer'' (msg : chunks)
               else return ({-# SCC "splitChunks4" #-} reverse chunks, buffer)
            
            
-- | Blocks until a message is received from the switch or the connection is closed.
-- Returns `Nothing` only if the connection is closed.
receiveFromSwitch :: SwitchHandle a -> IO (Maybe (TransactionID, SCMessage a))
receiveFromSwitch sh@(SwitchHandle (clientAddr,s,_,_,_,_,_,OpenFlowServer (_,_,parser))) 
  = do hdrbs <- recv s headerSize 
       if (headerSize /= S.length hdrbs) 
         then if S.length hdrbs == 0 
              then return Nothing 
              else error "error reading header"
         else 
           let header = fst (runGet getHeader hdrbs) in
               do let expectedBodyLen = fromIntegral (msgLength header) - headerSize
                  bodybs <- if expectedBodyLen > 0 
                            then do bodybs <- recv s expectedBodyLen 
                                    when (expectedBodyLen /= S.length bodybs) (error "error reading body")
                                    return bodybs
                            else return S.empty
                  let msg = fst (runGet (getSCMessageBody parser header) bodybs ) in 
                      case msg of 
                        (xid, SCEchoRequest bytes) -> do sendToSwitch sh (xid, CSEchoReply bytes)
                                                         receiveFromSwitch sh
                        _ -> return (Just msg)
{-# INLINE receiveFromSwitch #-}

-- | Send a message to the switch.
sendToSwitch :: SwitchHandle a -> (TransactionID, CSMessage) -> IO ()       
sendToSwitch (SwitchHandle (_,s,fptr,_,_,_,casLock,_)) msg =
  do bytes <- withForeignPtr fptr $ \ptr -> Strict.runPut ptr (putCSMessage msg) 
     sendAll s (S.fromForeignPtr fptr 0 bytes)
{-# INLINE sendToSwitch #-}    
     
-- | Send a message to the switch.
sendToSwitch2 :: SwitchHandle a -> (TransactionID, CSMessage) -> IO ()       
sendToSwitch2 (SwitchHandle (_,s,fptr,_,_,_,casLock,_)) msg =
  let !bs = Strict.runPutToByteString 512 (putCSMessage msg)
  in withSpinLock casLock (sendAll s bs)
{-# INLINE sendToSwitch2 #-}    



sendBatch :: SwitchHandle a -> Int -> [(TransactionID, CSMessage)] -> IO ()     
sendBatch (SwitchHandle(_,s,_,_,_,_,_,_)) maxSize batch = 
     sendMany s $ map (\msg -> Strict.runPutToByteString maxSize (putCSMessage msg)) batch
{-# INLINE sendBatch #-}
     

sendBatches :: SwitchHandle a -> Int -> [[(TransactionID, CSMessage)]] -> IO ()     
sendBatches (SwitchHandle(_,s,fptr,_,_,_,_,_)) maxSize batches = 
  do bytes <- withForeignPtr fptr $ \ptr -> Strict.runPut ptr (mapM_ (mapM_ putCSMessage) batches)
     sendAll s (S.fromForeignPtr fptr 0 bytes)
{-# INLINE sendBatches #-}
  
     
sendToSwitchWithID :: OpenFlowServer a -> SwitchID -> (TransactionID, CSMessage) -> IO Bool
sendToSwitchWithID (OpenFlowServer (_,shmr,_)) sid msg 
  = do switchHandleMap <- readIORef shmr 
       case {-# SCC "lookup-switch" #-} Map.lookup sid switchHandleMap of
         Nothing -> do -- hPrintf stderr "Tried to send message to switch: %d, but it is no longer connected.\nMessage was %s.\n" sid (show msg)
                       return False
         Just sh -> do sendToSwitch sh msg
                       return True
{-# INLINE sendToSwitchWithID #-}                                        
     

sendToSwitchWithID2 :: OpenFlowServer a -> SwitchID -> (TransactionID, CSMessage) -> IO ()                                             
sendToSwitchWithID2 (OpenFlowServer (_,shmr,_)) sid msg 
  = do switchHandleMap <- readIORef shmr 
       case Map.lookup sid switchHandleMap of
         Nothing -> printf "Tried to send message to switch: %d, but it is no longer connected.\nMessage was %s.\n" sid (show msg)
         Just sh -> sendToSwitch2 sh msg --this could fail.
{-# INLINE sendToSwitchWithID2 #-}                                        



-- | Close a switch connection.     
closeSwitchHandle :: SwitchHandle a -> IO ()    
closeSwitchHandle (SwitchHandle (_, s,_,_,_,sid,_,OpenFlowServer (_, shmr,_))) = 
  do atomicModifyIORef shmr (\switchHandleMap -> let map' = Map.delete sid switchHandleMap
                                                 in map' `seq` (map', ())
                            )
     sClose s
     -- writeIORef shmr (Map.delete sid switchHandleMap) 

handle2SwitchID :: SwitchHandle a -> SwitchID
handle2SwitchID (SwitchHandle (_,_,_,_,_,sid,_,_)) = sid
{-# INLINE handle2SwitchID #-}    

-- | Repeatedly perform the first action, passing its result to the second action, until
-- the result of the first action is 'Nothing', at which point the computation returns.
untilNothing :: IO (Maybe a) -> (a -> IO ()) -> IO ()
untilNothing sense act = go
  where go = do ma <- sense
                case ma of
                  Nothing -> return ()
                  Just a  -> act a >> go




type Lock = IORef Bool          

newLock :: IO Lock
newLock = newIORef False

readUntilRelease :: Lock -> IO ()
readUntilRelease lock = go 0
  where go :: Int -> IO ()
        go !n = do b <- readIORef lock
                   if b
                     then if (n==maxspins) then (yield >> go 0) else go (n + 1)
                     else return ()
        maxspins = 100
{-# INLINE readUntilRelease #-}        
        
release :: Lock -> IO ()                     
release lock = writeIORef lock False          
{-# INLINE release #-}

spinLock :: Lock -> IO ()
spinLock lock = go
  where go = do readUntilRelease lock
                (_, prev) <- casIORef lock False True 
                if prev
                  then yield >> go
                  else return ()

withSpinLock :: Lock -> IO () -> IO ()
withSpinLock lock action = 
  do spinLock lock
     finally action (release lock)
{-# INLINE withSpinLock #-}
