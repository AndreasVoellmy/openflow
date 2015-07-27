module Network.Data.OF13.Server
       ( Switch
       , Factory
       , runServer
       , runServerOne
       , sendMessage
       , talk
       , talk2
       ) where

import Control.Concurrent
import Control.Exception
import Control.Monad
import Data.Binary
import Data.Binary.Get
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as S
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

type Factory a = Switch -> IO (Maybe a -> IO ())
newtype Switch = Switch Socket

runServer :: Binary a => Int -> Factory a -> IO ()
runServer portNum mkHandler =
  runServer_ portNum $ \(conn, _) ->
  void $
  forkIO $
  bracket
  (mkHandler (Switch conn))
  (\handler -> handler Nothing >> sClose conn)
  (talk conn)

runServerOne :: Binary a => Int -> Factory a -> IO ()
runServerOne portNum mkHandler =
  runServer_ portNum $ \(conn, _) ->
  void $
  bracket
  (mkHandler (Switch conn))
  (\handler -> handler Nothing >> sClose conn)
  (talk conn)

runServer_ :: Int -> ((Socket, SockAddr) -> IO ()) -> IO ()
runServer_ portNum f = withSocketsDo $
  do addrinfos <- getAddrInfo
                  (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
                  Nothing 
                  (Just $ show portNum)
     let serveraddr = head addrinfos
     bracket
       (socket (addrFamily serveraddr) Stream defaultProtocol)
       sClose
       (\sock -> do
           setSocketOption sock ReuseAddr 1
           bindSocket sock $ addrAddress serveraddr
           listen sock 1
           forever $ accept sock >>= f
       )

talk :: Binary a => Socket -> (Maybe a -> IO ()) -> IO ()
talk = talk2 get

talk2 :: Get a -> Socket -> (Maybe a -> IO ()) -> IO ()
talk2 getter conn handler = go $ runGetIncremental getter
  where 
    go (Fail _ _ err) = error err
    go (Partial f) = do
      msg <- recv conn bATCH_SIZE
      if S.null msg
        then return ()
        else go $ f $ Just msg
    go (Done unused _ ofm) = do
      handler $ Just ofm
      go $ pushChunk (runGetIncremental getter) unused

bATCH_SIZE :: Int
bATCH_SIZE = 1024
                
sendMessage :: Binary a => Switch -> [a] -> IO ()
sendMessage (Switch s) = mapM_ (sendMessage' s)

sendMessage' :: Binary a => Socket -> a -> IO ()
sendMessage' sock = mapM_ (sendAll sock) . L.toChunks . encode
