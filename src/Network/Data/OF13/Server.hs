{-|
Provides functions to establish connections, both passively and actively, with Openflow switches.
-}
module Network.Data.OF13.Server
       ( Switch(..)
       , Factory
       , runServer
       , runServerOne
       , sendMessage
       , talk
       , talk2
       , connectToSwitch
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

-- |Listen (at the specified port) for any number of Openflow switches to connect to this given server. Uses the given
-- factory to instantiate Openflow session handlers for these swithes.
runServer :: Binary a => Int -> Factory a -> IO ()
runServer portNum mkHandler =
  runServer_ portNum $ \(conn, _) ->
  void $
  forkIO $
  bracket
  (mkHandler (Switch conn))
  (\handler -> handler Nothing >> close conn)
  (talk conn)

-- |Listen (at the specified port) for a single Openflow switch to connect to this given server (possibly repeatedly).
-- Uses the given factory to instantiate Openflow session handlers for these swithes.
runServerOne :: Binary a => Int -> Factory a -> IO ()
runServerOne portNum mkHandler =
  runServer_ portNum $ \(conn, _) ->
  void $
  bracket
  (mkHandler (Switch conn))
  (\handler -> handler Nothing >> close conn)
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
       close
       (\sock -> do
           setSocketOption sock ReuseAddr 1
           bind sock $ addrAddress serveraddr
           listen sock 1
           forever $ accept sock >>= f
       )

-- |Establishes an Openflow connection to the given server and port, using the specified handler on the connection.
connectToSwitch :: Binary a => String -> String -> (Switch -> Maybe a -> IO ()) -> IO ()
connectToSwitch hostNameOrIp port handler = do
  addrinfos <- getAddrInfo Nothing (Just hostNameOrIp) (Just port)
  let serveraddr = head addrinfos
  sock <- socket (addrFamily serveraddr) Stream defaultProtocol
  connect sock (addrAddress serveraddr)
  talk sock $ handler $ Switch sock

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
