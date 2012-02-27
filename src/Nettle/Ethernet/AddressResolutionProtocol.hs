{-# LANGUAGE MultiParamTypeClasses, RecordWildCards, TypeOperators #-}

module Nettle.Ethernet.AddressResolutionProtocol ( 
  ARPPacket (..)
  , ARPQueryPacket(..)
  , ARPReplyPacket(..)
  , getARPPacket
  , getARPPacket2
  , putARPPacket
  ) where

import Nettle.Ethernet.EthernetAddress
import Nettle.IPv4.IPAddress
import Data.Binary
import Data.Binary.Put
import Data.Word
import Control.Monad
import Control.Monad.Error
import Data.HList
import qualified Nettle.OpenFlow.Get as Strict
import qualified Nettle.OpenFlow.StrictPut as Strict
import qualified Data.Binary.Get as Binary

data ARPPacket = ARPQuery ARPQueryPacket
               | ARPReply ARPReplyPacket
               deriving (Show, Eq)

data ARPQueryPacket = 
  ARPQueryPacket { querySenderEthernetAddress :: EthernetAddress
                 , querySenderIPAddress       :: IPAddress
                 , queryTargetIPAddress       :: IPAddress
                 } deriving (Show,Eq)


data ARPReplyPacket = 
  ARPReplyPacket { replySenderEthernetAddress :: EthernetAddress
                 , replySenderIPAddress       :: IPAddress
                 , replyTargetEthernetAddress :: EthernetAddress
                 , replyTargetIPAddress       :: IPAddress
                 } 
  deriving (Show, Eq)

queryOpCode, replyOpCode :: Word16
queryOpCode = 1
replyOpCode = 2


-- | Parser for ARP packets
getARPPacket :: Strict.Get (Maybe ARPPacket)
getARPPacket = do 
  htype <- Strict.getWord16be
  ptype <- Strict.getWord16be
  hlen  <- Strict.getWord8
  plen  <- Strict.getWord8
  opCode <- Strict.getWord16be
  sha <- getEthernetAddress
  spa <- getIPAddress
  tha <- getEthernetAddress
  tpa <- getIPAddress
  body <- if opCode == queryOpCode
          then return ( Just (ARPQuery (ARPQueryPacket { querySenderEthernetAddress = sha
                                                       , querySenderIPAddress       = spa
                                                       , queryTargetIPAddress       = tpa
                                                       } 
                                       )
                             )
                      )
          else if opCode == replyOpCode 
               then return (Just (ARPReply (ARPReplyPacket { replySenderEthernetAddress = sha
                                                           , replySenderIPAddress       = spa
                                                           , replyTargetEthernetAddress = tha
                                                           , replyTargetIPAddress       = tpa
                                                           } 
                                           )
                                 )
                           )
               else return Nothing
  return body

-- | Parser for ARP packets
getARPPacket2 :: Binary.Get (Maybe ARPPacket)
getARPPacket2 = do 
  htype <- Binary.getWord16be
  ptype <- Binary.getWord16be
  hlen  <- Binary.getWord8
  plen  <- Binary.getWord8
  opCode <- Binary.getWord16be
  sha <- getEthernetAddress2
  spa <- getIPAddress2
  tha <- getEthernetAddress2
  tpa <- getIPAddress2
  body <- if opCode == queryOpCode
          then return ( Just (ARPQuery (ARPQueryPacket { querySenderEthernetAddress = sha
                                                       , querySenderIPAddress       = spa
                                                       , queryTargetIPAddress       = tpa
                                                       } 
                                       )
                             )
                      )
          else if opCode == replyOpCode 
               then return (Just (ARPReply (ARPReplyPacket { replySenderEthernetAddress = sha
                                                           , replySenderIPAddress       = spa
                                                           , replyTargetEthernetAddress = tha
                                                           , replyTargetIPAddress       = tpa
                                                           } 
                                           )
                                 )
                           )
               else return Nothing
  return body


putARPPacket :: ARPPacket -> Strict.Put
putARPPacket body = 
  case body of 
    (ARPQuery (ARPQueryPacket {..})) -> 
      do 
        Strict.putWord16be ethernetHardwareType
        Strict.putWord16be ipProtocolType
        Strict.putWord8 numberOctetsInEthernetAddress
        Strict.putWord8 numberOctetsInIPAddress
        Strict.putWord16be queryOpCode
        putEthernetAddress querySenderEthernetAddress
        putIPAddress querySenderIPAddress
        putEthernetAddress (ethernetAddress 0 0 0 0 0 0)
        putIPAddress queryTargetIPAddress
        
    (ARPReply (ARPReplyPacket {..})) -> 
      do 
        Strict.putWord16be ethernetHardwareType
        Strict.putWord16be ipProtocolType
        Strict.putWord8 numberOctetsInEthernetAddress
        Strict.putWord8 numberOctetsInIPAddress
        Strict.putWord16be replyOpCode
        putEthernetAddress replySenderEthernetAddress
        putIPAddress replySenderIPAddress
        putEthernetAddress replyTargetEthernetAddress
        putIPAddress replyTargetIPAddress

ethernetHardwareType          = 1
ipProtocolType                = 0x0800
numberOctetsInEthernetAddress = 6
numberOctetsInIPAddress       = 4

