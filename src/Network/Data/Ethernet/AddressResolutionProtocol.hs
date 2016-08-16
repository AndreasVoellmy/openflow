{-# LANGUAGE MultiParamTypeClasses, RecordWildCards, TypeOperators #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.Ethernet.AddressResolutionProtocol ( 
  ARPPacket (..)
  , ARPQueryPacket(..)
  , ARPReplyPacket(..)
  , arpOpCode
  , getARPPacket
  , putARPPacket
  ) where

import Network.Data.Ethernet.EthernetAddress
import Network.Data.IPv4.IPAddress
import Data.Word
import qualified Data.Binary.Get as Strict
import qualified Data.Binary.Put as Strict
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

data ARPPacket = ARPQuery ARPQueryPacket
               | ARPReply ARPReplyPacket
               deriving (Show, Eq, Generic, NFData)

data ARPQueryPacket = 
  ARPQueryPacket { querySenderEthernetAddress :: EthernetAddress
                 , querySenderIPAddress       :: IPAddress
                 , queryTargetIPAddress       :: IPAddress
                 } deriving (Show,Eq, Generic, NFData)


data ARPReplyPacket = 
  ARPReplyPacket { replySenderEthernetAddress :: EthernetAddress
                 , replySenderIPAddress       :: IPAddress
                 , replyTargetEthernetAddress :: EthernetAddress
                 , replyTargetIPAddress       :: IPAddress
                 } 
  deriving (Show, Eq, Generic, NFData)

arpOpCode :: ARPPacket -> Word16
arpOpCode (ARPQuery _) = queryOpCode
arpOpCode (ARPReply _) = replyOpCode

queryOpCode, replyOpCode :: Word16
queryOpCode = 1
replyOpCode = 2


-- | Parser for ARP packets
getARPPacket :: Strict.Get (Maybe ARPPacket)
getARPPacket = do 
  _ <- Strict.getWord16be
  _ <- Strict.getWord16be
  _  <- Strict.getWord8
  _  <- Strict.getWord8
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


putARPPacket :: ARPPacket -> Strict.Put
putARPPacket body = 
  case body of 
    (ARPQuery (ARPQueryPacket {..})) -> 
        Strict.putWord16be ethernetHardwareType >>
        Strict.putWord16be ipProtocolType       >>
        Strict.putWord8 numberOctetsInEthernetAddress >>
        Strict.putWord8 numberOctetsInIPAddress       >>
        Strict.putWord16be queryOpCode                >>
        putEthernetAddress querySenderEthernetAddress >>
        putIPAddress querySenderIPAddress             >>
        putEthernetAddress (ethernetAddress 0 0 0 0 0 0) >>
        putIPAddress queryTargetIPAddress
        
    (ARPReply (ARPReplyPacket {..})) -> 
        Strict.putWord16be ethernetHardwareType >>
        Strict.putWord16be ipProtocolType >>
        Strict.putWord8 numberOctetsInEthernetAddress >>
        Strict.putWord8 numberOctetsInIPAddress >>
        Strict.putWord16be replyOpCode >>
        putEthernetAddress replySenderEthernetAddress >>
        putIPAddress replySenderIPAddress >>
        putEthernetAddress replyTargetEthernetAddress >>
        putIPAddress replyTargetIPAddress 

ethernetHardwareType :: Word16
ethernetHardwareType = 1

ipProtocolType :: Word16
ipProtocolType = 0x0800

numberOctetsInEthernetAddress :: Word8
numberOctetsInEthernetAddress = 6

numberOctetsInIPAddress :: Word8
numberOctetsInIPAddress       = 4

