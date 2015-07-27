module Network.Data.IPv4.DHCP
       (
         DHCPMessage(..)
       , getDHCPMessage
       , dhcpServerPort
       , dhcpClientPort
       )
       where

import Data.Binary.Get
import Network.Data.IPv4.UDP
import Network.Data.IPv4.IPAddress

data DHCPMessage = DHCPDiscover
                 | DHCPMessageOther
                 deriving (Show,Eq)

getDHCPMessage :: IPAddress
                  -> IPAddress
                  -> UDPPortNumber
                  -> UDPPortNumber
                  -> Get DHCPMessage
getDHCPMessage sa da sp dp = do
  opcode <- getWord8
  if opcode == 1 &&
     sa == ipAddress 0 0 0 0 && da == ipAddress 255 255 255 255 &&
     sp == dhcpClientPort && dp == dhcpServerPort
    then return DHCPDiscover
    else return DHCPMessageOther

dhcpServerPort :: UDPPortNumber
dhcpServerPort = 67

dhcpClientPort :: UDPPortNumber
dhcpClientPort = 68

