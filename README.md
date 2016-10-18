# OpenFlow [![Build Status](https://travis-ci.org/AndreasVoellmy/openflow.svg)](https://travis-ci.org/AndreasVoellmy/openflow)

OpenFlow is a Haskell library that implements OpenFlow protocols 1.0 and 1.3. It defines data types that model the logical content of the various OpenFlow protocol messages and provides serialization and deserialization methods using the [binary package](http://hackage.haskell.org/package/binary). It also provides basic functions to start servers that use these representations. 

# Getting Started

To write an OpenFlow 1.3 controller, start with the following template, and then fill in the `messageHandler` function:
```haskell
import Network.Data.OF13.Message
import Network.Data.OF13.Server

main :: IO ()
main = runServerOne 6633 factory
  where factory sw = handshake sw >> return (messageHandler sw)

handshake :: Switch -> IO ()
handshake sw = sendMessage sw [Hello { xid = 0, len = 8 }]

messageHandler :: Switch -> Maybe Message -> IO ()
messageHandler _ Nothing = putStrLn "Disconnecting"
messageHandler sw (Just msg) = print msg >> sendMessage sw [FeatureRequest 1]
```

The above `main` program calls `runServerOne` which will wait for a single OpenFlow 1.3 server to connect on port 6633 and then will run the given `factory` function. The `factory` function performs an initial `handshake`, which, in this bare bones example, consists of sending a `Hello` message to the switch, and then returns a message handler function `messageHandler` that will be used to interact with that switch until the connection is terminated. When the server receives an OpenFlow 1.3 message `m`, it will run `messageHandler (Just m)` and when the connection is terminated, the server runs `messageHandler Nothing`. The message handler can do anything, but typically it sends messages to the switch. To do this, use the `sendMessage` function.

# Contributors

* Andreas Voellmy
* Ashish Agarwal
* John Launchbury
