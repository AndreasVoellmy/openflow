module Nettle.OpenFlow.Get (
    -- * The Get type
      Get
    , runGet
    , runGet2
    , runGetResult      
      
    -- * Utility
    , skip
    , bytesRead
    , remaining
    , isEmpty

    -- * Parsing particular types
    , getWord8

    -- ** Big-endian reads
    , getWord16be
    , getWord32be
    , getWord64be

    -- ** Little-endian reads
    , getWord16le
    , getWord32le
    , getWord64le
) where

import Nettle.OpenFlow.GetInternal