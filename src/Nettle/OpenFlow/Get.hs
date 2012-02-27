{-# LANGUAGE CPP #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE MagicHash #-}
-- for unboxed shifts

-- AV: This source is copied from the following Haskell module from the binary-strict
-- package. Andreas Voellmy made various modifications in 2011-2012. Some of these 
-- changes are experiments and we may not keep them. Some of them may turn out to 
-- be important and we may either fork our Get module or ask that our changes be
-- incorporated into the original package.

-----------------------------------------------------------------------------
-- |
-- Module      : Nettle.OpenFlow.Get
-- Copyright   : Lennart Kolmodin
-- License     : BSD3-style (see LICENSE)
--
-- Maintainer  : Adam Langley <agl@imperialviolet.org>
-- Stability   : experimental
-- Portability : portable to Hugs and GHC.
--
-- This is a strict version of the Get monad from the binary package. It's
-- pretty much just a copy and paste job from the original source code.
-- The binary team are currently unsure about their future plans w.r.t.
-- strictness, so this is a stop gap measure.
--
-- To use, write a function in the Get monad:
--
-- > import Data.Binary.Strict.Get as BinStrict
-- > import Data.ByteString as BS
-- > parse :: BinStrict.Get
-- > parse = getWord16be
-- > main = print $ runGet parse $ BS.pack [1, 1]
--
-- This results in a tuple of (Right 257, \"\") (where the second element is
-- just the remaining data after the parser has run)
-----------------------------------------------------------------------------

#if defined(__GLASGOW_HASKELL__) && !defined(__HADDOCK__)
#include "MachDeps.h"
#endif

#include "Common.h"

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

    -- ** ByteStrings
    , getByteString

    -- ** Big-endian reads
    , getWord16be
    , getWord32be
    , getWord64be

    -- ** Little-endian reads
    , getWord16le
    , getWord32le
    , getWord64le
) where

import Control.Applicative(Alternative(..), Applicative(..))
import Control.Monad (MonadPlus(..), ap)

import Control.Monad (when)
import Data.Maybe (isNothing)

import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B

import Foreign
import Foreign.C.Types

#if defined(__GLASGOW_HASKELL__) && !defined(__HADDOCK__)
import GHC.Base
import GHC.Word
#endif

-- | The parse state
data S = S {-# UNPACK #-} !B.ByteString  -- input
           {-# UNPACK #-} !Int  -- bytes read

newtype Get a = Get (S -> (# a, S #))

instance Functor Get where
    fmap f (Get m) = Get (\s -> case m s of
                             (# a, s' #) -> (# f a, s' #))
    {-# INLINE fmap #-}

instance Monad Get where
  return a = Get (\s -> (# a, s #))
  {-# INLINE return #-}
  (Get m) >>= k = Get (\s -> case m s of
                            (# a, s' #) -> case k a of { Get m' -> m' s' })
  {-# INLINE (>>=) #-}
  (Get m) >> (Get m') = Get (\s -> case m s of (# _, s' #) -> m' s')
  {-# INLINE (>>) #-}
  fail = failDesc

failDesc :: String -> Get a
failDesc err = do
    S _ bytes <- get
    Get (error (err ++ ". Failed reading at byte position " ++ show bytes))

get :: Get S
get = Get (\s -> (# s, s #))
{-# INLINE get #-}

put :: S -> Get ()
put s = Get (\_ -> (# (), s #))
{-# INLINE put #-}

initState :: B.ByteString -> S
initState input = S input 0
{-# INLINE initState #-}

instance Applicative Get where
  pure = return
  (<*>) = ap

-- | Run a parser on the given input and return the result (either an error
--   string from a call to @fail@, or the parsing result) and the remainder of
--   of the input.
runGet :: Get a -> B.ByteString -> (a, B.ByteString)
runGet (Get m) input =
  case m (initState input) of
       (# a, ~(S _ offset) #) -> (a, B.drop offset input)

runGetResult :: Get a -> B.ByteString -> a
runGetResult (Get m) input =
  case m (initState input) of
       (# a, _ #) -> a

runGet2 :: Get a -> B.ByteString -> (# a, B.ByteString #)
runGet2 (Get m) input =
  case m (initState input) of
       (# a, ~(S _ offset) #) -> (# a, B.drop offset input #)


-- | Skip ahead @n@ bytes. Fails if fewer than @n@ bytes are available.
skip :: Int -> Get ()
skip n = 
  do S s offset <- get
     put $! S (B.drop n s) (offset + fromIntegral n)
{-# INLINE skip #-}

-- | Get the total number of bytes read to this point.
bytesRead :: Get Int
bytesRead = do
  S _ b <- get
  return b
{-# INLINE bytesRead #-}
  
-- | Get the number of remaining unparsed bytes.
-- Useful for checking whether all input has been consumed.
remaining :: Get Int
remaining = do
  S s _ <- get
  return (fromIntegral (B.length s))

-- | Test whether all input has been consumed,
-- i.e. there are no remaining unparsed bytes.
isEmpty :: Get Bool
isEmpty = do
  S s _ <- get
  return $ B.null s

------------------------------------------------------------------------
-- Utility with ByteStrings

-- | An efficient 'get' method for strict ByteStrings. Fails if fewer
-- than @n@ bytes are left in the input.
getByteString :: Int -> Get B.ByteString
getByteString n = getBytes n
{-# INLINE getByteString #-}

-- | Pull @n@ bytes from the input, as a strict ByteString.
getBytes :: Int -> Get B.ByteString
getBytes n = 
  do S s offset <- get
     let (consume, rest) = B.splitAt n s
     put $! S rest (offset + fromIntegral n)
     return $! consume
{-# INLINE getBytes #-}

GETWORDS(Get, getBytes)

{-# INLINE getWord64be #-}
{-# INLINE getWord32be #-}
{-# INLINE getWord16be #-}

{-# INLINE getWord8 #-}
getWord8 :: Get Word8
getWord8 = do
  do S s offset <- get
     put $! S (B.tail s) (offset + 1)
     return $! B.head s

shiftl_w16 :: Word16 -> Int -> Word16
shiftl_w32 :: Word32 -> Int -> Word32
shiftl_w64 :: Word64 -> Int -> Word64

#if defined(__GLASGOW_HASKELL__) && !defined(__HADDOCK__)
shiftl_w16 (W16# w) (I# i) = W16# (w `uncheckedShiftL#`   i)
shiftl_w32 (W32# w) (I# i) = W32# (w `uncheckedShiftL#`   i)

#if WORD_SIZE_IN_BITS < 64
shiftl_w64 (W64# w) (I# i) = W64# (w `uncheckedShiftL64#` i)
#else
shiftl_w64 (W64# w) (I# i) = W64# (w `uncheckedShiftL#` i)
#endif

#else
shiftl_w16 = shiftL
shiftl_w32 = shiftL
shiftl_w64 = shiftL
#endif

