module Nettle.TestUtil where

import Test.QuickCheck 
import Data.Word
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put

instance Arbitrary Word8 where
    arbitrary = arbitraryBoundedIntegral 
    shrink    = shrinkIntegral 

instance Arbitrary Word16 where
    arbitrary = arbitraryBoundedIntegral 
    shrink    = shrinkIntegral 

instance Arbitrary Word32 where
    arbitrary = arbitraryBoundedIntegral 
    shrink    = shrinkIntegral

instance Arbitrary Word64 where
    arbitrary = arbitraryBoundedIntegral
    shrink = shrinkIntegral
 

prop_encodeThenDecode :: (Eq a, Binary a) => a -> Bool
prop_encodeThenDecode a = decode (encode a) == a

genBoundedWord32 :: Int -> Gen Word32
genBoundedWord32 0     = return 0
genBoundedWord32 (n+1) = do ds <- sequence [ elements [0,1] >>= (\c -> return (c * 2^m)) | m <- [0..n] ]
                            return (sum ds)

