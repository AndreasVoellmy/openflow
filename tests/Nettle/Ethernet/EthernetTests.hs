module Nettle.Ethernet.EthernetTests where

import Test.QuickCheck 
import Nettle.TestUtil
import Nettle.Ethernet.EthernetAddress
import Nettle.Ethernet.EthernetFrame
import qualified Data.ByteString.Lazy as B
import Data.List as List
import Data.Word

props = [ prop_EthHeaderPutGet ]

prop_EthHeaderPutGet :: Property
prop_EthHeaderPutGet = forAll 
                       (arbitrary :: Gen EthernetHeader)
                       prop_encodeThenDecode

instance Arbitrary EthernetFrame where
    arbitrary = do 
      eh <- arbitrary
      body <- arbitrary 
      return $ EthernetFrame eh body
    shrink (EthernetFrame hdr body) = [ EthernetFrame hdr' body' | hdr' <- shrink hdr , body' <- shrink body]

instance Arbitrary EthernetBody where
    arbitrary = do 
      bs <- listOf arbitrary 
      return $ UninterpretedEthernetBody $ B.pack bs
    shrink (UninterpretedEthernetBody bs) = [ UninterpretedEthernetBody (B.pack bs') | bs' <- shrink (B.unpack bs) ]
    shrink _ = []



instance Arbitrary EthernetHeader where
    arbitrary = oneof [genEthernetHeaderNormal, genEthernetHeader8021Q]
    shrink (EthernetHeader da sa tc) = 
        [ EthernetHeader da' sa' tc' | da' <- shrink da, 
                                       sa' <- shrink sa, 
                                       tc' <- shrink tc  ]
    shrink (Ethernet8021Q _ _ _ _ _ _) = []

genEthernetHeaderNormal :: Gen EthernetHeader
genEthernetHeaderNormal = 
    do da <- arbitrary 
       sa <- arbitrary
       tc <- arbitraryBoundedIntegral `suchThat` (\tc -> tc /= ethTypeVLAN && tc >= ofpDlTypeEth2Cutoff)
       return (EthernetHeader da sa tc)

genEthernetHeader8021Q :: Gen EthernetHeader
genEthernetHeader8021Q = 
    do da <- arbitrary 
       sa <- arbitrary
       tc <- arbitraryBoundedIntegral
       pcp <- elements [0..7]
       caf <- arbitrary
       vlanid <- elements [0..(2^12 - 1)]
       return (Ethernet8021Q da sa tc pcp caf vlanid)


instance Arbitrary EthernetAddress where
    arbitrary = do 
      a1 <- arbitraryBoundedIntegral
      a2 <- arbitraryBoundedIntegral
      a3 <- arbitraryBoundedIntegral
      a4 <- arbitraryBoundedIntegral
      a5 <- arbitraryBoundedIntegral
      a6 <- arbitraryBoundedIntegral
      return (EthernetAddress a1 a2 a3 a4 a5 a6)

    shrink (EthernetAddress a1 a2 a3 a4 a5 a6) = 
        [ EthernetAddress a1' a2' a3' a4' a5' a6' | a1' <- [ a1 `quot` 2 ], 
                                                    a2' <- [ a2 `quot` 2 ],
                                                    a3' <- [ a3 `quot` 2 ],
                                                    a4' <- [ a4 `quot` 2 ],
                                                    a5' <- [ a5 `quot` 2 ],
                                                    a6' <- [ a6 `quot` 2 ] ]

