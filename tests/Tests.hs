module Main where

import Test.QuickCheck
import qualified Nettle.Ethernet.EthernetTests as EthernetTests

main :: IO ()
main = sequence_ [ quickCheckWith (stdArgs { maxSuccess = 300 }) p | p <- props ]

props = concat [ EthernetTests.props ]
