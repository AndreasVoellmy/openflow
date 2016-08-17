{-# LANGUAGE CPP, DisambiguateRecordFields, RecordWildCards, NamedFieldPuns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | This module implements parsing and unparsing functions for 
-- OpenFlow messages. It exports a driver that can be used to read messages
-- from a file handle and write messages to a handle.
module Network.Data.OpenFlow.MessagesBinary
       (
         getCSMessage
       , putCSMessage
       , getSCMessage
       , putSCMessage
       ) where

import Prelude hiding (mconcat)
import Network.Data.Ethernet.EthernetAddress
import Network.Data.Ethernet.EthernetFrame
import Network.Data.IPv4.IPAddress
import qualified Network.Data.OpenFlow.Messages as M
import Network.Data.OpenFlow.Port
import Network.Data.OpenFlow.Action
import Network.Data.OpenFlow.Switch
import Network.Data.OpenFlow.Match
import Network.Data.OpenFlow.Packet
import Network.Data.OpenFlow.FlowTable
import Network.Data.OpenFlow.Statistics
import Network.Data.OpenFlow.Error
import Control.Monad (when)
import Data.Word
import Data.Bits
import Data.Binary
import Data.Binary.Put
import Data.Binary.Get
import qualified Data.ByteString as B
import Data.List as List
import Data.Char (chr)
import qualified Data.Map as Map
import Data.Bimap (Bimap, (!), (!>))
import qualified Data.Bimap as Bimap
import Data.Char (ord)
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)



instance Binary M.SCMessage where
  get = getSCMessage
  put = putSCMessage

instance Binary M.CSMessage where
  put = putCSMessage
  get = getCSMessage
          
type MessageTypeCode = Word8

ofptHello :: MessageTypeCode    
ofptHello                 = 0

ofptError :: MessageTypeCode
ofptError                 = 1

ofptEchoRequest :: MessageTypeCode
ofptEchoRequest           = 2

ofptEchoReply :: MessageTypeCode
ofptEchoReply             = 3

ofptVendor :: MessageTypeCode
ofptVendor                = 4

ofptFeaturesRequest :: MessageTypeCode
ofptFeaturesRequest       = 5

ofptFeaturesReply :: MessageTypeCode
ofptFeaturesReply         = 6

-- ofptGetConfigRequest :: MessageTypeCode
-- ofptGetConfigRequest      = 7

-- ofptGetConfigReply :: MessageTypeCode
-- ofptGetConfigReply        = 8

ofptSetConfig :: MessageTypeCode
ofptSetConfig             = 9

ofptPacketIn :: MessageTypeCode
ofptPacketIn              = 10

ofptFlowRemoved :: MessageTypeCode
ofptFlowRemoved           = 11

ofptPortStatus :: MessageTypeCode
ofptPortStatus            = 12   

ofptPacketOut :: MessageTypeCode
ofptPacketOut             = 13

ofptFlowMod :: MessageTypeCode
ofptFlowMod               = 14

ofptPortMod :: MessageTypeCode
ofptPortMod               = 15

ofptStatsRequest :: MessageTypeCode
ofptStatsRequest          = 16

ofptStatsReply :: MessageTypeCode
ofptStatsReply            = 17

ofptBarrierRequest :: MessageTypeCode
ofptBarrierRequest        = 18

ofptBarrierReply :: MessageTypeCode
ofptBarrierReply          = 19

ofptQueueGetConfigRequest :: MessageTypeCode
ofptQueueGetConfigRequest = 20

ofptQueueGetConfigReply :: MessageTypeCode
ofptQueueGetConfigReply   = 21

-- | Parser for @SCMessage@s
getSCMessage :: Get M.SCMessage
getSCMessage 
  = do hdr <- getHeader
       bdy <- getSCMessageBody (msgTransactionID hdr) (msgType hdr) (fromIntegral $ msgLength hdr)
       return bdy

-- | Parser for @CSMessage@s
getCSMessage :: Get M.CSMessage
getCSMessage = do hdr <- getHeader
                  snd <$> getCSMessageBody hdr


-- | Unparser for @SCMessage@s
putSCMessage :: M.SCMessage -> Put 
putSCMessage msg = 
  case msg of 
    M.SCHello xid -> putH xid ofptHello headerSize

    M.SCEchoRequest xid bytes -> putH xid ofptEchoRequest (headerSize + length bytes)  <>
                                 putWord8s bytes
    M.SCEchoReply xid bytes  -> putH xid ofptEchoReply (headerSize + length bytes)   <>
                                putWord8s bytes
    M.PacketIn  xid pktInfo  -> let bodyLen = packetInMessageBodyLen pktInfo
                                in  putH xid ofptPacketIn (headerSize + bodyLen) <>
                                    putPacketInRecord pktInfo
    M.Features xid features   -> putH xid ofptFeaturesReply (headerSize + 24 + 48 * length (ports features)) <>
                                 putSwitchFeaturesRecord features
    M.Error xid err           -> putH xid ofptError (headerSize + 2 + 2) <>
                                 putSwitchError err
    _ -> error ("serialization for message " ++ show msg ++ " is not yet supported.")
  where vid      = ofpVersion
        putH xid tcode len = putHeader (OFPHeader vid tcode (fromIntegral len) xid) 

packetInMessageBodyLen :: PacketInfo -> Int
packetInMessageBodyLen pktInfo = 10 + fromIntegral (packetLength pktInfo)

putPacketInRecord :: PacketInfo -> Put
putPacketInRecord (PacketInfo {..}) = 
  putWord32be (maybe 0xffffffff id bufferID)  <>
  (putWord16be $ fromIntegral packetLength ) <>
  putWord16be receivedOnPort <>
  (putWord8 $ reason2Code reasonSent) <>
  putWord8 0


{- Header -}

type OpenFlowVersionID = Word8

ofpVersion :: OpenFlowVersionID
ofpVersion =  0x01

-- | OpenFlow message header
data OFPHeader = 
  OFPHeader { msgVersion       :: !OpenFlowVersionID
            , msgType          :: !MessageTypeCode 
            , msgLength        :: !Word16 
            , msgTransactionID :: !M.TransactionID 
            } deriving (Show,Eq,Generic,NFData)

headerSize :: Int
headerSize = 8 

-- | Unparser for OpenFlow message header
putHeader :: OFPHeader -> Put
putHeader (OFPHeader {..}) = putWord8 msgVersion <>
                             putWord8 msgType  <>
                             putWord16be msgLength <>
                             putWord32be msgTransactionID
                   
putHeaderInternal :: MessageTypeCode -> Word16 -> M.TransactionID -> Put
putHeaderInternal !t !l !x 
  = putWord8 ofpVersion <>
    putWord8 t <>
    putWord16be l <>
    putWord32be x
{-# INLINE putHeaderInternal #-}

-- | Parser for the OpenFlow message header                          
getHeader :: Get OFPHeader
getHeader = do v <- getWord8
               t <- getWord8
               l <- getWord16be
               x <- getWord32be
               return $ OFPHeader v t l x
{-# INLINE getHeader #-} 
               
-- Get SCMessage body
{-# INLINE getSCMessageBody #-} 
getSCMessageBody :: M.TransactionID -> MessageTypeCode -> Int -> Get M.SCMessage
getSCMessageBody !xid !msgType !len 
  | msgType == ofptPacketIn      = do packetInRecord <- getPacketInRecord len
                                      return (M.PacketIn xid packetInRecord)
  | msgType == ofptEchoRequest   = do bytes <- getWord8s (len - headerSize)
                                      return (M.SCEchoRequest xid bytes)
  | msgType == ofptEchoReply     = do bytes <- getWord8s (len - headerSize)
                                      return (M.SCEchoReply xid bytes)
  | msgType == ofptFeaturesReply = do switchFeaturesRecord <- getSwitchFeaturesRecord len
                                      return (M.Features xid switchFeaturesRecord)
  | msgType == ofptHello         = return (M.SCHello xid )
  | msgType == ofptPortStatus    = do body <- getPortStatus 
                                      return (M.PortStatus xid body)
  | msgType == ofptError         = do body <- getSwitchError len
                                      return (M.Error xid body)
  | msgType == ofptFlowRemoved   = do body <- getFlowRemovedRecord 
                                      return (M.FlowRemoved xid body)
  | msgType == ofptBarrierReply  = return $ M.BarrierReply xid 
  | msgType == ofptStatsReply    = do body <- getStatsReply len
                                      return (M.StatsReply xid body)
  | msgType == ofptQueueGetConfigReply = do qcReply <- getQueueConfigReply len
                                            return (M.QueueConfigReply xid qcReply)
  | otherwise = error ("Unrecognized message type: " ++ show msgType)



getCSMessageBody :: OFPHeader -> Get (M.TransactionID, M.CSMessage)
getCSMessageBody header@(OFPHeader {..}) = 
    if msgType == ofptPacketOut 
    then do packetOut <- getPacketOut len
            return (msgTransactionID, M.PacketOut msgTransactionID packetOut)
    else if msgType == ofptFlowMod
         then do fmod <- getFlowMod len
                 return (msgTransactionID, M.FlowMod msgTransactionID fmod)
         else if msgType == ofptHello 
              then return (msgTransactionID, M.CSHello msgTransactionID)
              else if msgType == ofptEchoRequest
                   then do bytes <- getWord8s (len - headerSize)
                           return (msgTransactionID, M.CSEchoRequest msgTransactionID bytes)
                   else if msgType == ofptEchoReply
                        then do bytes <- getWord8s (len - headerSize)
                                return (msgTransactionID, M.CSEchoReply msgTransactionID bytes)
                        else if msgType == ofptFeaturesRequest
                             then return (msgTransactionID, M.FeaturesRequest msgTransactionID)
                             else if msgType == ofptSetConfig
                                  then do _ <- getSetConfig 
                                          return (msgTransactionID, M.SetConfig msgTransactionID)
                                  else if msgType == ofptVendor 
                                       then do () <- getVendorMessage len
                                               return (msgTransactionID, M.Vendor msgTransactionID)
                                       else error ("Unrecognized message type with header: " ++ show header)
    where len = fromIntegral msgLength

-----------------------
-- Queue Config parser
-----------------------
getQueueConfigReply :: Int -> Get QueueConfigReply
getQueueConfigReply len = 
  do portID <- getWord16be 
     skip 6
     qs <- getQueues 16 []
     return (PortQueueConfig portID qs)
  where 
    getQueues pos acc = 
      if pos < len
      then do (q, n) <- getQueue
              let pos' = pos + n
              pos' `seq` getQueues pos' (q:acc)
      else return acc
    getQueue = 
      do qid <- getWord32be 
         qdlen <- getWord16be
         skip 2
         qprops <- getQueueProps qdlen 8 [] -- at byte 8 because of ofp_packet_queue header and len includes header (my guess).
         return (QueueConfig qid qprops, fromIntegral qdlen)
      where 
        getQueueProps qdlen pos acc = 
          if pos < qdlen
          then do (prop, propLen) <- getQueueProp
                  let pos' = pos + propLen
                  pos' `seq` getQueueProps qdlen pos' (prop : acc)
          else return acc
        getQueueProp = 
          do propType <- getWord16be
             propLen  <- getWord16be 
             skip 4
             when (propType /= ofpqtMinRate) (error ("Unexpected queue property type code " ++ show propType))
             rate <- getWord16be
             skip 6
             let rate' = if rate  > 1000 then Disabled else Enabled rate
             return (MinRateQueue rate', propLen)
                          
                          
ofpqtMinRate :: Word16                          
ofpqtMinRate = 1
----------------------
-- Set Config parser
----------------------
getSetConfig :: Get (Word16, Word16)          
getSetConfig = do flags <- getWord16be
                  missSendLen <- getWord16be
                  return (flags, missSendLen)
          
-------------------------------------------               
-- Vendor parser               
-------------------------------------------                  
getVendorMessage :: Int -> Get ()                  
getVendorMessage r
  = do skip r
       return ()
               
-------------------------------------------
--  SWITCH FEATURES PARSER 
-------------------------------------------
putSwitchFeaturesRecord :: SwitchFeatures -> Put
putSwitchFeaturesRecord (SwitchFeatures {..}) = 
  putWord64be switchID <>
  (putWord32be $ fromIntegral packetBufferSize) <>
  (putWord8 $ fromIntegral numberFlowTables) <>
  (sequence_ $ replicate 3 (putWord8 0)) <>
  (putWord32be $ switchCapabilitiesBitVector capabilities) <>
  (putWord32be $ actionTypesBitVector supportedActions) <>
  mconcat [ putPhyPort p | p <- ports ]

getSwitchFeaturesRecord :: Int -> Get SwitchFeatures
getSwitchFeaturesRecord len = do 
  dpid    <- getWord64be
  nbufs   <- getWord32be
  ntables <- getWord8
  skip 3
  caps    <- getWord32be
  acts    <- getWord32be
  ports <- sequence (replicate num_ports getPhyPort)
  return (SwitchFeatures
          dpid
          (fromIntegral nbufs)
          (fromIntegral ntables)
          (bitMap2SwitchCapabilitySet caps)
          (bitMap2SwitchActionSet acts) ports
         )
    where ports_offset      = 32
          num_ports         = (len - ports_offset) `div` size_ofp_phy_port
          size_ofp_phy_port = 48

putPhyPort :: Port -> Put
putPhyPort (Port {..}) = 
  putWord16be portID <>
  putEthernetAddress portAddress <>
  (putWord8s $ take ofpMaxPortNameLen (map (fromIntegral . ord) portName ++ repeat 0)) <>
  (putWord32be $ portConfigsBitVector portConfig) <>
  (putWord32be $ portState2Code portLinkDown portSTPState) <>
  (putWord32be $ featuresBitVector $ maybe [] id portCurrentFeatures) <>
  (putWord32be $ featuresBitVector $ maybe [] id portAdvertisedFeatures) <>
  (putWord32be $ featuresBitVector $ maybe [] id portSupportedFeatures) <>
  (putWord32be $ featuresBitVector $ maybe [] id portPeerFeatures)
     

getPhyPort :: Get Port
getPhyPort = do 
  port_no  <- getWord16be
  hw_addr  <- getEthernetAddress
  name_arr <- getWord8s ofpMaxPortNameLen
  let port_name = [ chr (fromIntegral b) | b <- takeWhile (/=0) name_arr ]
  cfg  <- getWord32be
  st   <- getWord32be
  let (linkDown, stpState) = code2PortState st
  curr <- getWord32be
  adv  <- getWord32be 
  supp <- getWord32be
  peer <- getWord32be
  return $ Port { portID                 = port_no, 
                  portName               = port_name, 
                  portAddress            = hw_addr, 
                  portConfig             = bitMap2PortConfigAttributeSet cfg, 
                  portLinkDown           = linkDown, 
                  portSTPState           = stpState, 
                  portCurrentFeatures    = decodePortFeatureSet curr, 
                  portAdvertisedFeatures = decodePortFeatureSet adv,
                  portSupportedFeatures  = decodePortFeatureSet supp,
                  portPeerFeatures       = decodePortFeatureSet peer
                }

ofpMaxPortNameLen :: Int
ofpMaxPortNameLen = 16

featuresBitVector :: [PortFeature] -> Word32
featuresBitVector = foldl (\v f -> v .|. featureBitMask f) 0

featureBitMask :: PortFeature -> Word32
featureBitMask feat = 
  case lookup feat featurePositions of 
    Nothing -> error "unexpected port feature"
    Just i -> bit i

decodePortFeatureSet :: Word32 -> Maybe [PortFeature]
decodePortFeatureSet word 
    | word == 0 = Nothing
    | otherwise = Just $ concat [ if word `testBit` position then [feat] else [] | (feat, position) <- featurePositions ]

featurePositions :: [(PortFeature, Int)]
featurePositions = [ (Rate10MbHD,       0),
                     (Rate10MbFD,       1), 
                     (Rate100MbHD,      2), 
                     (Rate100MbFD,      3),
                     (Rate1GbHD,        4),
                     (Rate1GbFD,        5),
                     (Rate10GbFD,       6),
                     (Copper,           7),
                     (Fiber,            8),
                     (AutoNegotiation,  9),
                     (Pause,           10),
                     (AsymmetricPause, 11) ]

ofppsLinkDown, ofppsStpListen, ofppsStpLearn, ofppsStpForward, ofppsStpBlock, ofppsStpMask :: Word32
ofppsLinkDown   = 1 `shiftL` 0  -- 1 << 0
ofppsStpListen  = 0 `shiftL` 8  -- 0 << 8
ofppsStpLearn   = 1 `shiftL` 8  -- 1 << 8
ofppsStpForward = 2 `shiftL` 8  -- 2 << 8
ofppsStpBlock   = 3 `shiftL` 8  -- 3 << 8 
ofppsStpMask    = 3 `shiftL` 8  -- 3 << 8

code2PortState :: Word32 -> (Bool, SpanningTreePortState)
code2PortState w = (w .&. ofppsLinkDown /= 0, stpState)
    where stpState 
              | flag == ofppsStpListen  = STPListening
              | flag == ofppsStpLearn   = STPLearning
              | flag == ofppsStpForward = STPForwarding
              | flag == ofppsStpBlock   = STPBlocking
              | otherwise               = error "Unrecognized port status code."
          flag = w .&. ofppsStpMask

portState2Code :: Bool -> SpanningTreePortState -> Word32
portState2Code isUp stpState = 
  let b1 = if isUp then ofppsLinkDown else 0
      b2 = case stpState of
        STPListening  -> ofppsStpListen
        STPLearning   -> ofppsStpLearn
        STPForwarding -> ofppsStpForward
        STPBlocking   -> ofppsStpBlock
  in b1 .|. b2
     
bitMap2PortConfigAttributeSet :: Word32 -> [PortConfigAttribute]
bitMap2PortConfigAttributeSet bmap = filter inBMap $ enumFrom $ toEnum 0
    where inBMap attr = let mask = portAttribute2BitMask attr 
                        in mask .&. bmap == mask

portConfigsBitVector :: [PortConfigAttribute] -> Word32
portConfigsBitVector = foldl (\v a -> v .|. portAttribute2BitMask a) 0

portAttribute2BitMask :: PortConfigAttribute -> Word32
portAttribute2BitMask PortDown      = shiftL 1 0
portAttribute2BitMask STPDisabled   = shiftL 1 1
portAttribute2BitMask OnlySTPackets = shiftL 1 2
portAttribute2BitMask NoSTPackets   = shiftL 1 3
portAttribute2BitMask NoFlooding    = shiftL 1 4
portAttribute2BitMask DropForwarded = shiftL 1 5
portAttribute2BitMask NoPacketInMsg = shiftL 1 6

portAttributeSet2BitMask :: [PortConfigAttribute] -> Word32
portAttributeSet2BitMask = foldl f 0
    where f mask b = mask .|. portAttribute2BitMask b

bitMap2SwitchCapabilitySet :: Word32 -> [SwitchCapability]
bitMap2SwitchCapabilitySet bmap =
  filter inBMap capList
    where inBMap attr = let mask = switchCapability2BitMask attr 
                        in mask .&. bmap == mask
          capList = [ HasFlowStats
                    , HasTableStats
                    , HasPortStats
                    , SpanningTree
                    , CanReassembleIPFragments
                    , HasQueueStatistics
                    , CanMatchIPAddressesInARPPackets
                    ]

switchCapabilitiesBitVector :: [SwitchCapability] -> Word32
switchCapabilitiesBitVector = 
  foldl (\vector c -> vector .|. switchCapability2BitMask c) 0

switchCapability2BitMask :: SwitchCapability -> Word32
switchCapability2BitMask HasFlowStats  = shiftL 1 0
switchCapability2BitMask HasTableStats = shiftL 1 1
switchCapability2BitMask HasPortStats  = shiftL 1 2
switchCapability2BitMask SpanningTree  = shiftL 1 3
switchCapability2BitMask CanReassembleIPFragments = shiftL 1 5
switchCapability2BitMask HasQueueStatistics = shiftL 1 6
switchCapability2BitMask CanMatchIPAddressesInARPPackets = shiftL 1 7
switchCapability2BitMask MayTransmitOverMultiplePhysicalInterfaces =
  error "No encoding defined for MayTransmitOverMultiplePhysicalInterfaces"


bitMap2SwitchActionSet :: Word32 -> [ActionType]
bitMap2SwitchActionSet bmap = filter inBMap $ enumFrom $ toEnum 0
    where inBMap attr = let mask = actionType2BitMask attr 
                        in mask .&. bmap == mask

actionTypesBitVector :: [ActionType] -> Word32
actionTypesBitVector = foldl (\v a -> v .|. actionType2BitMask a) 0

code2ActionType :: Word16 -> ActionType
code2ActionType !code = 
  case code of
    0 -> OutputToPortType
    1 -> SetVlanVIDType
    2 -> SetVlanPriorityType
    3 -> StripVlanHeaderType
    4 -> SetEthSrcAddrType
    5 -> SetEthDstAddrType
    6 -> SetIPSrcAddrType
    7 -> SetIPDstAddrType
    8 -> SetIPTypeOfServiceType
    9 -> SetTransportSrcPortType
    10 -> SetTransportDstPortType
    11 -> EnqueueType
    0xffff -> VendorActionType
    _ -> error "Unknown action type code"
{-# INLINE code2ActionType #-}

actionType2Code :: ActionType -> Word16
actionType2Code OutputToPortType = 0
actionType2Code SetVlanVIDType = 1
actionType2Code SetVlanPriorityType = 2
actionType2Code StripVlanHeaderType = 3
actionType2Code SetEthSrcAddrType = 4
actionType2Code SetEthDstAddrType = 5
actionType2Code SetIPSrcAddrType = 6
actionType2Code SetIPDstAddrType = 7
actionType2Code SetIPTypeOfServiceType = 8
actionType2Code SetTransportSrcPortType = 9
actionType2Code SetTransportDstPortType = 10
actionType2Code EnqueueType = 11
actionType2Code VendorActionType = 0xffff
{-# INLINE actionType2Code #-}  



actionType2BitMask :: ActionType -> Word32
actionType2BitMask = shiftL 1 . fromIntegral . actionType2Code 

------------------------------------------
-- Packet In Parser
------------------------------------------
{-# INLINE getPacketInRecord #-} 
getPacketInRecord :: Int -> Get PacketInfo
getPacketInRecord len = do 
  bufID      <- getWord32be
  totalLen   <- getWord16be
  in_port    <- getWord16be
  reasonCode <- getWord8
  skip 1
  let !reason = code2Reason reasonCode
  (!hdr, bdy) <- lookAhead getEthernetFrame
  rawBytes' <- getByteString $ fromIntegral data_len
  return $ PacketInfo
    { bufferID       = if bufID == 0xffffffff then Nothing else Just bufID
    , packetLength   = fromIntegral totalLen
    , receivedOnPort = in_port
    , reasonSent     = reason
    , enclosedFrame  = (hdr,bdy)
    , rawBytes       = rawBytes'
    }
  where data_offset = 18 -- 8 + 4 + 2 + 2 + 1 + 1
        data_len    = len - data_offset

{-# INLINE code2Reason #-}
code2Reason :: Word8 -> PacketInReason
code2Reason !code 
  | code == 0  = NotMatched
  | code == 1  = ExplicitSend
  | otherwise  = error ("Received unknown packet-in reason code: " ++ show code ++ ".")

{-# INLINE reason2Code #-}
reason2Code :: PacketInReason -> Word8
reason2Code NotMatched   = 0
reason2Code ExplicitSend = 1

  


------------------------------------------
-- Port Status parser
------------------------------------------
getPortStatus :: Get PortStatus
getPortStatus = do 
  reasonCode <- getWord8
  skip 7
  portDesc <- getPhyPort
  return $ (code2PortStatusUpdateReason reasonCode, portDesc)

code2PortStatusUpdateReason :: (Eq a, Num a, Show a) =>
                               a -> PortStatusUpdateReason
code2PortStatusUpdateReason code
  | code == 0 = PortAdded
  | code == 1 = PortDeleted
  | code == 2 = PortModified
  | otherwise = error ("Unkown port status update reason code: " ++ show code)

------------------------------------------
-- Switch Error parser
------------------------------------------
getSwitchError :: Int -> Get SwitchError
getSwitchError len = do 
  typ   <- getWord16be
  code  <- getWord16be
  bytes <- getWord8s (len - headerSize - 4)
  return (code2ErrorType typ code bytes)

putSwitchError :: SwitchError -> Put
putSwitchError (BadRequest VendorNotSupported []) = 
  putWord16be 1 <>
  putWord16be 3
putSwitchError err = error ("Serialization for error " ++ show err ++ " not yet supported.")

code2ErrorType :: Word16 -> Word16 -> [Word8] -> SwitchError
code2ErrorType typ code bytes
    | typ == 0 = HelloFailed   (helloErrorCodesMap  ! code) [ chr (fromIntegral b) | b <- takeWhile (/=0) bytes ]
    | typ == 1 = BadRequest    (requestErrorCodeMap ! code) bytes
    | typ == 2 = BadAction     (actionErrorCodeMap  ! code) bytes
    | typ == 3 = FlowModFailed (flowModErrorCodeMap ! code) bytes
    | typ == 4 = error "Port mod failed error not yet handled"
    | typ == 5 = error "Queue op failed error not yet handled"
    | otherwise = error "Unknown error type code"


helloErrorCodesMap :: Bimap Word16 HelloFailure
helloErrorCodesMap = Bimap.fromList [ (0, IncompatibleVersions)
                                      , (1       , HelloPermissionsError) 
                                      ]

requestErrorCodeMap :: Bimap Word16 RequestError
requestErrorCodeMap = Bimap.fromList [ (0,    VersionNotSupported),                  
                                       (1   ,    MessageTypeNotSupported), 
                                       (2   ,    StatsRequestTypeNotSupported), 
                                       (3 ,    VendorNotSupported), 
                                       (4,    VendorSubtypeNotSupported)
                                       , (5      ,    RequestPermissionsError)
                                       , (6    ,    BadRequestLength)
                                       , (7,   BufferEmpty)
                                       , (8, UnknownBuffer) 
                                       ]

actionErrorCodeMap :: Bimap Word16 ActionError
actionErrorCodeMap = Bimap.fromList [ (0, UnknownActionType), 
                                      (1, BadActionLength), 
                                      (2, UnknownVendorID), 
                                      (3, UnknownActionTypeForVendor), 
                                      (4, BadOutPort), 
                                      (5, BadActionArgument)
                                      , (6, ActionPermissionsError)
                                      , (7, TooManyActions)
                                      , (8, InvalidQueue) 
                                      ]

flowModErrorCodeMap :: Bimap Word16 FlowModError                 
flowModErrorCodeMap = Bimap.fromList [ (0,   TablesFull) 
                                       , (1,           OverlappingFlow)
                                       , (2,             FlowModPermissionsError)
                                       , (3, EmergencyModHasTimeouts)
                                       , (4,       BadCommand)
                                       , (5,       UnsupportedActionList) 
                                       ]


------------------------------------------
-- FlowRemoved parser
------------------------------------------
getFlowRemovedRecord :: Get FlowRemoved
getFlowRemovedRecord = do 
  m         <- getMatch
  cookie <- getWord64be
  p         <- getWord16be
  rcode     <- getWord8
  skip 1 
  dur       <- getWord32be
  dur_nsec <-  getWord32be
  idle_timeout <- getWord16be
  skip 2 
  pktCount  <- getWord64be
  byteCount <- getWord64be
  return $ FlowRemovedRecord m cookie p (code2FlowRemovalReason rcode) (fromIntegral dur) (fromIntegral dur_nsec) (fromIntegral idle_timeout) (fromIntegral pktCount) (fromIntegral byteCount)


flowRemovalReason2CodeBijection :: Bimap FlowRemovalReason Word8
flowRemovalReason2CodeBijection =
    Bimap.fromList [(IdleTimerExpired,    0), 
                    (HardTimerExpired,    1), 
                    (DeletedByController, 2)        ]

code2FlowRemovalReason :: Word8 -> FlowRemovalReason
code2FlowRemovalReason rcode = (Bimap.!>) flowRemovalReason2CodeBijection rcode


-----------------------------------------
-- Stats Reply parser
-----------------------------------------

getStatsReply :: Int -> Get StatsReply
getStatsReply headerLen = do 
  statsType <- getWord16be
  flags     <- getWord16be
  let bodyLen = headerLen - (headerSize + 4)
  let moreFlag = flags == 0x0001
  if statsType == ofpstFlow
   then do flowStats    <- getFlowStatsReplies bodyLen 
           return (FlowStatsReply moreFlag flowStats)
   else if statsType == ofpstPort
         then do portStats <- getPortStatsReplies bodyLen
                 return (PortStatsReply moreFlag portStats)
         else if statsType == ofpstAggregate 
              then do aggStats <- getAggregateStatsReplies bodyLen
                      return (AggregateFlowStatsReply aggStats)
              else if statsType == ofpstTable 
                   then do tableStats <- getTableStatsReplies bodyLen
                           return (TableStatsReply moreFlag tableStats)
                   else if statsType == ofpstDesc 
                        then do desc <- getDescriptionReply
                                return (DescriptionReply desc)
                        else 
                          if statsType == ofpstQueue 
                          then do queueStats <- getQueueStatsReplies bodyLen 
                                  return (QueueStatsReply moreFlag queueStats)
                          else 
                            error ("unhandled stats reply message with type: " ++ show statsType)


getQueueStatsReplies :: Int -> Get [QueueStats]
getQueueStatsReplies bodyLen = do 
  sequence (replicate cnt getQueueStatsReply)
  where cnt = let (d,m) = bodyLen `divMod` queueStatsLength
              in if m == 0 
                 then d
                 else error ("Body of queue stats reply must be a multiple of " ++ show queueStatsLength)
        queueStatsLength = 32
        getQueueStatsReply = do 
          portNo     <- getWord16be
          skip 2
          qid        <- getWord32be
          tx_bytes   <- getWord64be
          tx_packets <- getWord64be
          tx_errs    <- getWord64be
          return (QueueStats { queueStatsPortID             = portNo, 
                               queueStatsQueueID            = qid,
                               queueStatsTransmittedBytes   = fromIntegral tx_bytes,
                               queueStatsTransmittedPackets = fromIntegral tx_packets,
                               queueStatsTransmittedErrors  = fromIntegral tx_errs })


getDescriptionReply :: Get Description
getDescriptionReply = do 
  mfr    <- getCharsRightPadded descLen
  hw     <- getCharsRightPadded descLen
  sw     <- getCharsRightPadded descLen
  serial <- getCharsRightPadded descLen
  dp     <- getCharsRightPadded serialNumLen
  return ( Description { manufacturerDesc = mfr
                       , hardwareDesc     = hw
                       , softwareDesc     = sw
                       , serialNumber     = serial
                       , datapathDesc     = dp
  } )
  where descLen      = 256
        serialNumLen =  32
  
getCharsRightPadded :: Int -> Get String        
getCharsRightPadded n = do 
  bytes <- getWord8s n
  return [ chr (fromIntegral b) | b <- takeWhile (/=0) bytes]
        
getTableStatsReplies :: Int -> Get [TableStats]
getTableStatsReplies bodyLen = sequence (replicate cnt getTableStatsReply)
  where cnt = let (d,m) = bodyLen `divMod` tableStatsLength
              in if m == 0 
                 then d
                 else error ("Body of Table stats reply must be a multiple of " ++ show tableStatsLength)
        tableStatsLength = 64

getTableStatsReply :: Get TableStats
getTableStatsReply = do 
  tableID      <- getWord8
  skip 3
  name_bytes   <- getWord8s maxTableNameLen
  let name = [ chr (fromIntegral b) | b <- name_bytes ]
  _            <- getWord32be
  maxEntries   <- getWord32be
  activeCount  <- getWord32be
  lookupCount  <- getWord64be
  matchedCount <- getWord64be
  return ( TableStats { tableStatsTableID   = tableID, 
                        tableStatsTableName = name, 
                        tableStatsMaxEntries = fromIntegral maxEntries, 
                        tableStatsActiveCount = fromIntegral activeCount, 
                        tableStatsLookupCount  = fromIntegral lookupCount, 
                        tableStatsMatchedCount = fromIntegral matchedCount } )
  where maxTableNameLen = 32


getFlowStatsReplies :: Int -> Get [FlowStats]
getFlowStatsReplies bodyLen 
    | bodyLen == 0 = return []
    | otherwise    = do (fs,fsLen) <- getFlowStatsReply 
                        rest       <- getFlowStatsReplies (bodyLen - fsLen) 
                        return (fs : rest)

getFlowStatsReply :: Get (FlowStats, Int)
getFlowStatsReply = do !len            <- getWord16be
                       !tid            <- getWord8
                       skip 1
                       match          <- getMatch
                       !dur_sec        <- getWord32be
                       !dur_nanosec    <- getWord32be
                       !priority       <- getWord16be
                       !idle_to        <- getWord16be
                       !hard_to        <- getWord16be
                       skip 6
                       !cookie         <- getWord64be
                       !packet_count   <- getWord64be
                       !byte_count     <- getWord64be
                       actions <- getActionsOfSize (fromIntegral len - flowStatsReplySize)                          
                       let !stats = FlowStats { flowStatsTableID             = tid, 
                                                flowStatsMatch               = match, 
                                                flowStatsDurationSeconds     = fromIntegral dur_sec,
                                                flowStatsDurationNanoseconds = fromIntegral dur_nanosec, 
                                                flowStatsPriority            = priority, 
                                                flowStatsIdleTimeout         = fromIntegral idle_to,
                                                flowStatsHardTimeout         = fromIntegral hard_to,
                                                flowStatsCookie              = cookie, 
                                                flowStatsPacketCount         = fromIntegral packet_count, 
                                                flowStatsByteCount           = fromIntegral byte_count, 
                                                flowStatsActions             = actions      }
                       return (stats, fromIntegral len)
    where flowStatsReplySize = 88

getActionsOfSize :: Int -> Get [Action]    
getActionsOfSize n 
  | n > 0 = do a <- getAction
               as <- getActionsOfSize (n - actionSizeInBytes a)
               return (a : as)
  | n == 0 = return []
  | otherwise = error "bad number of actions or bad action size"

getAction :: Get Action
getAction = do 
  action_type <- getWord16be
  action_len  <- getWord16be
  getActionForType (code2ActionType action_type) action_len

getActionForType :: ActionType -> Word16 -> Get Action
getActionForType OutputToPortType _ = 
  do port    <- getWord16be 
     max_len <- getWord16be
     return (SendOutPort (action port max_len))
    where action !port !max_len
              | port <= 0xff00          = PhysicalPort port
              | port == ofppInPort      = InPort
              | port == ofppFlood       = Flood
              | port == ofppAll         = AllPhysicalPorts
              | port == ofppController  = ToController max_len
              | port == ofppTable       = WithTable
              | otherwise               = error "Unknown pseudo-port code"
getActionForType SetVlanVIDType _ = 
  do vlanid <- getWord16be
     skip 2
     return (SetVlanVID vlanid)
getActionForType SetVlanPriorityType _ = 
  do pcp <- getWord8
     skip 3
     return (SetVlanPriority pcp)
getActionForType StripVlanHeaderType _ = 
  do skip 4
     return StripVlanHeader
getActionForType SetEthSrcAddrType _ = 
  do addr <- getEthernetAddress
     skip 6
     return (SetEthSrcAddr addr)
getActionForType SetEthDstAddrType _ = 
  do addr <- getEthernetAddress
     skip 6
     return (SetEthDstAddr addr)
getActionForType SetIPSrcAddrType _ = 
  do addr <- getIPAddress
     return (SetIPSrcAddr addr)
getActionForType SetIPDstAddrType _ = 
  do addr <- getIPAddress
     return (SetIPDstAddr addr)
getActionForType SetIPTypeOfServiceType _ = 
  do tos <- getWord8
     skip 3
     return (SetIPToS tos)
getActionForType SetTransportSrcPortType _ = 
  do port <- getWord16be
     return (SetTransportSrcPort port)
getActionForType SetTransportDstPortType _ = 
  do port <- getWord16be
     return (SetTransportDstPort port)
getActionForType EnqueueType _ = 
  do port <- getWord16be
     skip 6
     qid <- getWord32be
     return (Enqueue port qid)
getActionForType VendorActionType action_len = 
  do vendorid <- getWord32be
     bytes <- getWord8s (fromIntegral action_len - 2 - 2 - 4)
     return (VendorAction vendorid bytes)



getAggregateStatsReplies :: Int -> Get AggregateFlowStats
getAggregateStatsReplies _ = do 
  pkt_cnt <- getWord64be
  byte_cnt <- getWord64be
  flow_cnt <- getWord32be
  skip 4
  return (AggregateFlowStats (fromIntegral pkt_cnt) (fromIntegral byte_cnt) (fromIntegral flow_cnt))

getPortStatsReplies :: Int -> Get [(PortID,PortStats)]
getPortStatsReplies bodyLen = sequence (replicate numPorts getPortStatsReply)
    where numPorts      = bodyLen `div` portStatsSize
          portStatsSize = 104

getPortStatsReply :: Get (PortID, PortStats)
getPortStatsReply = do port_no    <- getWord16be
                       skip 6
                       rx_packets <- getWord64be
                       tx_packets <- getWord64be
                       rx_bytes   <- getWord64be
                       tx_bytes   <- getWord64be
                       rx_dropped <- getWord64be
                       tx_dropped <- getWord64be
                       rx_errors  <- getWord64be
                       tx_errors  <- getWord64be
                       rx_frame_err <- getWord64be
                       rx_over_err <- getWord64be
                       rx_crc_err <- getWord64be
                       collisions <- getWord64be
                       return $ (port_no, 
                                 PortStats { 
                                    portStatsReceivedPackets      = checkValid rx_packets, 
                                    portStatsSentPackets          = checkValid tx_packets, 
                                    portStatsReceivedBytes        = checkValid rx_bytes, 
                                    portStatsSentBytes            = checkValid tx_bytes, 
                                    portStatsReceiverDropped      = checkValid rx_dropped, 
                                    portStatsSenderDropped        = checkValid tx_dropped,
                                    portStatsReceiveErrors        = checkValid rx_errors,
                                    portStatsTransmitError        = checkValid tx_errors, 
                                    portStatsReceivedFrameErrors  = checkValid rx_frame_err, 
                                    portStatsReceiverOverrunError = checkValid rx_over_err,
                                    portStatsReceiverCRCError     = checkValid rx_crc_err,
                                    portStatsCollisions           = checkValid collisions }
                                 )
    where checkValid :: Word64 -> Maybe Double
          checkValid x = if x == -1 
                         then Nothing 
                         else Just (fromIntegral x)


----------------------------------------------
-- Unparsers for CSMessages
----------------------------------------------

putCSMessage :: M.CSMessage -> Put
putCSMessage !msg = 
    case msg of 
      M.FlowMod xid fmod -> putFlowModMain xid fmod
      M.PacketOut xid packetOut -> putSendPacket xid packetOut
      M.CSHello xid -> putH xid ofptHello headerSize
      M.CSEchoRequest xid bytes -> putH xid ofptEchoRequest (headerSize + length bytes)  <>
                                   putWord8s bytes
      M.CSEchoReply xid bytes   -> putEchoReply xid bytes
      M.FeaturesRequest xid -> putFeatureRequest xid 
      M.PortMod xid portModRecord -> putH xid ofptPortMod portModLength <>
                                     putPortMod portModRecord
      M.BarrierRequest xid         -> putBarrierRequest xid
      M.StatsRequest xid request -> putH xid ofptStatsRequest (statsRequestSize request) <>
                                    putStatsRequestBody request
      M.GetQueueConfig xid request -> putH xid ofptQueueGetConfigRequest 12 <>
                                      putQueueConfigRequest request
      M.ExtQueueModify xid p qCfgs -> putExtQueueModify xid p qCfgs
      M.ExtQueueDelete xid p qCfgs -> putExtQueueDelete xid p qCfgs
      _ -> error ("Serialization of message " ++ show msg ++ " not yet supported.")
    where vid      = ofpVersion
          putH :: M.TransactionID -> MessageTypeCode -> Int -> Put
          putH xid tcode len = putHeader (OFPHeader vid tcode (fromIntegral len) xid) 
{-# INLINE putCSMessage #-}

putBarrierRequest :: M.TransactionID -> Put
putBarrierRequest xid = 
  putHeaderInternal ofptBarrierRequest (fromIntegral headerSize) xid

putFeatureRequest :: M.TransactionID -> Put
putFeatureRequest xid = 
  putHeaderInternal ofptFeaturesRequest (fromIntegral headerSize) xid

putEchoReply :: M.TransactionID -> [Word8] -> Put
putEchoReply xid bytes =
  putHeaderInternal ofptEchoReply (fromIntegral (headerSize + length bytes)) xid <>
  putWord8s bytes


putQueueConfigRequest :: QueueConfigRequest -> Put
putQueueConfigRequest (QueueConfigRequest portID) = 
  putWord16be portID <>
  putWord16be 0 --padding

putExtQueueModify :: M.TransactionID -> PortID -> [QueueConfig] -> Put
putExtQueueModify xid p qCfgs
  = putHeaderInternal ofptVendor (fromIntegral (headerSize + 16 + sum (map lenQueueConfig qCfgs))) xid <>
    putWord32be 0x000026e1 <> -- OPENFLOW_VENDOR_ID
    putWord32be 0 <> -- OFP_EXT_QUEUE_MODIFY
    putWord16be p <>
    putWord32be 0 <>
    putWord16be 0 <>
    mconcat (map putQueueConfig qCfgs)

putExtQueueDelete :: M.TransactionID -> PortID -> [QueueConfig] -> Put
putExtQueueDelete xid p qCfgs
  = putHeaderInternal ofptVendor (fromIntegral (headerSize + 16 + sum (map lenQueueConfig qCfgs)) ) xid <>
    putWord32be 0x000026e1 <>  -- OPENFLOW_VENDOR_ID
    putWord32be 1 <>           -- OFP_EXT_QUEUE_DELETE
    putWord16be p <>
    putWord32be 0 <>
    putWord16be 0 <>
    mconcat (map putQueueConfig qCfgs)

-- struct ofp_packet_queue
putQueueConfig :: QueueConfig -> Put
putQueueConfig (QueueConfig qid props) = 
  putWord32be qid <>
  putWord16be (fromIntegral (8 + sum (map lenQueueProp props))) <>
  putWord16be 0 <> -- padding
  mapM_ putQueueProp props

-- struct ofp_queue_prop_min_rate
putQueueProp :: QueueProperty -> Put
putQueueProp (MinRateQueue (Enabled rate)) = 
  putWord16be 1    <> -- OFPQT_MIN_RATE
  putWord16be 16   <> -- length
  putWord32be 0    <> -- padding
  putWord16be rate <>
  putWord32be 0    <> -- padding
  putWord16be 0       --padding
putQueueProp prop = error ("Serialization of queue property " ++
                           show prop ++ " not yet supported.")

lenQueueConfig :: QueueConfig -> Int
lenQueueConfig (QueueConfig _ props)
  = 8 + sum (map lenQueueProp props)

lenQueueProp :: QueueProperty -> Int
lenQueueProp (MinRateQueue _) = 16

------------------------------------------
-- Unparser for packet out message
------------------------------------------

sendPacketSizeInBytes :: PacketOut -> Int
sendPacketSizeInBytes (!PacketOutRecord bufferIDData _ actions) = 
  16 {- 16 == headerSize + 4 + 2 + 2 -} 
  + actionSequenceSizeInBytes actions
  + case bufferIDData of { Left _ -> 0 ; Right xs -> fromIntegral (B.length xs) } 


putSendPacket_ :: PacketOut -> Put 
putSendPacket_ (PacketOutRecord {..}) = 
  (putWord32be $ either id (const (-1)) bufferIDData) <>
  putWord16be (maybe ofppNone id packetInPort) <>
  putWord16be (fromIntegral actionArraySize) <>
  (putActions $ actionSequenceToList packetActions) <>
  (either (const $ return ()) putByteString bufferIDData) 
    where actionArraySize = actionSequenceSizeInBytes packetActions

{-# INLINE putSendPacket #-}
putSendPacket :: M.TransactionID -> PacketOut -> Put
putSendPacket xid pkt = 
  putHeaderInternal ofptPacketOut (fromIntegral $ sendPacketSizeInBytes pkt) xid <>
  putSendPacket_ pkt

getPacketOut :: Int -> Get PacketOut
getPacketOut len = do 
  bufID'           <- getWord32be
  port'            <- getWord16be
  actionArraySize' <- getWord16be
  actions          <- getActionsOfSize (fromIntegral actionArraySize')
  packetData       <- if bufID' == -1
                      then let bytesOfData = len - headerSize - 4 - 2 - 2 - fromIntegral actionArraySize'
                           in  getByteString (fromIntegral bytesOfData)
                      else return B.empty
  return $ PacketOutRecord { bufferIDData = if bufID' == -1 
                                            then Right packetData
                                            else Left bufID'
                           , packetInPort = if port' == ofppNone then Nothing else Just port'
                           , packetActions = ActionSequence (error "unknown size") actions
                           } 

------------------------------------------
-- Unparser for flow mod message
------------------------------------------
flowModSizeInBytes' :: ActionSequence -> Int
flowModSizeInBytes' !actions = 
  72 + actionSequenceSizeInBytes actions
  -- 72 = headerSize + matchSize + 24 
{-# INLINE flowModSizeInBytes' #-}  
          
data FlowModRecordInternal = FlowModRecordInternal {
      command'       :: !FlowModType
      , match'       :: !Match
      , actions'     :: !([Action])
      , priority'    :: !Priority
      , idleTimeOut' :: !(Maybe TimeOut)
      , hardTimeOut' :: !(Maybe TimeOut)
      , flags'       :: !([FlowModFlag])
      , bufferID'    :: !(Maybe BufferID)
      , outPort'     :: !(Maybe PseudoPort)
      , cookie'      :: !Cookie
    } deriving (Eq,Show,Generic,NFData)


-- | Specification: @ofp_flow_mod_command@.
data FlowModType
    = FlowAddType
    | FlowModifyType
    | FlowModifyStrictType
    | FlowDeleteType
    | FlowDeleteStrictType
    deriving (Show,Eq,Ord,Generic,NFData)

-- | A set of flow mod attributes can be added to a flow modification command.
data FlowModFlag = SendFlowRemoved | CheckOverlap | Emergency deriving (Show,Eq,Ord,Enum,Generic,NFData)

{-# INLINE putFlowModMain #-}
putFlowModMain :: M.TransactionID -> FlowMod -> Put
putFlowModMain !xid !fmod =
  case fmod of 
    (DeleteFlows {..}) -> 
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' mempty) xid <>
      putMatch match <>
      putWord64be 0 <>
      putWord16be ofpfcDelete  <>
      putWord32be 0 <>
      putWord16be 0 <>
      putWord32be (-1) <>
      (putWord16be $ maybe ofppNone fakePort2Code outPort) <>
      putWord16be 0
         
    (DeleteFlowStrict {..}) ->
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' mempty) xid <>
      putMatch match <>
      putWord64be 0 <>
      (putWord16be $ flowModTypeToCode FlowDeleteStrictType) <>
      putWord32be 0 <>
      putWord16be priority <>
      putWord32be (-1) <>
      (putWord16be $ maybe ofppNone fakePort2Code outPort) <>
      putWord16be 0
                 
    (AddFlow !match !priority !actions !cookie !idleTimeOut !hardTimeOut !notifyWhenRemoved !applyToPacket !overlapAllowed) ->
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' actions) xid <>
      putMatch match <>
      putWord64be cookie <>
      putWord16be ofpfcAdd <>
      (putWord16be $ timeOutToCode idleTimeOut) <>
      (putWord16be $ timeOutToCode hardTimeOut) <>
      putWord16be priority <>
      (putWord32be $ maybe (-1) id applyToPacket) <>
      putWord16be ofppNone <>
      (putWord16be $ let overlapFlag = if overlapAllowed then 0 else 2 
                         removeFlag  = if notifyWhenRemoved then 1 else 0
                     in overlapFlag .|. removeFlag) <>
      (putActions $ actionSequenceToList actions)
    
    (AddEmergencyFlow {..}) ->
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' actions) xid <>
      putMatch match <>
      putWord64be cookie <>
      putWord16be ofpfcAdd <>
      putWord32be 0 <>
      putWord16be priority <>
      putWord32be (-1) <>
      putWord16be ofppNone <>
      (putWord16be $ let emergencyFlag = 4 
                         overlapFlag = if overlapAllowed then 0 else 2
                     in emergencyFlag .|. overlapFlag) <>
      (putActions $ actionSequenceToList actions)

    (ModifyFlows {..}) ->
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' newActions) xid <>
      putMatch match <>
      putWord64be ifMissingCookie <>
      (putWord16be $ flowModTypeToCode FlowModifyType) <>
      (putWord16be $ timeOutToCode ifMissingIdleTimeOut) <>
      (putWord16be $ timeOutToCode ifMissingHardTimeOut) <>
      putWord16be ifMissingPriority <>
      putWord32be (-1) <>
      putWord16be ofppNone <>
      (putWord16be $ let overlapFlag = if ifMissingOverlapAllowed then 0 else 2 
                         removeFlag  = if ifMissingNotifyWhenRemoved then 1 else 0
                     in overlapFlag .|. removeFlag) <>
      (putActions $ actionSequenceToList newActions)
            
    (ModifyFlowStrict {..}) ->
      putHeaderInternal ofptFlowMod (fromIntegral $ flowModSizeInBytes' newActions) xid <>
      putMatch match <>
      putWord64be ifMissingCookie <>
      (putWord16be $ flowModTypeToCode FlowModifyStrictType) <>
      (putWord16be $ timeOutToCode ifMissingIdleTimeOut) <>
      (putWord16be $ timeOutToCode ifMissingHardTimeOut) <>
      putWord16be priority <>
      putWord32be (-1) <>
      putWord16be ofppNone <>
      (putWord16be $ let overlapFlag = if ifMissingOverlapAllowed then 0 else 2 
                         removeFlag  = if ifMissingNotifyWhenRemoved then 1 else 0
                     in overlapFlag .|. removeFlag) <>
      (putActions $ actionSequenceToList newActions)

(<>) :: Put -> Put -> Put
x <> y = x >> y

mconcat :: [Put] -> Put
mconcat = sequence_

putActions :: [Action] -> Put
putActions = mapM_ putAction

getBufferID :: Get (Maybe BufferID)
getBufferID = do w <- getWord32be
                 if w == -1
                   then return Nothing
                   else return (Just w)
                        
getOutPort :: Get (Maybe PseudoPort)                        
getOutPort = do w <- getWord16be
                if w == ofppNone
                  then return Nothing
                  else return (Just (code2FakePort w))


getFlowModInternal :: Int -> Get FlowModRecordInternal
getFlowModInternal len = 
  do match       <- getMatch
     cookie      <- getWord64be 
     modType     <- getFlowModType
     idleTimeOut <- getTimeOutFromCode 
     hardTimeOut <- getTimeOutFromCode 
     priority    <- getWord16be 
     mBufferID   <- getBufferID
     outPort     <- getOutPort
     flags       <- getFlowModFlags
     let bytesInActionList = len - 72
     actions <- getActionsOfSize (fromIntegral bytesInActionList)
     return $ FlowModRecordInternal { command'     = modType
                                    , match'       = match 
                                    , actions'     = actions
                                    , priority'    = priority
                                    , idleTimeOut' = idleTimeOut
                                    , hardTimeOut' = hardTimeOut
                                    , flags'       = flags
                                    , bufferID'    = mBufferID
                                    , outPort'     = outPort
                                    , cookie'      = cookie
                                    } 

       
getFlowMod :: Int -> Get FlowMod
getFlowMod len = getFlowModInternal len >>= return . flowModInternal2FlowMod

--fromJust2 :: String -> Maybe a -> a
--fromJust2 s Nothing = error s
--fromJust2 _ (Just a) = a

fromJust :: Maybe a -> a
fromJust Nothing = error "MessagesBinary.fromJust"
fromJust (Just a) = a

flowModInternal2FlowMod :: FlowModRecordInternal -> FlowMod 
flowModInternal2FlowMod (FlowModRecordInternal {..}) = 
  case command' of 
    FlowDeleteType -> DeleteFlows { match = match', outPort = outPort' }
    FlowDeleteStrictType -> DeleteFlowStrict { match = match', outPort = outPort', priority = priority' }
    FlowAddType -> 
      if elem Emergency flags'
      then AddEmergencyFlow { match = match'
                            , priority = priority'
                            , actions  = ActionSequence (error "size unknown") actions'
                            , cookie   = cookie'
                            , overlapAllowed = elem CheckOverlap flags'
                            }
      else AddFlow { match = match'
                   , priority = priority'
                   , actions = ActionSequence (error "size unknown") actions'
                   , cookie = cookie'
                   , idleTimeOut = fromJust idleTimeOut'
                   , hardTimeOut = fromJust hardTimeOut'
                   , notifyWhenRemoved = elem SendFlowRemoved flags'
                   , applyToPacket     = bufferID'
                   , overlapAllowed    = elem CheckOverlap flags'
                   }
    FlowModifyType -> ModifyFlows { match = match'
                                  , newActions = ActionSequence (error "size unknown") actions'
                                  , ifMissingPriority = priority'
                                  , ifMissingCookie   = cookie'
                                  , ifMissingIdleTimeOut = fromJust idleTimeOut'
                                  , ifMissingHardTimeOut = fromJust hardTimeOut'
                                  , ifMissingOverlapAllowed    = CheckOverlap `elem` flags'
                                  , ifMissingNotifyWhenRemoved = SendFlowRemoved `elem` flags'
                                  } 
    FlowModifyStrictType -> ModifyFlowStrict { match = match'
                                             , newActions = ActionSequence (error "size unknown") actions'
                                             , priority = priority'
                                             , ifMissingCookie   = cookie'
                                             , ifMissingIdleTimeOut = fromJust idleTimeOut'
                                             , ifMissingHardTimeOut = fromJust hardTimeOut'
                                             , ifMissingOverlapAllowed    = CheckOverlap `elem` flags'
                                             , ifMissingNotifyWhenRemoved = SendFlowRemoved `elem` flags'
                                             } 

timeOutToCode :: TimeOut -> Word16
timeOutToCode Permanent = 0
timeOutToCode (ExpireAfter t) = t

getTimeOutFromCode :: Get (Maybe TimeOut)
getTimeOutFromCode = do code <- getWord16be
                        if code == 0
                          then return Nothing
                          else return (Just (ExpireAfter code))

flowModFlagToBitMaskBijection :: [(FlowModFlag,Word16)]
flowModFlagToBitMaskBijection = [(SendFlowRemoved, shiftL 1 0), 
                                 (CheckOverlap,    shiftL 1 1), 
                                 (Emergency,       shiftL 1 2) ]
                                
bitMap2FlagSet :: Word16 -> [FlowModFlag]
bitMap2FlagSet w = [ flag | (flag,mask) <- flowModFlagToBitMaskBijection, mask .&. w /= 0 ]

getFlowModFlags :: Get [FlowModFlag]
getFlowModFlags = do w <- getWord16be
                     return (bitMap2FlagSet w)



ofpfcAdd, ofpfcModify, ofpfcModifyStrict, ofpfcDelete, ofpfcDeleteStrict :: Word16
ofpfcAdd          = 0
ofpfcModify       = 1
ofpfcModifyStrict = 2
ofpfcDelete       = 3
ofpfcDeleteStrict = 4
  
flowModTypeBimap :: Bimap FlowModType Word16
flowModTypeBimap =
    Bimap.fromList [
              (FlowAddType, ofpfcAdd),
              (FlowModifyType, ofpfcModify),
              (FlowModifyStrictType, ofpfcModifyStrict),
              (FlowDeleteType, ofpfcDelete),
              (FlowDeleteStrictType, ofpfcDeleteStrict)
             ]

getFlowModType :: Get FlowModType
getFlowModType = do code <- getWord16be
                    return (flowModTypeBimap !> code)

flowModTypeToCode :: FlowModType -> Word16
flowModTypeToCode !FlowAddType = ofpfcAdd
flowModTypeToCode !FlowModifyType = ofpfcModify
flowModTypeToCode !FlowModifyStrictType = ofpfcModifyStrict
flowModTypeToCode !FlowDeleteType = ofpfcDelete
flowModTypeToCode !FlowDeleteStrictType = ofpfcDeleteStrict

putAction :: Action -> Put
putAction !act = 
  case act of 
    (SendOutPort !port) -> 
      putWord32be 8 >> -- replaces putWord16be 0 >> putWord16be 8
      putPseudoPort port
    (SetVlanVID vlanid) -> 
      putWord16be 1 >>
      putWord16be 8 >>
      putWord16be vlanid >>
      putWord16be 0
    (SetVlanPriority priority) -> 
      putWord16be 2 >>
      putWord16be 8 >>
      putWord8 priority >>
      putWord8 0 >>
      putWord8 0 >>
      putWord8 0
    (StripVlanHeader) -> 
      putWord16be 3 >>
      putWord16be 8 >>
      putWord32be 0
    (SetEthSrcAddr addr) -> 
      putWord16be 4 >>
      putWord16be 16 >>
      putEthernetAddress addr >>
      sequence_ (replicate 6 (putWord8 0))
    (SetEthDstAddr addr) -> 
      putWord16be 5 >>
      putWord16be 16 >>
      putEthernetAddress addr >>
      sequence_ (replicate 6 (putWord8 0))
    (SetIPSrcAddr addr) -> 
      putWord16be 6 >>
      putWord16be 8 >>
      putWord32be (ipAddressToWord32 addr)
    (SetIPDstAddr addr) -> 
      putWord16be 7 >>
      putWord16be 8 >>
      putWord32be (ipAddressToWord32 addr)
    (SetIPToS tos) -> 
      putWord16be 8 >>
      putWord16be 8 >>
      putWord8 tos >>
      sequence_ (replicate 3 (putWord8 0))
    (SetTransportSrcPort port) -> 
      putWord16be 9 >>
      putWord16be 8 >>
      putWord16be port >>
      putWord16be 0
    (SetTransportDstPort port) -> 
      putWord16be 10 >>
      putWord16be 8 >>
      putWord16be port >>
      putWord16be 0
    (Enqueue port qid) ->
      putWord16be 11 >>
      putWord16be 16 >>
      putWord16be port >>
      sequence_ (replicate 6 (putWord8 0)) >>
      putWord32be qid
    (VendorAction vendorID bytes) -> 
      let !l = 2 + 2 + 4 + length bytes
      in if (l `mod` 8 /= 0) 
         then error "Vendor action must have enough data to make the action length a multiple of 8 bytes"
         else putWord16be 0xffff >>
              putWord16be (fromIntegral l) >>
              putWord32be vendorID >>
              mapM_ putWord8 bytes

putPseudoPort :: PseudoPort -> Put
putPseudoPort (PhysicalPort !pid) = 
 putWord16be pid >>
 putWord16be 0
putPseudoPort (ToController !maxLen) = 
 putWord16be ofppController >>
 putWord16be maxLen
putPseudoPort !port = 
 putWord16be (fakePort2Code port) >>
 putWord16be 0
           
actionSizeInBytes :: Action -> Int
actionSizeInBytes (!SendOutPort _)     = 8
actionSizeInBytes (!SetVlanVID _)      = 8
actionSizeInBytes (!SetVlanPriority _) = 8
actionSizeInBytes (!StripVlanHeader)   = 8
actionSizeInBytes (!SetEthSrcAddr _)   = 16
actionSizeInBytes (!SetEthDstAddr _)   = 16
actionSizeInBytes (!SetIPSrcAddr _)    = 8
actionSizeInBytes (!SetIPDstAddr _)    = 8
actionSizeInBytes (!SetIPToS _)        = 8    
actionSizeInBytes (!SetTransportSrcPort _)    = 8
actionSizeInBytes (!SetTransportDstPort _)    = 8
actionSizeInBytes (!Enqueue _ _) = 16    
actionSizeInBytes (!VendorAction _ bytes) =
  let l = length bytes + 8 -- + 2 + 2 + 4 
  in if l `mod` 8 /= 0 
     then error "Vendor action must have enough data to make the action length a multiple of 8 bytes"
     else l
{-# INLINE actionSizeInBytes #-}


------------------------------------------
-- Port mod unparser
------------------------------------------

portModLength :: Int
portModLength = 32

putPortMod :: PortMod -> Put
putPortMod (PortModRecord {..} ) = 
 putWord16be portNumber <>
 putEthernetAddress hwAddr <>
 putConfigBitMap <>
 putMaskBitMap <>
 putAdvertiseBitMap <>
 putPad
    where putConfigBitMap    = putWord32be (portAttributeSet2BitMask onAttrs)
          putMaskBitMap      = putWord32be (portAttributeSet2BitMask attrsChanging)
          putAdvertiseBitMap = putWord32be 0
          putPad             = putWord32be 0
          attrsChanging      = List.union onAttrs offAttrs
          onAttrs = Map.keys $ Map.filter (==True) attributesToSet
          offAttrs = Map.keys $ Map.filter (==False) attributesToSet


----------------------------------------
-- Stats requests unparser
----------------------------------------
          
statsRequestSize :: StatsRequest -> Int
statsRequestSize (FlowStatsRequest _ _ _) = headerSize + 2 + 2 + matchSize + 1 + 1 + 2
statsRequestSize (PortStatsRequest _)     = headerSize + 2 + 2 + 2 + 6
statsRequestSize (DescriptionRequest)     = headerSize + 2 + 2
statsRequestSize req = error ("Size of " ++ show req ++ " not yet implemented.")


putStatsRequestBody :: StatsRequest -> Put 
putStatsRequestBody (FlowStatsRequest match tableQuery mPort) = 
    putWord16be ofpstFlow >>
    putWord16be 0 >>
    putMatch match >>
    putWord8 (tableQueryToCode tableQuery) >>
    putWord8 0 >>
    (putWord16be $ maybe ofppNone fakePort2Code mPort)
putStatsRequestBody (AggregateFlowStatsRequest match tableQuery mPort) = 
  putWord16be ofpstAggregate >>
  putWord16be 0 >>
  putMatch match >>
  putWord8 (tableQueryToCode tableQuery) >>
  putWord8 0 >>
  (putWord16be $ maybe ofppNone fakePort2Code mPort)
putStatsRequestBody TableStatsRequest = 
  putWord16be ofpstTable >> 
  putWord16be 0
putStatsRequestBody DescriptionRequest = 
  putWord16be ofpstDesc >>
  putWord16be 0
putStatsRequestBody (QueueStatsRequest portQuery queueQuery) = 
  putWord16be ofpstQueue >>
  putWord16be 0 >>
  putWord16be (queryToPortNumber portQuery) >>
  putWord16be 0 >>
  putWord32be (queryToQueueID queueQuery)
putStatsRequestBody (PortStatsRequest query) = 
 putWord16be ofpstPort >>
 putWord16be 0 >>
 putWord16be (queryToPortNumber query) >>
 sequence_ (replicate 6 (putWord8 0))
                      
queryToPortNumber :: PortQuery -> Word16
queryToPortNumber AllPorts       = ofppNone
queryToPortNumber (SinglePort p) = p

queryToQueueID :: QueueQuery -> QueueID
queryToQueueID AllQueues       = 0xffffffff
queryToQueueID (SingleQueue q) = q

-- Not yet used: ofppMax :: Word16
-- ofppMax = 0xff00

ofppInPort, ofppTable, ofppNormal, ofppFlood, ofppAll, ofppController, ofppNone :: Word16
ofppInPort     = 0xfff8
ofppTable      = 0xfff9
ofppNormal     = 0xfffa
ofppFlood      = 0xfffb
ofppAll        = 0xfffc
ofppController = 0xfffd
-- Not yet used: ofppLocal      = 0xfffe
ofppNone       = 0xffff

fakePort2Code :: PseudoPort -> Word16
fakePort2Code Flood                 = ofppFlood
fakePort2Code (PhysicalPort portID) = portID
fakePort2Code InPort                = ofppInPort
fakePort2Code AllPhysicalPorts      = ofppAll
fakePort2Code (ToController _)      = ofppController
fakePort2Code NormalSwitching       = ofppNormal
fakePort2Code WithTable             = ofppTable

code2FakePort :: Word16 -> PseudoPort
code2FakePort w 
  | w <= 0xff00         = PhysicalPort w
  | w == ofppInPort     = InPort
  | w == ofppFlood      = Flood
  | w == ofppAll        = AllPhysicalPorts
  | w == ofppController = ToController 0
  | w == ofppNormal     = NormalSwitching
  | w == ofppTable      = WithTable
  | otherwise           = error ("unknown pseudo port number: " ++ show w)

tableQueryToCode :: TableQuery -> Word8
tableQueryToCode AllTables      = 0xff
tableQueryToCode EmergencyTable = 0xfe
tableQueryToCode (Table t)      = t

ofpstDesc, ofpstFlow, ofpstAggregate, ofpstTable, ofpstPort, ofpstQueue :: Word16
ofpstDesc      = 0
ofpstFlow      = 1
ofpstAggregate = 2
ofpstTable     = 3
ofpstPort      = 4
ofpstQueue     = 5
-- Not yet used: ofpstVendor    = 0xffff 



---------------------------------------------
-- Parser and Unparser for Match
---------------------------------------------
matchSize :: Int
matchSize = 40


getMatch :: Get Match
getMatch = do 
  wcards      <- getWord32be 
  inport      <- getWord16be
  srcEthAddr  <- getEthernetAddress
  dstEthAddr  <- getEthernetAddress
  dl_vlan     <- getWord16be
  dl_vlan_pcp <- getWord8
  skip 1
  dl_type     <- getWord16be
  nw_tos      <- getWord8
  nw_proto    <- getWord8
  skip 2
  nw_src <- getWord32be
  nw_dst <- getWord32be
  tp_src <- getWord16be
  tp_dst <- getWord16be
  return $ ofpMatch2Match $ OFPMatch wcards inport srcEthAddr dstEthAddr dl_vlan dl_vlan_pcp dl_type nw_tos nw_proto nw_src nw_dst tp_src tp_dst

putMatch :: Match -> Put
putMatch (Match inPort (MatchHeader {..}) (MatchBody {..})) = 
     putWord32be wildcards 
  >> (putWord16be $ maybe 0 id inPort)
  >> (putEthernetAddress $ maybe nullEthAddr id srcEthAddress )
  >> (putEthernetAddress $ maybe nullEthAddr id dstEthAddress )
  >> (putWord16be $ maybe 0 id vLANID )
  >> (putWord8 $ maybe 0 id vLANPriority )
  >> putWord8 0  -- padding
  >> (putWord16be $ maybe 0 id ethFrameType) 
  >> (putWord8 $ maybe 0 id ipTypeOfService )
  >> (putWord8 $ maybe 0 id matchIPProtocol )
  >> putWord16be 0 -- padding
  >> (putWord32be $ ipAddressToWord32 $ addressPart srcIPAddress )
  >> (putWord32be $ ipAddressToWord32 $ addressPart dstIPAddress )
  >> (putWord16be $ maybe 0 id srcTransportPort )
  >> (putWord16be $ maybe 0 id dstTransportPort )
  where nullEthAddr = ethernetAddress64 0
        wildcards   = 
          shiftL (fromIntegral numIgnoredBitsSrc) 8 .|. 
          shiftL (fromIntegral numIgnoredBitsDst) 14 .|.
          (maybe (flip setBit 0) (const id) inPort $
           maybe (flip setBit 1) (const id) vLANID $
           maybe (flip setBit 2) (const id) srcEthAddress $
           maybe (flip setBit 3) (const id) dstEthAddress $
           maybe (flip setBit 4) (const id) ethFrameType $
           maybe (flip setBit 5) (const id) matchIPProtocol $
           maybe (flip setBit 6) (const id) srcTransportPort $
           maybe (flip setBit 7) (const id) dstTransportPort $
           maybe (flip setBit 20) (const id) vLANPriority $
           maybe (flip setBit 21) (const id) ipTypeOfService $
           0
          )
        numIgnoredBitsSrc = 32 - (prefixLength srcIPAddress) 
        numIgnoredBitsDst = 32 - (prefixLength dstIPAddress)



data OFPMatch = OFPMatch { ofpm_wildcards           :: !Word32, 
                           ofpm_in_port             :: !Word16, 
                           ofpm_dl_src, ofpm_dl_dst :: !EthernetAddress, 
                           ofpm_dl_vlan             :: !Word16,
                           ofpm_dl_vlan_pcp         :: !Word8,
                           ofpm_dl_type             :: !Word16,
                           ofpm_nw_tos              :: !Word8,
                           ofpm_nw_proto            :: !Word8,
                           ofpm_nw_src, ofpm_nw_dst :: !Word32,
                           ofpm_tp_src, ofpm_tp_dst :: !Word16 
                         } deriving (Show,Eq,Generic,NFData)

ofpMatch2Match :: OFPMatch -> Match
ofpMatch2Match ofpm = Match
                      (getField 0 ofpm_in_port)
                      (MatchHeader
                       (getField 2 ofpm_dl_src)
                       (getField 3 ofpm_dl_dst)
                       (getField 1 ofpm_dl_vlan)
                       (getField 20 ofpm_dl_vlan_pcp)
                       (getField 4 ofpm_dl_type))
                      (MatchBody
                       (getField 21 ofpm_nw_tos)
                       (getField 5 ofpm_nw_proto)
                       (IPAddress (ofpm_nw_src ofpm) // src_prefix_len)
                       (IPAddress (ofpm_nw_dst ofpm) // dst_prefix_len)
                       (getField 6 ofpm_tp_src)
                       (getField 7 ofpm_tp_dst))
    where getField :: Int -> (OFPMatch -> a) -> Maybe a
          getField wcindex getter = if testBit (ofpm_wildcards ofpm) wcindex
                                    then Nothing
                                    else Just (getter ofpm)
          nw_src_shift       = 8
          nw_dst_shift       = 14
          nw_src_mask        = shiftL ((shiftL 1 6) - 1) nw_src_shift
          nw_dst_mask        = shiftL ((shiftL 1 6) - 1) nw_dst_shift
          nw_src_num_ignored = fromIntegral (shiftR (ofpm_wildcards ofpm .&. nw_src_mask) nw_src_shift)
          nw_dst_num_ignored = fromIntegral (shiftR (ofpm_wildcards ofpm .&. nw_dst_mask) nw_dst_shift)
          src_prefix_len     = 32 - min 32 nw_src_num_ignored
          dst_prefix_len     = 32 - min 32 nw_dst_num_ignored


-----------------------------------
-- Utilities
-----------------------------------
getWord8s :: Int -> Get [Word8]
getWord8s n = B.unpack <$> getByteString n

putWord8s :: [Word8] -> Put
putWord8s bytes = sequence_ [putWord8 b | b <- bytes]
