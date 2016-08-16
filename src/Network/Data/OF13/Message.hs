{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OF13.Message (
  Message(..)
  , XID
  , TableID
  , ErrorType(..)
  , BadRequestError(..)
  , SwitchCapability(..)
  , ConfigFlag(..)
  , Action(..) 
  , Match(..)
  , OXM(..)
  , OXMOFField(..)
  , Instruction(..)
  , PortID
  , Priority
  , oFPP_CONTROLLER
  , Group(..)
  , GroupID
  , ActionList
  , FailoverBucket(..)
  , BucketWeight
  , oFPG_MAX
  , oFPG_ALL
  , oFPG_ANY
  , MeterID
  , MPLSLabel
  , IPv6FlowLabel
  , IPv6Address
  , STCPPort
  , UDPPort
  , TCPPort
  , VLANMatch
  , QueueID
  , Header
  , TableFeature(..)
  , MultipartMessage(..)
  , Port(..)
  , PortFeature(..)
  , PortConfigFlag(..)
  , PortStats(..)
  , PortStateChangeReason(..)
  , Timeout
  , Cookie
  , TableStats(..)
  , TableProperty(..)
  , FlowRemovedReason(..)
  , SwitchID
  , Len
  , BadMatchError(..)
  , BadInstructionError(..)
  , BadGroupModError(..)
  , PacketInReason(..)
  , KiloBitsPerSecond
  , PortStateFlag
  , isPortDown
  , isPortUp
  ) where

import Network.Data.Ethernet hiding
  (getEthernetAddress, putEthernetAddress)
import Network.Data.IPv4.IPAddress hiding (getIPAddress, putIPAddress)

import Control.Exception hiding (mask)
import Control.Monad
import Data.Bimap (Bimap)
import qualified Data.Bimap as Bimap
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Maybe (fromJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Map (Map)
import qualified Data.Map as Map
-- import qualified Debug.Trace as Debug
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)


data Message = Hello       { xid :: XID, len :: Len }
             | EchoRequest { xid :: XID, body :: B.ByteString }
             | EchoReply   { xid :: XID, body :: B.ByteString }
             | Error       { xid       :: XID
                           , body      :: B.ByteString 
                           , errorType :: ErrorType
                           , errorCode :: Word16
                           }
             | FeatureRequest { xid :: XID }
             | FeatureReply { xid          :: XID
                            , sid          :: SwitchID
                            , numBuffers   :: Word32
                            , numTables    :: Word8
                            , auxID        :: Word8
                            , capabilities :: Set SwitchCapability
                            }
             | ConfigRequest { xid :: XID }
             | ConfigReply { xid         :: XID
                           , configFlags :: Set ConfigFlag
                           , missSendLen :: Word16
                           }
             | ConfigSet { xid         :: XID
                         , configFlags :: Set ConfigFlag
                         , missSendLen :: Word16
                         }
             | PacketIn { xid      :: XID 
                        , bufferID :: Maybe Word32
                        , totalLen :: Word16
                        , reason   :: PacketInReason
                        , tableID  :: TableID
                        , cookie   :: Cookie
                        , match    :: Match
                        , payload  :: B.ByteString
                        }
             | FlowRemoved { xid               :: XID
                           , cookie            :: Cookie
                           , priority          :: Priority
                           , flowRemovedReason :: FlowRemovedReason
                           , tableID           :: TableID
                           , duration_sec      :: Word32
                           , duration_nsec     :: Word32
                           , idleTimeout       :: Timeout
                           , hardTimeout       :: Timeout
                           , packetCount       :: Word64
                           , byteCount         :: Word64
                           , match             :: Match
                           }
             | PortStatus { xid :: XID
                          , portStateChangeReason :: PortStateChangeReason
                          , port :: Port
                          } 
             | PacketOut { xid               :: XID
                         , packetOutBufferID :: Maybe Word32
                         , inPort            :: Maybe PortID
                         , actions           :: [Action]
                         , payload           :: B.ByteString
                         } 
             | AddFlow { xid             :: XID
                       , cookie          :: Cookie
                       , tableID         :: TableID
                       , idleTimeout     :: Timeout
                       , hardTimeout     :: Timeout
                       , priority        :: Priority
                       , bufferID        :: Maybe Word32
                       , sendFlowRemoved :: Bool
                       , checkOverlap    :: Bool
                       , countPackets    :: Bool
                       , countBytes      :: Bool
                       , match           :: Match
                       , instructions    :: [Instruction]
                       }
             | DeleteFlowStrict { xid      :: XID
                                , cookie   :: Cookie
                                , tableID  :: TableID
                                , priority :: Priority
                                , outPort  :: Maybe PortID
                                , outGroup :: Maybe GroupID
                                , match    :: Match
                                }
             | DeleteFlow { xid           :: XID
                          , cookie        :: Cookie
                          , cookieMask    :: Cookie
                          , maybeTableID  :: Maybe TableID
                          , priority      :: Priority
                          , outPort       :: Maybe PortID
                          , outGroup      :: Maybe GroupID
                          , match         :: Match
                          }
             | ModifyFlowStrict { xid           :: XID
                                , cookie        :: Cookie
                                , tableID       :: TableID
                                , priority      :: Priority
                                , match         :: Match
                                , resetCounters :: Bool
                                , instructions  :: [Instruction]
                                }
             | ModifyFlow { xid           :: XID
                          , cookie        :: Cookie
                          , cookieMask    :: Cookie
                          , tableID       :: TableID
                          , match         :: Match
                          , resetCounters :: Bool
                          , instructions  :: [Instruction]
                          }
             | AddGroup { xid     :: XID
                        , group   :: Group
                        , groupID :: GroupID
                        }
             | ModifyGroup { xid     :: XID
                           , group   :: Group
                           , groupID :: GroupID
                           }
             | DeleteGroup { xid :: XID
                           , groupID :: GroupID
                           }
             | PortMod { xid :: XID
                       , portID :: PortID
                       , hwAddr :: EthernetAddress
                       , portModConfig :: Map PortConfigFlag Bool
                       , portModAdvertised ::  Set PortFeature
                       }
             | RequestSwitchDesc  { xid :: XID }               
             | RequestTableStats { xid :: XID }
             | RequestPortStats { xid    :: XID
                                , portID :: PortID 
                                }
             | RequestTableFeatures { xid :: XID
                                    , tableFeatures :: [TableFeature]
                                    }
             | RequestPorts { xid :: XID }
             | RequestGroups { xid :: XID }
             | MultipartReply { xid              :: XID
                              , moreToCome       :: Bool
                              , multipartMessage :: MultipartMessage
                              }
             | BarrierRequest { xid :: XID }
             | BarrierReply { xid :: XID }
             | Undefined Header
      deriving (Show,Eq,Generic,NFData)

type MultipartTypeCode = Word16

oFPMP_TABLE_FEATURES :: MultipartTypeCode
oFPMP_TABLE_FEATURES = 12

data TableFeature = TableFeature { tableFeatureTableID :: TableID
                                 , tableName :: String   -- len <= 32
                                 , metadataMatch :: Word64
                                 , metadataWrite :: Word64
                                 , maxEntries :: Int
                                 , tableProperties :: [TableProperty]
                                 } deriving (Eq,Show,Ord,Generic,NFData)

data TableProperty = NoTableProperty --InstructionsProperty { }
                   deriving (Show,Eq,Ord,Generic,NFData)

type Timeout = Word16
type TableID = Word8
type Priority = Word16

data Instruction = GotoTable TableID
                 | WriteMetadata { metadata :: Word64, metadataMask :: Word64 }
                 | WriteActions [Action]
                 | ApplyActions [Action]
                 | ClearActions
                 | Meter MeterID
                 deriving (Show,Eq,Generic,NFData)

type MeterID = Word32

oFPP_CONTROLLER, oFPP_ANY :: PortID
oFPP_CONTROLLER = 0xfffffffd
oFPP_ANY = 0xffffffff

oFPG_MAX, oFPG_ALL, oFPG_ANY :: GroupID
oFPG_MAX = 0xffffff00
oFPG_ALL = 0xfffffffc
oFPG_ANY = 0xffffffff

type ActionList = [Action]

data Group =
  All { buckets :: [ActionList] }
  | Select { weightedBuckets :: [(BucketWeight, ActionList)] }
  | Indirect { bucket :: ActionList }
  | FastFailover { failoverBuckets :: [FailoverBucket] }
  deriving (Eq,Show,Ord,Generic,NFData)

type BucketWeight = Word16
data FailoverBucket = FailoverBucket { bucketActions :: ActionList
                                     , watchPort :: PortID
                                     , watchGroup :: GroupID
                                     }
                    deriving (Eq,Ord,Show,Generic,NFData)

type GenericBucket = (BucketWeight, PortID, GroupID, ActionList)

genericBuckets :: Group -> [GenericBucket]
genericBuckets (All {buckets}) = [(0, oFPP_ANY, oFPG_ANY, b) | b <- buckets ]
genericBuckets (Select { weightedBuckets }) =
  [(w, oFPP_ANY, oFPG_ANY, b) | (w,b) <- weightedBuckets ]
genericBuckets (Indirect { bucket }) = [(0, oFPP_ANY, oFPG_ANY, bucket)]
genericBuckets (FastFailover { failoverBuckets })
  = [(0, watchPort, watchGroup, bucketActions)
    | FailoverBucket {..} <- failoverBuckets ]


gROUP_TYPE_ALL,gROUP_TYPE_SELECT,gROUP_TYPE_INDIRECT,gROUP_TYPE_FF :: Word8
gROUP_TYPE_ALL = 0
gROUP_TYPE_SELECT = 1
gROUP_TYPE_INDIRECT = 2
gROUP_TYPE_FF = 3

groupTypeCode :: Group -> Word8
groupTypeCode (All {})          = gROUP_TYPE_ALL
groupTypeCode (Select {})       = gROUP_TYPE_SELECT
groupTypeCode (Indirect {})     = gROUP_TYPE_INDIRECT
groupTypeCode (FastFailover {}) = gROUP_TYPE_FF

bucketsToGroup :: Word8 -> [GenericBucket] -> Group
bucketsToGroup t bkts = case t of
  _ | t == gROUP_TYPE_ALL -> All [ al | (_,_,_,al) <- bkts ]
  _ | t == gROUP_TYPE_SELECT -> Select [ (w,al) | (w,_,_,al) <- bkts ]
  _ | t == gROUP_TYPE_INDIRECT -> case bkts of
    [(_,_,_,al)] -> Indirect al
    _ -> error ("bucketsToGroup: Bad indirect group with buckets " ++ show bkts)
  _ | t == gROUP_TYPE_FF ->
    FastFailover [ FailoverBucket { bucketActions = bucketActions
                                  , watchPort = watchPort
                                  , watchGroup = watchGroup
                                  }
                 | (_,watchPort, watchGroup, bucketActions) <- bkts ]
  _ -> error ("bucketsToGroup: unknown group type code: " ++ show t)

-- TODO: Add SetField, PushPBB, PopPBB, Experimenter actions.
data Action = Output { outputPortID :: PortID
                     , maxLengthToController :: Maybe Word16
                     } 
            | CopyTTLOut
            | CopyTTLIn
            | SetMPLSTTL Word8
            | DecMPLSTTL
            | PushVLAN Word16
            | PopVLAN
            | PushMPLS Word16
            | PopMPLS Word16
            | SetQueue QueueID
            | SetGroup GroupID
            | SetNetworkTTL Word8
            | DecNetworkTTL
            | SetNiciraRegister Int Word32
            | SetField OXM
            deriving (Eq,Ord,Show,Generic,NFData)

type QueueID = Word32
type GroupID = Word32

data MultipartMessage = PortDesc [Port]
                      | SwitchDesc { mfrDesc :: String 
                                   , hw_desc :: String
                                   , sw_desc :: String
                                   , serial_num :: String
                                   , dp_desc :: String
                                   }
                      | AllTableStats [TableStats]
                      | AllPortStats [PortStats]
                      | GroupDesc [(GroupID, Group)]
                      deriving (Eq, Show,Generic,NFData)


data PortStats = PortStats { statsPortID :: PortID
                           , rxPackets :: Int
                           , txPackets :: Int
                           , rxBytes :: Int
                           , txBytes :: Int
                           , rxDropped :: Int
                           , txDropped :: Int
                           , rxErrors :: Int
                           , txErrors :: Int
                           , rxFrameErrors :: Int
                           , rxOverErrors :: Int
                           , rxCRCErrors :: Int
                           , collisions :: Int
                           , portDurationSec :: Int
                           , portDurationNanoSec :: Int
                           } deriving (Eq,Ord,Show,Generic,NFData)

data TableStats = TableStats { statsTableID :: Word8
                             , activeCount :: Int
                             , lookupCount :: Int
                             , matchedCount :: Int
                             } 
                deriving (Eq,Ord,Show,Generic,NFData)

type Header = (Word8, Word8, Len, XID)
type XID = Word32
type Len = Word16
type SwitchID = Word64
type Cookie = Word64
type PortID = Word32


data PortStateChangeReason = PortAdd
                           | PortDelete
                           | PortModify
                           deriving (Show,Eq,Ord,Enum,Generic,NFData)
                                    
data Port = Port { portNumber         :: PortID
                 , hwAddress          :: EthernetAddress
                 , portName           :: String
                 , portConfig         :: Set PortConfigFlag
                 , portState          :: Set PortStateFlag
                 , currentFeatures    :: Set PortFeature
                 , advertisedFeatures :: Set PortFeature
                 , supportedFeatures  :: Set PortFeature
                 , peerFeatures       :: Set PortFeature
                 , currentSpeed       :: KiloBitsPerSecond
                 , maxSpeed           :: KiloBitsPerSecond
                 } deriving (Show,Eq,Ord,Generic,NFData)

isPortDown :: Port -> Bool
isPortDown = Set.member PortDown . portConfig

isPortUp :: Port -> Bool
isPortUp = not . isPortDown

type KiloBitsPerSecond = Int

data PortFeature = HD10Mb 
                 | FD10Mb 
                 | HD100Mb 
                 | FD100Mb 
                 | HD1Gb 
                 | FD1Gb 
                 | FD10Gb 
                 | FD40Gb 
                 | FD100Gb 
                 | FD1Tb 
                 | OtherRate 
                 | Copper 
                 | Fiber 
                 | AutoNeg 
                 | Pause 
                 | PauseAsym
                 deriving (Eq,Ord,Enum,Show,Generic,NFData)

data PortConfigFlag = PortDown 
                    | NoRecv 
                    | NoFwd 
                    | NoPacketIn 
                    deriving (Eq,Ord,Enum,Show,Generic,NFData)

data PortStateFlag = LinkDown 
                   | Blocked 
                   | Live 
                   deriving (Eq,Ord,Enum,Show,Generic,NFData)

data FlowRemovedReason = IdleTimeout 
                       | HardTimeout 
                       | FlowDelete 
                       | GroupDelete 
                       deriving (Eq,Ord,Enum,Show,Generic,NFData)

data Match = MatchOXM { oxms :: [OXM] } 
           deriving (Eq,Ord,Show,Generic,NFData)

data OXM = OXMOther { oxmClass   :: Word16
                    , oxmField   :: Word8
                    , oxmHasMask :: Bool
                    , oxmBody    :: B.ByteString
                    }
         | InPort    { inPortID :: PortID }
         | InPhyPort { inPortID :: PortID }
         | Metadata  { oxmMetadata, oxmMetadataMask :: Word64
                     , oxmHasMask :: Bool }
         | EthDst { oxmEthDst, oxmEthDstMask :: EthernetAddress
                  , oxmHasMask :: Bool }
         | EthSrc { oxmEthSrc, oxmEthSrcMask :: EthernetAddress
                  , oxmHasMask :: Bool }
         | EthType { oxmEthType :: EthernetTypeCode }
         | IPv4Dst { oxmIPDst :: IPAddressPrefix }
         | IPv4Src { oxmIPSrc :: IPAddressPrefix }
         | NiciraRegister { oxmRegisterIndex :: Int, oxmRegisterValue :: Word32 }
         | OXM { oxmOFField :: OXMOFField
               , oxmHasMask :: Bool
               }
         deriving (Eq,Ord,Show,Generic,NFData)

oxmHasMask' :: OXM -> Bool
oxmHasMask' (InPort {}) = False
oxmHasMask' (InPhyPort {}) = False
oxmHasMask' (Metadata {oxmHasMask}) = oxmHasMask
oxmHasMask' (EthDst {oxmHasMask}) = oxmHasMask
oxmHasMask' (EthSrc {oxmHasMask}) = oxmHasMask
oxmHasMask' (EthType {}) = False
oxmHasMask' (IPv4Dst {oxmIPDst}) = not $ prefixIsExact oxmIPDst
oxmHasMask' (IPv4Src {oxmIPSrc}) = not $ prefixIsExact oxmIPSrc
oxmHasMask' (NiciraRegister {}) = False
oxmHasMask' (OXM {oxmHasMask}) = oxmHasMask
oxmHasMask' (OXMOther {oxmHasMask}) = oxmHasMask

data OXMOFField = VLANID VLANMatch
                | VLANPCP Word8
                | IPDSCP Word8
                | IPECN Word8
                | IPProto Word8
                | TCPSrc TCPPort
                | TCPDst TCPPort
                | UDPSrc UDPPort
                | UDPDst UDPPort
                | SCTPSrc STCPPort
                | SCTPDst STCPPort
                | ICMPv4_Type Word8
                | ICMPv4_Code Word8
                | ARP_OP Word16
                | ARP_SPA IPAddress IPAddress
                | ARP_TPA IPAddress IPAddress
                | ARP_SHA EthernetAddress EthernetAddress
                | ARP_THA EthernetAddress EthernetAddress
                | IPv6Src IPv6Address IPv6Address
                | IPv6Dst IPv6Address IPv6Address
                | IPv6_FLabel IPv6FlowLabel
                | ICMPv6_Type Word8
                | ICMPv6_Code Word8
                | IPv6_ND_Target IPv6Address
                | IPv6_ND_SLL EthernetAddress
                | IPv6_ND_TLL EthernetAddress
                | MPLS_Label MPLSLabel
                | MPLS_TC Word8
                | MPLS_BOS Word8
                | PBB_ISID Word32 Word32
                | TunnelID Word64 Word64
                | IPv6_EXTHDR Word16
                deriving (Eq,Ord,Show,Generic,NFData)

type TCPPort = Word16
type UDPPort = Word16
type STCPPort = Word16
type IPv6Address = B.ByteString
type IPv6FlowLabel = Word32
type MPLSLabel = Word32

data VLANMatch = Absent
               | Present (Maybe Word16)
               deriving (Eq,Ord,Show,Generic,NFData)

data PacketInReason = NoMatch 
                    | MatchedAction 
                    | InvalidTTL 
                    deriving (Eq,Ord,Enum,Show,Generic,NFData)

packetInReasonCodeMap :: Bimap PacketInReason Word8
packetInReasonCodeMap = 
  Bimap.fromList [ (NoMatch, 0)
                 , (MatchedAction, 1)
                 , (InvalidTTL, 2)
                 ]
                   
data ErrorType = HelloFailed
               | BadRequest BadRequestError
               | BadAction
               | BadInstruction BadInstructionError
               | BadMatch BadMatchError
               | FlowModFailed
               | GroupModFailed BadGroupModError
               | PortModFailed
               | TableModFailed
               | QueueOpFailed
               | SwitchConfigFailed
               | RoleRequestFailed
               | MeterModFailed
               | TableFeaturesFailed
               | ExperimenterError
               deriving (Eq,Ord,Show,Generic,NFData)

data BadRequestError = BadVersion 
                     | BadType
                     | BadMultipart
                     | BadExperimenter
                     | BadExpType
                     | BadPermission
                     | BadLen
                     | BufferEmpty
                     | BufferUnknown
                     | BadTableID
                     | IsSlave
                     | BadPort
                     | BadPacket
                     | MultipartBufferOverflow
                     deriving (Eq,Ord,Enum,Show,Generic,NFData)

badRequestCodeMap :: Bimap BadRequestError Word16
badRequestCodeMap = 
  Bimap.fromList [ (BadVersion ,0)
                 , (BadType,1)
                 , (BadMultipart,2)
                 , (BadExperimenter,3)
                 , (BadExpType,4)
                 , (BadPermission,5)
                 , (BadLen,6)
                 , (BufferEmpty,7)
                 , (BufferUnknown,8)
                 , (BadTableID,9)
                 , (IsSlave,10)
                 , (BadPort,11)
                 , (BadPacket,12)
                 , (MultipartBufferOverflow,13)
                 ]

data BadMatchError = BadMatchType
                   | BadMatchLength
                   | BadMatchTag
                   | BadMatchDLAddrMask
                   | BadMatchNWAddrMask
                   | BadWildcards
                   | BadMatchField
                   | BadMatchValue
                   | BadMatchMask
                   | BadMatchPrereq
                   | BadMatchDupField
                   | BadMatchPermissions
                   deriving (Eq,Ord,Enum,Show,Generic,NFData)

badMatchCodeMap :: Bimap BadMatchError Word16
badMatchCodeMap = 
  Bimap.fromList [ (BadMatchType,        0)
                 , (BadMatchLength,      1)
                 , (BadMatchTag,         2)
                 , (BadMatchDLAddrMask,  3)
                 , (BadMatchNWAddrMask,  4)
                 , (BadWildcards,        5)
                 , (BadMatchField,       6)
                 , (BadMatchValue,       7)
                 , (BadMatchMask,        8)
                 , (BadMatchPrereq,      9)
                 , (BadMatchDupField,   10)
                 , (BadMatchPermissions,11)
                 ]

data BadInstructionError = UnknownInstruction
                         | UnsupportedInstruction
                         | BadInstructionTableID
                         | UnsupportedMetadata
                         | UnsupportedMetadataMask
                         | BadExperimenterID
                         | BadExperimenterType
                         | BadInstructionLength
                         | BadInstructionPermission
                         deriving (Eq,Ord,Enum,Show,Generic,NFData)

badInstructionCodeMap :: Bimap BadInstructionError Word16
badInstructionCodeMap =
  Bimap.fromList [ (UnknownInstruction, 0)
                 , (UnsupportedInstruction, 1)
                 , (BadInstructionTableID, 2)
                 , (UnsupportedMetadata, 3)
                 , (UnsupportedMetadataMask, 4)
                 , (BadExperimenterID, 5)
                 , (BadExperimenterType, 6)
                 , (BadInstructionLength, 7)
                 , (BadInstructionPermission, 8)
                 ]

data BadGroupModError = GroupExistsError
                      | GroupInvalidError
                      | GroupUnsupportedWeight
                      | GroupTableFullError
                      | GroupBucketsFullError
                      | GroupChainsUnsupported
                      | GroupWatchUnsupported
                      | GroupWouldCauseLoop
                      | GroupDoesNotExist
                      | GroupReferencedByOtherGroup
                      | GroupBadType
                      | GroupBadCommand
                      | GroupBadBucket
                      | GroupBadWatch
                      | GroupPermissionError
                      deriving (Eq,Ord,Enum,Show,Generic,NFData)
                               
badGroupModCodeMap :: Bimap BadGroupModError Word16
badGroupModCodeMap =
  Bimap.fromList [ (GroupExistsError, 0)
                 , (GroupInvalidError, 1)
                 , (GroupUnsupportedWeight, 2)
                 , (GroupTableFullError, 3)
                 , (GroupBucketsFullError, 4)
                 , (GroupChainsUnsupported, 5)
                 , (GroupWatchUnsupported, 6)
                 , (GroupWouldCauseLoop, 7)
                 , (GroupDoesNotExist, 8)
                 , (GroupReferencedByOtherGroup, 9)
                 , (GroupBadType, 10)
                 , (GroupBadCommand, 11)
                 , (GroupBadBucket, 12)
                 , (GroupBadWatch, 13)
                 , (GroupPermissionError, 14)
                 ]

data ConfigFlag = FragNormal
                | FragDrop
                | FragReasm
                -- What is this? | FragMask
                deriving (Eq,Ord,Enum,Show,Generic,NFData)

data SwitchCapability = FlowStats 
                      | HasTableStats
                      | HasPortStats
                      | GroupStats
                      | IPReassembly
                      | QueueStats
                      | PortBlocked
                      deriving (Eq,Ord,Enum,Show,Generic,NFData)


configFlagsFields :: [(Int, ConfigFlag)]
configFlagsFields = [ (0,FragNormal)
                    , (1,FragDrop)
                    , (2,FragReasm)
                    ]

switchCapabilityFields :: [(Int, SwitchCapability)]
switchCapabilityFields = [ (0, FlowStats)
                         , (1, HasTableStats)
                         , (2, HasPortStats)
                         , (3, GroupStats)
                         , (5, IPReassembly)
                         , (6, QueueStats)
                         , (8, PortBlocked)
                         ]
  
instance Binary Message where
  get = do hdr <- getHeader
           getBody hdr

  put (Hello { xid }) = 
    putHeader hello_type_code len_header xid
  put (Error {xid, body}) = do
    putHeader error_type_code (numMessageBytes $ B.length body) xid
    () <- error "BROKEN"
    putByteString body
  put (EchoRequest {xid, body}) = do
    putHeader echo_request_type_code (numMessageBytes $ B.length body) xid
    putByteString body
  put (EchoReply {xid, body}) = do
    putHeader echo_reply_type_code (numMessageBytes $ B.length body) xid
    putByteString body
  put (FeatureRequest {xid}) =
    putHeader feature_request_type_code len_header xid
  put (FeatureReply {..}) = do
    putHeader feature_reply_type_code (len_header + 24) xid
    putWord64be sid
    putWord32be numBuffers
    putWord8 numTables
    putWord8 auxID
    putWord16be 0
    putWord32be $ setToBitSet switchCapabilityFields capabilities
    putWord32be 0
  put (ConfigRequest {xid}) =
    putHeader config_request_type_code len_header xid
  put (ConfigReply {..}) = do
    putHeader config_reply_type_code (len_header + 4) xid
    putWord16be $ setToBitSet configFlagsFields configFlags
    putWord16be missSendLen
  put (ConfigSet {..}) = do
    putHeader config_set_type_code (len_header + 4) xid
    putWord16be $ setToBitSet configFlagsFields configFlags
    putWord16be missSendLen
  put (RequestTableFeatures {..}) = do
    putHeader multipart_request_type_code (len_header + 8) xid
    putWord16be oFPMP_TABLE_FEATURES
    putWord16be 0
    putWord32be 0
    mapM_ putTableFeature tableFeatures
  put (RequestPorts {..}) = do
    putHeader multipart_request_type_code (len_header + 8) xid
    putWord16be multipart_type_port_desc
    putWord16be 0
    putWord32be 0
  put (RequestGroups {..}) = do
    putHeader multipart_request_type_code (len_header + 8) xid
    putWord16be multipart_type_group_desc
    putWord16be 0
    putWord32be 0
  put (RequestSwitchDesc {..}) = do
    putHeader multipart_request_type_code (len_header + 8) xid
    putWord16be multipart_type_desc
    putWord16be 0
    putWord32be 0
  put (RequestTableStats {..}) = do
    putHeader multipart_request_type_code (len_header + 8) xid
    putWord16be multipart_table_stats
    putWord16be 0
    putWord32be 0
  put (RequestPortStats {..}) = do
    putHeader multipart_request_type_code (len_header + 8 + 8) xid
    putWord16be multipart_port_stats
    putWord16be 0
    putWord32be 0
    putWord32be portID
    putWord32be 0
  put (PacketOut {..}) = do
    let actionsLength = actionListLength actions
    let len' = 24 + actionsLength + B.length payload
    putHeader packet_out_type_code (fromIntegral len') xid
    putWord32be $ maybe (-1) id packetOutBufferID
    putWord32be $ maybe controllerPortID id inPort
    putWord16be $ fromIntegral actionsLength
    putWord32be 0
    putWord16be 0
    mapM_ putAction actions
    putByteString payload
  put (BarrierRequest {..}) = do
    putHeader barrier_request_type_code len_header xid
  put (AddFlow {..}) = do
    let len = len_header + 40 + 
              fromIntegral (matchLength match) + 
              fromIntegral (sum $ map instructionLength instructions)
    putHeader flow_mod_type_code len xid
    putWord64be cookie
    putWord64be 0
    putWord8 tableID
    putWord8 fmod_add
    putWord16be idleTimeout
    putWord16be hardTimeout
    putWord16be priority
    putWord32be $ maybe (-1) id bufferID
    putWord64be 0 -- unused port ID and group ID
    let flags = 
          (cond sendFlowRemoved (flip setBit 0)) .
          (cond checkOverlap (flip setBit 1)) .          
          (cond (not countPackets) (flip setBit 3)) .          
          (cond (not countBytes) (flip setBit 4)) $
          0
    putWord16be flags
    putWord16be 0 --padding
    putMatch match
    mapM_ putInstruction instructions
    
  put (DeleteFlowStrict {..}) = do
    let len = len_header + 40 + fromIntegral (matchLength match)
    putHeader flow_mod_type_code len xid
    putWord64be cookie
    putWord64be (-1)
    putWord8 tableID
    putWord8 fmod_delete_strict
    putWord32be 0 -- unused idle and hard timeout
    putWord16be priority
    putWord32be 0
    putWord32be $ maybe (-1) id outPort
    putWord32be $ maybe (-1) id outGroup
    putWord32be 0 -- unused flags and padding
    putMatch match
    
  put (DeleteFlow {..}) = do
    let len = len_header + 40 + fromIntegral (matchLength match)
    putHeader flow_mod_type_code len xid
    putWord64be cookie
    putWord64be cookieMask
    putWord8 $ maybe (-1) id maybeTableID
    putWord8 fmod_delete
    putWord32be 0 -- unused idle and hard timeout
    putWord16be priority
    putWord32be 0
    putWord32be $ maybe (-1) id outPort
    putWord32be $ maybe (-1) id outGroup
    putWord32be 0 -- unused flags and padding
    putMatch match
    
  put (ModifyFlowStrict {..}) = do
    let len = len_header + 40 + 
              fromIntegral (matchLength match) + 
              fromIntegral (sum $ map instructionLength instructions)
    putHeader flow_mod_type_code len xid
    putWord64be cookie
    putWord64be (-1)
    putWord8 tableID
    putWord8 fmod_modify_strict
    putWord32be 0 -- unused idle & hard timeouts
    putWord16be priority
    putWord32be (-1) --bufferID
    putWord64be 0 -- unused port ID and group ID
    let flags = if resetCounters then setBit 2 0 else 0
    putWord16be flags
    putWord16be 0 --padding
    putMatch match
    mapM_ putInstruction instructions

  put (ModifyFlow {..}) = do
    let len = len_header + 40 + 
              fromIntegral (matchLength match) + 
              fromIntegral (sum $ map instructionLength instructions)
    putHeader flow_mod_type_code len xid
    putWord64be cookie
    putWord64be cookieMask
    putWord8 tableID
    putWord8 fmod_modify
    putWord32be 0 -- unused idle & hard timeouts
    putWord16be 0
    putWord32be (-1) --bufferID
    putWord64be 0 -- unused port ID and group ID
    let flags = if resetCounters then setBit 2 0 else 0
    putWord16be flags
    putWord16be 0 --padding
    putMatch match
    mapM_ putInstruction instructions

  put (AddGroup {..}) = do
    let bkts = genericBuckets group
    let len = groupModLength bkts
    putHeader group_mod_type_code len xid
    putWord16be oFPGC_ADD
    putWord8 $ groupTypeCode group
    putWord8 0 --padding
    putWord32be groupID
    putBuckets bkts
  put (ModifyGroup {..}) = do
    let bkts = genericBuckets group
    let len = groupModLength bkts
    putHeader group_mod_type_code len xid
    putWord16be oFPGC_MODIFY
    putWord8 $ groupTypeCode group
    putWord8 0 --padding
    putWord32be groupID
    putBuckets bkts
  put (DeleteGroup {..}) = do
    putHeader group_mod_type_code (len_header + 8) xid
    putWord16be oFPGC_DELETE
    putWord8 0
    putWord8 0
    putWord32be groupID
  put (PortMod {..}) = do
    putHeader port_mod_type_code (len_header + 32) xid
    putWord32be portID
    putWord32be 0 --pad
    putEthernetAddress hwAddr
    putWord16be 0 --pad
    let (trueConfigSet,allConfigSet) = mapToBitSets portConfigCodeMap portModConfig
    putWord32be trueConfigSet
    putWord32be allConfigSet
    putWord32be $ setToBitSet portFeaturesCodeMap portModAdvertised
    putWord32be 0 --pad
    
putTableFeature :: TableFeature -> Put
putTableFeature (TableFeature {..}) = do
  putWord16be 64
  putWord8 tableFeatureTableID
  putWord8 0    -- pad
  putWord32be 0 -- pad
  putByteString $ trimTableName tableName
  putWord64be metadataMatch
  putWord64be metadataWrite
  putWord32be 0
  putWord32be $ fromIntegral maxEntries

trimTableName :: String -> B.ByteString
trimTableName name =
  B.take oFP_MAX_TABLE_NAME_LEN $
  BC.pack $
  name ++ replicate (oFP_MAX_TABLE_NAME_LEN - length name) ' '

oFP_MAX_TABLE_NAME_LEN :: Int
oFP_MAX_TABLE_NAME_LEN = 32

groupModLength :: [GenericBucket] -> Word16
groupModLength bkts = len_header + 8 + fromIntegral (sum (map bucketSize bkts))

putBuckets :: [GenericBucket] -> Put
putBuckets = mapM_ putBucket

actionListLength :: ActionList -> Int
actionListLength = sum . map actionLength

bucketSize :: GenericBucket -> Int
bucketSize (_,_,_,actions) = 16 + actionListLength actions

putBucket :: GenericBucket -> Put
putBucket b@(w,wp,wg,al) = do
  putWord16be $ fromIntegral $ bucketSize b
  putWord16be w
  putWord32be wp
  putWord32be wg
  putWord32be 0 -- padding
  putActionList al

cond :: Bool -> (a -> a) -> a -> a  
cond True f a = f a
cond False _ a = a
  
fmod_add, fmod_modify, fmod_modify_strict, fmod_delete, fmod_delete_strict :: Word8  
fmod_add = 0
fmod_modify = 1
fmod_modify_strict = 2
fmod_delete = 3
fmod_delete_strict = 4

instructionLength :: Instruction -> Int
instructionLength ClearActions = 8
instructionLength (WriteActions actions) 
  = 8 + actionListLength actions
instructionLength (ApplyActions actions) 
  = 8 + actionListLength actions
instructionLength (GotoTable _) = 8
instructionLength (WriteMetadata {}) = 24
instructionLength (Meter _) = 8

putActionList :: ActionList -> Put
putActionList = mapM_ putAction

putInstruction :: Instruction -> Put
putInstruction i@(GotoTable t) = do
  putWord16be 1
  putWord16be $ fromIntegral $ instructionLength i
  putWord8 t
  putByteString $ B.replicate 3 0
putInstruction i@(WriteMetadata {..}) = do
  putWord16be 2
  putWord16be $ fromIntegral $ instructionLength i
  putWord32be 0
  putWord64be metadata
  putWord64be metadataMask
putInstruction i@(WriteActions actions) = do
  putWord16be 3
  putWord16be $ fromIntegral $ instructionLength i
  putWord32be 0
  putActionList actions
putInstruction i@(ApplyActions actions) = do
  putWord16be 4
  putWord16be $ fromIntegral $ instructionLength i
  putWord32be 0
  putActionList actions
putInstruction ClearActions = do
  putWord16be 5
  putWord16be $ fromIntegral $ instructionLength ClearActions
  putWord32be 0
putInstruction i@(Meter mid) = do
  putWord16be 6
  putWord16be $ fromIntegral $ instructionLength i
  putWord32be mid
  
putAction :: Action -> Put
putAction (SetField oxm) = do
  putWord16be oFPAT_SET_FIELD
  let len1 = 4 + oxmLen oxm
      remainder = (- len1 :: Int) `mod` 8
      len  = len1 + remainder
  putWord16be $ fromIntegral len
  putOXM oxm
  putByteString $ B.replicate remainder 0

putAction (Output {..}) = do
  putWord16be output_action_type_code
  putWord16be 16
  putWord32be outputPortID
  putWord16be $ maybe (-1) (\x -> assert (x <= 0xffe5) x) maxLengthToController
  putWord32be 0
  putWord16be 0
putAction CopyTTLOut = do
  putWord16be 11
  putWord16be 8
  putWord32be 0
putAction CopyTTLIn = do
  putWord16be 12
  putWord16be 8
  putWord32be 0
putAction (SetMPLSTTL ttl) = do
  putWord16be 15
  putWord16be 8
  putWord8 ttl
  putWord8 0
  putWord16be 0
putAction DecMPLSTTL = do
  putWord16be 16
  putWord16be 8
  putWord32be 0
putAction (PushVLAN w) = do
  putWord16be 17
  putWord16be 8
  putWord16be w
  putWord16be 0
putAction PopVLAN = do
  putWord16be 18
  putWord16be 8
  putWord32be 0
putAction (PushMPLS w) = do
  putWord16be 19
  putWord16be 8
  putWord16be w
  putWord16be 0
putAction (PopMPLS w) = do
  putWord16be 20
  putWord16be 8
  putWord16be w
  putWord16be 0
putAction (SetQueue w) = do
  putWord16be 21
  putWord16be 8
  putWord32be w
putAction (SetGroup w) = do
  putWord16be 22
  putWord16be 8
  putWord32be w
putAction (SetNetworkTTL w) = do
  putWord16be 23
  putWord16be 8
  putWord8 w
  putWord8 0
  putWord16be 0
putAction DecNetworkTTL = do
  putWord16be 24
  putWord16be 8
  putWord32be 0
putAction (SetNiciraRegister idx v) = do
  putWord16be oFPAT_EXPERIMENTER
  putWord16be 24
  putWord32be nX_VENDOR_ID
  putWord16be nXAST_REG_LOAD
  let n_bits = 32
      offset = 0
  putWord16be $ shiftL offset 6 .|. (n_bits - 1)
  putWord32be $ nXM_HEADER 1 (fromIntegral idx) 4
  putWord64be $ fromIntegral v

nXM_HEADER__ :: Word32 -> Word32 -> Bool -> Word32 -> Word32
nXM_HEADER__ vendor field hasMask len
  = shiftL vendor 16 .|. shiftL field 9 .|. shiftL hasMask' 8 .|. len
  where hasMask' | hasMask   = 1
                 | otherwise = 0

nXM_HEADER :: Word32 -> Word32 -> Word32 -> Word32
nXM_HEADER vendor field len = nXM_HEADER__ vendor field False len

nXAST_REG_LOAD :: Word16
nXAST_REG_LOAD = 7

nX_VENDOR_ID :: Word32
nX_VENDOR_ID = 0x00002320

oFPAT_EXPERIMENTER :: Word16
oFPAT_EXPERIMENTER = -1

oFPAT_SET_FIELD :: Word16
oFPAT_SET_FIELD = 25

output_action_type_code :: Word16
output_action_type_code = 0
  
controllerPortID :: PortID
controllerPortID = 0xfffffffd

actionLength :: Action -> Int
actionLength (SetField oxm) =
  let len1 = 4 + oxmLen oxm
      remainder = (- len1 :: Int) `mod` 8
  in len1 + remainder
  
actionLength (Output {..}) = 16
actionLength CopyTTLOut = 8
actionLength CopyTTLIn = 8
actionLength (SetMPLSTTL _) = 8
actionLength DecMPLSTTL = 8
actionLength (PushVLAN _) = 8
actionLength PopVLAN = 8
actionLength (PushMPLS _) = 8
actionLength (PopMPLS _) = 8
actionLength (SetQueue _) = 8
actionLength (SetGroup _) = 8
actionLength (SetNetworkTTL _) = 8
actionLength DecNetworkTTL = 8
actionLength (SetNiciraRegister _ _) = 24

multipart_type_desc :: Word16
multipart_type_desc = 0

multipart_table_stats :: Word16
multipart_table_stats = 3

multipart_port_stats :: Word16
multipart_port_stats = 4

multipart_type_port_desc :: Word16
multipart_type_port_desc = 13

multipart_type_group_desc :: Word16
multipart_type_group_desc = 7

getHeader :: Get Header
getHeader = 
  do vid <- getWord8
     typ <- getWord8
     len <- getWord16be
     xid <- getWord32be
     assert (vid == version_of13) $ return (vid, typ, len, xid)

putHeader :: Word8 -> Len -> XID -> Put
putHeader typeCode' len xid = do
  putWord8 version_of13
  putWord8 typeCode'
  putWord16be len
  putWord32be xid

getBody :: Header -> Get Message
getBody hdr@(_, typ, len, xid) 
  | typ == hello_type_code        =
    do skip $ numBodyBytes len
       return $ Hello { xid = xid, len = len }
    
  | typ == error_type_code =
    do errorType <- getWord16be
       errorCode <- getWord16be       
       let errTyp' = case errorType of
             _ | errorType == 0 -> HelloFailed
             _ | errorType == 1 -> BadRequest $ fromJust $ Bimap.lookupR errorCode badRequestCodeMap
             _ | errorType == 2 -> BadAction         
             _ | errorType == 3 -> BadInstruction $ fromJust $ Bimap.lookupR errorCode badInstructionCodeMap
             _ | errorType == 4 -> BadMatch $ fromJust $ Bimap.lookupR errorCode badMatchCodeMap
             _ | errorType == 5 -> FlowModFailed         
             _ | errorType == 6 -> GroupModFailed $ fromJust $ Bimap.lookupR errorCode badGroupModCodeMap
             _ | errorType == 7 -> PortModFailed
             _ | errorType == 8 -> TableModFailed         
             _ | errorType == 9 -> QueueOpFailed
             _ | errorType == 10 -> SwitchConfigFailed
             _ | errorType == 11 -> RoleRequestFailed         
             _ | errorType == 12 -> MeterModFailed
             _ | errorType == 13 -> TableFeaturesFailed
             _ | errorType == 0xffff -> ExperimenterError         
             _ -> error "bad error type code"
       body <- getByteString $ numBodyBytes len - 4
       return $ Error { xid = xid
                      , errorType = errTyp'
                      , errorCode = errorCode
                      , body = body }
    
  | typ == echo_request_type_code =
    do body <- getByteString $ numBodyBytes len 
       return $ EchoRequest { xid = xid, body = body }
       
  | typ == echo_reply_type_code =
    do body <- getByteString $ numBodyBytes len 
       return $ EchoReply { xid = xid, body = body }
       
  | typ == feature_reply_type_code =
    do sid <- getWord64be
       numBuffers <- getWord32be
       numTables <- getWord8
       auxID <- getWord8
       skip 2
       caps <- getWord32be
       skip 4
       return $ 
         FeatureReply { xid = xid
                      , sid = sid 
                      , numBuffers = numBuffers
                      , numTables = numTables
                      , auxID = auxID
                      , capabilities = bitSetToSet switchCapabilityFields caps
                      }
  
  | typ == config_request_type_code = return $ ConfigRequest { xid = xid }
    
  | typ == config_reply_type_code =
      do flags <- getWord16be
         missSendLen <- getWord16be
         return $ ConfigReply { xid = xid
                              , configFlags = bitSetToSet configFlagsFields flags
                              , missSendLen = missSendLen
                              }

  | typ == config_set_type_code =
      do flags <- getWord16be
         missSendLen <- getWord16be
         return $ ConfigSet { xid = xid
                            , configFlags = bitSetToSet configFlagsFields flags
                            , missSendLen = missSendLen
                            }

  | typ == packet_in_type_code = 
        do bufferID' <- getWord32be
           let bufferID = if bufferID' == -1 
                          then Nothing 
                          else Just bufferID'
           totalLen <- getWord16be
           reason   <- getWord8
           tableID <- getWord8
           cookie <- getWord64be
           match <- getMatch
           skip 2
           readSoFar <- bytesRead
           rest <- getByteString $ fromIntegral $ fromIntegral len - readSoFar
           return $ PacketIn { xid = xid
                             , bufferID = bufferID
                             , totalLen = totalLen
                             , reason   = fromJust $ Bimap.lookupR reason packetInReasonCodeMap
                             , tableID  = tableID
                             , cookie   = cookie
                             , match    = match
                             , payload  = rest
                             }
  | typ == flow_removed_type_code = 
          do cookie <- getWord64be
             priority <- getWord16be
             reason <- getWord8
             let flowRemovedReason | reason == 0 = IdleTimeout
                                   | reason == 1 = HardTimeout
                                   | reason == 2 = FlowDelete
                                   | reason == 3 = GroupDelete
                                   | otherwise   = error "bad flow removed reason code"
             table <- getWord8
             duration_sec <- getWord32be
             duration_nsec <- getWord32be
             idleTimeout <- getWord16be
             hardTimeout <- getWord16be
             packetCount <- getWord64be
             byteCount <- getWord64be
             match <- getMatch
             return $ FlowRemoved { xid = xid
                                  , cookie = cookie
                                  , priority = priority
                                  , flowRemovedReason = flowRemovedReason
                                  , tableID = table
                                  , duration_sec = duration_sec
                                  , duration_nsec = duration_nsec
                                  , idleTimeout = idleTimeout
                                  , hardTimeout = hardTimeout
                                  , packetCount = packetCount
                                  , byteCount = byteCount
                                  , match = match
                                  }
          
  | typ == port_status_type_code = 
      do reason <- toReason <$> getWord8
         skip 7
         port <- getPort
         return $ PortStatus { xid = xid
                             , portStateChangeReason = reason
                             , port = port
                             } 
  | typ == multipart_reply_type_code =
      do multipart_type <- getWord16be
         moreToFollow <- flip testBit 0 <$> getWord16be
         skip 4
         let bodyLen = fromIntegral len - 16
         msg <- case multipart_type of
           
           _ | multipart_type == multipart_type_port_desc ->
             assert (0 == (bodyLen `mod` portDescLen)) $
             PortDesc <$> replicateM (bodyLen `div` portDescLen) getPort 
             
           _ | multipart_type == multipart_type_desc -> 
             getSwitchDesc
             
           _ | multipart_type == multipart_table_stats -> 
             assert (0 == (bodyLen `mod` tableStatsLen)) $
             AllTableStats <$> replicateM (bodyLen `div` tableStatsLen) getTableStats
             
           _ | multipart_type == multipart_port_stats -> 
             assert (0 == (bodyLen `mod` portStatsLen)) $
             AllPortStats <$> replicateM (bodyLen `div` portStatsLen) getPortStats
             
           _ | multipart_type == multipart_type_group_desc ->
             GroupDesc <$> getGroupDescs bodyLen

           _ | otherwise -> 
             error ("Invalid multipart message type " ++ show multipart_type)
             
         return $ MultipartReply { xid = xid
                                 , moreToCome = moreToFollow
                                 , multipartMessage = msg
                                 }
  | typ == barrier_reply_type_code =
      do return $ BarrierReply { xid = xid }  
  | otherwise = 
      do skip $ numBodyBytes len
         return $ Undefined hdr

getGroupDescs :: Int -> Get [(GroupID, Group)]
getGroupDescs bodyLen
  | bodyLen == 0 = return []
  | otherwise = do
    (glen, gd) <- getGroupDesc
    gds <- getGroupDescs (bodyLen - glen)
    return $ gd : gds

getGroupDesc :: Get (Int, (GroupID, Group))
getGroupDesc = do
  len <- getWord16be
  typ <- getWord8
  _ <- getWord8
  gid <- getWord32be
  buckets <- getGenericBuckets (fromIntegral len - 8)
  return (fromIntegral len, (gid, bucketsToGroup typ buckets))

getGenericBuckets :: Int -> Get [GenericBucket]
getGenericBuckets totalLen
  | totalLen == 0 = return []
  | otherwise = do
    (len, bkt) <- getGenericBucket
    bkts <- getGenericBuckets (totalLen - len)
    return $ bkt : bkts
  
getGenericBucket :: Get (Int, GenericBucket)
getGenericBucket = do
  len <- getWord16be
  weight <- getWord16be
  wp <- getWord32be
  wg <- getWord32be
  _ <- getWord32be --padding
  al <- getActionList (fromIntegral len - 16)
  return (fromIntegral len, (weight,wp,wg,al))

getActionList :: Int -> Get [Action]
getActionList totalLen
  | totalLen == 0 = return []
  | otherwise = do
    (len, act) <- getAction
    acts <- getActionList (totalLen - len)
    return $ act : acts

getAction :: Get (Int, Action)
getAction = do
  typ <- getWord16be
  len <- getWord16be
  act <- case typ of
    _ | typ == output_action_type_code -> getOutputAction
    _ -> error ("unhandled action typ: " ++ show typ)
  return (fromIntegral len, act)

getOutputAction :: Get Action  
getOutputAction = do
  pid <- getWord32be
  max_len <- getWord16be
  skip 6
  return $ Output pid (if max_len == -1 then Nothing else Just max_len)

portDescLen :: Int         
portDescLen = 64
         
tableStatsLen :: Int
tableStatsLen = 24

portStatsLen :: Int
portStatsLen = 112
         
getPortStats :: Get PortStats         
getPortStats = do
  portID <- getWord32be
  skip 4
  rxPackets <- fromIntegral <$> getWord64be
  txPackets <- fromIntegral <$> getWord64be  
  rxBytes <- fromIntegral <$> getWord64be  
  txBytes <- fromIntegral <$> getWord64be  
  rxDropped <- fromIntegral <$> getWord64be  
  txDropped <- fromIntegral <$> getWord64be  
  rxErrors <- fromIntegral <$> getWord64be
  txErrors <- fromIntegral <$> getWord64be  
  rxFrameErrors <- fromIntegral <$> getWord64be  
  rxOverErrors <- fromIntegral <$> getWord64be  
  rxCRCErrors <- fromIntegral <$> getWord64be  
  collisions <- fromIntegral <$> getWord64be  
  portDurationSec <- fromIntegral <$> getWord32be
  portDurationNanoSec <- fromIntegral <$> getWord32be
  return $  PortStats { statsPortID = portID
                      , rxPackets = rxPackets
                      , txPackets = txPackets
                      , rxBytes = rxBytes
                      , txBytes = txBytes
                      , rxDropped = rxDropped
                      , txDropped = txDropped
                      , rxErrors = rxErrors
                      , txErrors = txErrors
                      , rxFrameErrors = rxFrameErrors
                      , rxOverErrors = rxOverErrors
                      , rxCRCErrors = rxCRCErrors
                      , collisions = collisions
                      , portDurationSec = portDurationSec
                      , portDurationNanoSec = portDurationNanoSec
                      }


getTableStats :: Get TableStats
getTableStats = do
  tableID <- getWord8
  skip 3
  activeCount <- fromIntegral <$> getWord32be
  lookupCount <- fromIntegral <$> getWord64be  
  matchedCount <- fromIntegral <$> getWord64be  
  return $ TableStats { statsTableID = tableID
                      , activeCount = activeCount
                      , lookupCount = lookupCount
                      , matchedCount = matchedCount
                      }

getSwitchDesc :: Get MultipartMessage
getSwitchDesc = do
  mfrDesc <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString desc_str_len
  hw_desc <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString desc_str_len
  sw_desc <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString desc_str_len
  serial_num <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString serial_num_len
  dp_desc <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString desc_str_len
  return $ SwitchDesc { mfrDesc = mfrDesc  
                      , hw_desc = hw_desc
                      , sw_desc = sw_desc
                      , serial_num = serial_num
                      , dp_desc = dp_desc
                      }
  where 
    desc_str_len = 256
    serial_num_len = 32

getPort :: Get Port
getPort = do
  portNumber <- getWord32be
  skip 4
  hwAddress <- getEthernetAddress
  skip 2
  portName <- BC.unpack . BC.takeWhile (/= '\NUL') <$> getByteString 16
  portConfig <- toPortConfig <$> getWord32be
  portState <- toPortStates <$> getWord32be
  currentFeatures <- toPortFeatures <$> getWord32be
  advertisedFeatures <- toPortFeatures <$> getWord32be
  supportedFeatures <- toPortFeatures <$> getWord32be
  peerFeatures <- toPortFeatures <$> getWord32be
  currentSpeed <- getWord32be
  maxSpeed <- getWord32be  
  return $ Port { portNumber = portNumber
                , hwAddress  = hwAddress
                , portName   = portName
                , portConfig = portConfig
                , portState  = portState
                , currentFeatures = currentFeatures
                , advertisedFeatures = advertisedFeatures
                , supportedFeatures = supportedFeatures
                , peerFeatures = peerFeatures
                , currentSpeed = fromIntegral currentSpeed
                , maxSpeed = fromIntegral maxSpeed
                } 
  
toPortConfig :: Word32 -> Set PortConfigFlag
toPortConfig = bitSetToSet portConfigCodeMap

portConfigCodeMap :: [(Int, PortConfigFlag)]
portConfigCodeMap = [ (0, PortDown)
                    , (2, NoRecv)
                    , (5, NoFwd)
                    , (6, NoPacketIn)
                    ]

toPortStates :: Word32 -> Set PortStateFlag
toPortStates = bitSetToSet portStateCodeMap

portStateCodeMap :: [(Int, PortStateFlag)]
portStateCodeMap = [ (0, LinkDown)
                   , (1, Blocked)
                   , (2, Live)
                   ]

toPortFeatures :: Word32 -> Set PortFeature
toPortFeatures = bitSetToSet portFeaturesCodeMap

portFeaturesCodeMap :: [(Int, PortFeature)]
portFeaturesCodeMap = 
  [ (0, HD10Mb)
  , (1, FD10Mb)
  , (2, HD100Mb)
  , (3, FD100Mb)
  , (4, HD1Gb)
  , (5, FD1Gb)
  , (6, FD10Gb)
  , (7, FD40Gb)
  , (8, FD100Gb)
  , (9, FD1Tb)
  , (10, OtherRate)
  , (11, Copper)
  , (12, Fiber)
  , (13, AutoNeg)
  , (14, Pause)
  , (15, PauseAsym)
  ]

toReason :: Word8 -> PortStateChangeReason 
toReason 0 = PortAdd
toReason 1 = PortDelete
toReason 2 = PortModify
toReason code = error ("Invalid port state reason code: " ++ show code)

matchLength :: Match -> Int
matchLength (MatchOXM oxms) = 4 + oxmsLen + padding
  where
    oxmsLen = sum $ map oxmLen oxms
    padding = (-(4 + oxmsLen)) `mod` 8

putMatch :: Match -> Put
putMatch (MatchOXM oxms) = do
  putWord16be 1
  let oxmsLen = sum $ map oxmLen oxms
  let len = 4 + oxmsLen
  putWord16be $ fromIntegral len
  mapM_ putOXM oxms
  let remainder = (- (len :: Int)) `mod` 8        
  putByteString $ B.replicate remainder 0

putOXM :: OXM -> Put
putOXM (OXMOther {..}) = error "Non-basic OXMs are not supported."

putOXM (NiciraRegister r v) = do
  putWord16be 1
  putWord8 $ fromIntegral r `shiftL` 1
  putWord8 4
  putWord32be v

putOXM oxmof = do
  putOXMClass
  putOXMField (fieldCode oxmof) (oxmHasMask' oxmof)
  putWord8 $ fromIntegral (oxmLen oxmof - tlv_header_len)
  case oxmof of
    InPort p    -> putWord32be p
    InPhyPort p -> putWord32be p
    Metadata w w' hasMask -> do putWord64be w
                                when hasMask $ putWord64be w'
    EthDst a mask hasMask -> do
        putEthernetAddress a
        when hasMask $ putEthernetAddress mask
    EthSrc a mask hasMask -> do
        putEthernetAddress a
        when hasMask $ putEthernetAddress mask
    EthType a -> putWord16be a

    IPv4Dst a -> do putIPAddress $ addressPart a
                    unless (prefixIsExact a) $ putIPAddress $ prefixToMask a
    IPv4Src a -> do putIPAddress $ addressPart a
                    unless (prefixIsExact a) $ putIPAddress $ prefixToMask a
    OXM oxm _ -> case oxm of
      VLANID Absent -> putWord16be 0
      VLANID (Present Nothing) -> do putWord16be vlan_present_mask
                                     putWord16be vlan_present_mask
      VLANID (Present (Just vid)) -> putWord16be vid
      VLANPCP a -> putWord8 a
      IPDSCP a -> putWord8 a
      IPECN a -> putWord8 a
      IPProto a -> putWord8 a
      ARP_OP op -> putWord16be op
      ARP_TPA a _ -> putIPAddress a

      

putIPAddress :: IPAddress -> Put
putIPAddress (IPAddress a) = putWord32be a

getIPAddress :: Get IPAddress
getIPAddress = IPAddress <$> getWord32be

vlan_present_mask :: Word16
vlan_present_mask = 0x1000

fieldCode :: OXM -> Int
fieldCode (InPort {})    = 0
fieldCode (InPhyPort {}) = 1
fieldCode (Metadata {})  = 2
fieldCode (EthDst {})    = 3
fieldCode (EthSrc {})    = 4
fieldCode (EthType {})   = 5
fieldCode (OXM { oxmOFField = VLANID _})     = 6
fieldCode (OXM { oxmOFField = VLANPCP _})    = 7
fieldCode (OXM { oxmOFField = IPDSCP _})     = 8
fieldCode (OXM { oxmOFField = ARP_OP _})     = 21
fieldCode (OXM { oxmOFField = ARP_TPA _ _})  = 23
fieldCode (IPv4Src {})  = 11
fieldCode (IPv4Dst {})  = 12
fieldCode oxm = error $ "fieldCode: not yet implemented for " ++ show oxm

putOXMClass :: Put
putOXMClass = putWord16be 0x8000

putOXMField :: Int -> Bool -> Put
putOXMField x hasMask 
  = putWord8 $ fromIntegral x `shiftL` 1 + if hasMask then 1 else 0

oxmLen :: OXM -> Int  
oxmLen oxm = 
  tlv_header_len + 
  case oxm of
    OXMOther {}        -> error "Non-basic OXM match classes are not supported."
    InPort _           -> 4
    InPhyPort _        -> 4    
    Metadata _ _ False -> 8
    EthDst _ _ False   -> 6
    EthDst _ _ True    -> 6 * 2
    EthSrc _ _ False   -> 6
    EthSrc _ _ True    -> 6 * 2
    EthType _          -> 2
    NiciraRegister _ _ -> 4
    IPv4Dst a | prefixIsExact a -> 4
              | otherwise       -> 4 * 2
    IPv4Src a | prefixIsExact a -> 4
              | otherwise       -> 4 * 2
    
    OXM (VLANID _) False    -> 2
    OXM (VLANPCP _) False   -> 1
    OXM (IPDSCP _) False    -> 1
    OXM (IPECN _) False     -> 1
    OXM (IPProto _) False   -> 1
    OXM (TCPSrc _) False    -> 2
    OXM (TCPDst _) False    -> 2
    OXM (UDPSrc _) False    -> 2
    OXM (UDPDst _) False    -> 2
    OXM (SCTPSrc _) False    -> 2
    OXM (SCTPDst _) False    -> 2
    OXM (ICMPv4_Type _) False -> 1
    OXM (ICMPv4_Code _) False -> 1
    OXM (ARP_OP _) False    -> 2
    OXM (ARP_SPA _ _) False -> 4
    OXM (ARP_SPA _ _) True  -> 4 * 2
    OXM (ARP_TPA _ _) False -> 4
    OXM (ARP_TPA _ _) True  -> 4 * 2
    OXM (ARP_SHA _ _) False -> 6
    OXM (ARP_SHA _ _) True  -> 6 * 2
    OXM (ARP_THA _ _) False -> 6
    OXM (ARP_THA _ _) True  -> 6 * 2
    OXM (IPv6Src _ _) False -> 16
    OXM (IPv6Src _ _) True  -> 16 * 2
    OXM (IPv6Dst _ _) False -> 16
    OXM (IPv6Dst _ _) True  -> 16 * 2
    OXM (IPv6_FLabel _) False -> 4
    OXM (IPv6_FLabel _) True  -> 4 * 2
    OXM (ICMPv6_Type _) False -> 1
    OXM (ICMPv6_Code _) False -> 1    
    OXM (IPv6_ND_Target _) False -> 16
    OXM (IPv6_ND_SLL _) False -> 6
    OXM (IPv6_ND_TLL _) False -> 6    
    OXM (MPLS_Label _) False -> 4
    OXM (MPLS_TC _) False -> 1
    OXM (MPLS_BOS _) False -> 1
    OXM (PBB_ISID _ _ ) False -> 3
    OXM (PBB_ISID _ _ ) True  -> 3 * 2
    OXM (TunnelID _ _) False -> 8
    OXM (TunnelID _ _) True -> 8 * 2
    OXM (IPv6_EXTHDR _) False -> 2
    OXM (IPv6_EXTHDR _) True -> 2 * 2

    _ -> error ("Unexpected field and mask value: " ++ show oxm)

tlv_header_len :: Int
tlv_header_len = 4

getMatch :: Get Match
getMatch = do 
  matchType <- getWord16be
  matchLen  <- getWord16be
  assert (matchType /= 0) $ do
    oxms <- getOXMs $ fromIntegral matchLen - 4
    let remainder = (- (fromIntegral matchLen :: Int)) `mod` 8
    skip remainder
    return $ MatchOXM { oxms = oxms }

getOXMs :: Int -> Get [OXM]
getOXMs len 
  | len == 0 = return []
  | len > 0  = do (oxmlen,oxm) <- getOXM
                  oxms <- getOXMs (len - oxmlen)
                  return $ oxm:oxms
  | otherwise = error "Bad OXM length"
  
getOXM :: Get (Int,OXM)
getOXM = do
  header <- getWord32be
  let len = fromIntegral (header `mod` 0x100)
  let oxmClass = fromIntegral (shiftR header 16)
      oxmField = clearBit (fromIntegral $ shiftR header 9) 7
      hasMask  = testBit header 8
  oxm <-
    if oxmClass == 0x8000
    then do toField hasMask oxmField 
    else if oxmClass == 1
         then assert (len == 4) $ -- Don't yet support masked Nicira registers
              do val <- getWord32be
                 return $ NiciraRegister (fromIntegral oxmField) val
         else do payload <- getByteString len
                 return $ OXMOther { oxmBody = payload  
                                   , oxmField = oxmField
                                   , oxmClass = oxmClass
                                   , oxmHasMask = testBit header 8
                                   }
  return (4 + len, oxm)

toField :: Bool -> Word8 -> Get OXM
toField False 0 = InPort <$> getWord32be
toField False 1 = InPhyPort <$> getWord32be
toField hasMask 2 = 
  (\x y -> Metadata x y hasMask) <$>
  getWord64be <*> if hasMask then getWord64be else return (-1)
toField hasMask 3 = 
  (\x y -> EthDst x y hasMask) <$> 
  getEthernetAddress <*> 
  if hasMask then getEthernetAddress else return (-1)
toField hasMask 4 = 
  (\x y -> EthSrc x y hasMask) <$> 
  getEthernetAddress <*> 
  if hasMask then getEthernetAddress else return (-1)
toField False 5 = EthType <$> getWord16be
toField hasMask 6 = do
  v <- getWord16be
  if v == 0
    then assert (not hasMask) $ return $ OXM { oxmOFField = VLANID Absent, oxmHasMask = hasMask }
    else if hasMask
         then do mask' <- getWord16be 
                 assert (mask' == vlan_present_mask) $
                   return $ OXM { oxmOFField = VLANID (Present Nothing), oxmHasMask = hasMask }
         else return $ OXM { oxmOFField = VLANID (Present $ Just v), oxmHasMask = hasMask }

toField False 7 = (\x -> OXM { oxmOFField = VLANPCP x, oxmHasMask = False }) <$> getWord8
toField False 8 = (\x -> OXM { oxmOFField = IPDSCP x, oxmHasMask = False }) <$> getWord8
toField False 9 = (\x -> OXM { oxmOFField = IPECN x, oxmHasMask = False }) <$> getWord8
toField False 10 = (\x -> OXM { oxmOFField = IPProto x, oxmHasMask = False }) <$> getWord8
toField hasMask 11 =
 (\x y -> IPv4Src (x // maskToPrefixLength y)) <$>
 getIPAddress <*> if hasMask then getIPAddress else return (IPAddress 0xffffffff)
toField hasMask 12 = 
 (\x y -> IPv4Dst (x // maskToPrefixLength y)) <$>
 getIPAddress <*> if hasMask then getIPAddress else return (IPAddress 0xffffffff)
toField False 13 = (\x -> OXM { oxmOFField = TCPSrc x, oxmHasMask = False }) <$> getWord16be
toField False 14 = (\x -> OXM { oxmOFField = TCPDst x, oxmHasMask = False }) <$> getWord16be
toField False 15 = (\x -> OXM { oxmOFField = UDPSrc x, oxmHasMask = False }) <$> getWord16be
toField False 16 = (\x -> OXM { oxmOFField = UDPDst x, oxmHasMask = False }) <$> getWord16be
toField False 17 = (\x -> OXM { oxmOFField = SCTPSrc x, oxmHasMask = False }) <$> getWord16be
toField False 18 = (\x -> OXM { oxmOFField = SCTPDst x, oxmHasMask = False }) <$> getWord16be
toField False 19 = (\x -> OXM { oxmOFField = ICMPv4_Type x, oxmHasMask = False }) <$> getWord8
toField False 20 = (\x -> OXM { oxmOFField = ICMPv4_Code x, oxmHasMask = False }) <$> getWord8
toField False 21 =
  (\x -> OXM { oxmOFField = ARP_OP x, oxmHasMask = False }) <$>
  getWord16be
toField hasMask 22 = 
  (\x y -> OXM { oxmOFField = ARP_SPA x y, oxmHasMask = hasMask }) <$>
  getIPAddress <*> if hasMask then getIPAddress else return (-1)
toField hasMask 23 = 
  (\x y -> OXM { oxmOFField = ARP_TPA x y, oxmHasMask = hasMask }) <$>
  getIPAddress <*> if hasMask then getIPAddress else return (-1)
toField hasMask 24 = 
  (\x y -> OXM { oxmOFField = ARP_SHA x y, oxmHasMask = hasMask }) <$>
  getEthernetAddress <*> if hasMask then getEthernetAddress else return (-1)
toField hasMask 25 = 
  (\x y -> OXM { oxmOFField = ARP_THA x y, oxmHasMask = hasMask }) <$>
  getEthernetAddress <*> if hasMask then getEthernetAddress else return (-1)
toField hasMask 26 = 
  (\x y -> OXM { oxmOFField = IPv6Src x y, oxmHasMask = hasMask }) <$>
  getIPv6Address <*> if hasMask then getIPv6Address else return $ B.replicate 16 (-1)
toField hasMask 27 = 
  (\x y -> OXM { oxmOFField = IPv6Dst x y, oxmHasMask = hasMask }) <$>
  getIPv6Address <*> if hasMask then getIPv6Address else return $ B.replicate 16 (-1)
toField hasMask 38 = do
  v <- getWord64be 
  when hasMask $ void getWord64be
  return $ OXM { oxmOFField = TunnelID v (-1), oxmHasMask = hasMask }

toField _ _ = error "Illegal field code"

getIPv6Address :: Get IPv6Address
getIPv6Address = getByteString 16

getEthernetAddress :: Get EthernetAddress
getEthernetAddress =
  do x <- getWord32be 
     y <- getWord16be
     return $ ethernetAddress64 $ pack_32_16 x y

putEthernetAddress :: EthernetAddress -> Put
putEthernetAddress w = do
  let a = unpack64 w
  putWord32be $ fromIntegral $ a `shiftR` 16
  putWord16be $ fromIntegral a

numBodyBytes :: Integral a => Word16 -> a
numBodyBytes len = fromIntegral $ len - len_header

numMessageBytes :: Integral a => a -> Word16
numMessageBytes n = len_header + fromIntegral n

-- =========== CONSTANTS ===========

len_header :: Word16
len_header = 8

version_of13 :: Word8
version_of13 = 0x04

hello_type_code :: Word8
hello_type_code = 0

error_type_code :: Word8
error_type_code = 1

echo_request_type_code :: Word8
echo_request_type_code = 2

echo_reply_type_code :: Word8
echo_reply_type_code = 3

feature_request_type_code :: Word8
feature_request_type_code = 5

feature_reply_type_code :: Word8
feature_reply_type_code = 6

config_request_type_code :: Word8
config_request_type_code = 7

config_reply_type_code :: Word8
config_reply_type_code = 8

config_set_type_code :: Word8
config_set_type_code = 9

packet_in_type_code :: Word8
packet_in_type_code = 10

flow_removed_type_code :: Word8
flow_removed_type_code = 11

port_status_type_code :: Word8
port_status_type_code = 12

packet_out_type_code :: Word8
packet_out_type_code = 13

flow_mod_type_code :: Word8
flow_mod_type_code = 14

group_mod_type_code :: Word8
group_mod_type_code = 15

port_mod_type_code :: Word8
port_mod_type_code = 16

multipart_request_type_code :: Word8
multipart_request_type_code = 18

multipart_reply_type_code :: Word8
multipart_reply_type_code = 19

barrier_request_type_code :: Word8
barrier_request_type_code = 20

barrier_reply_type_code :: Word8
barrier_reply_type_code = 21

oFPGC_ADD, oFPGC_MODIFY, oFPGC_DELETE :: Word16
oFPGC_ADD    = 0
oFPGC_MODIFY = 1
oFPGC_DELETE = 2

-- =========== UTILITY ===========
bitSetToSet :: (Ord a, Bits b) => [(Int, a)] -> b -> Set a
bitSetToSet fields bitset =
  Set.fromList [ a | (i,a) <- fields, testBit bitset i ]

setToBitSet :: (Ord a, Bits b, Num b) => [(Int,a)] -> Set a -> b
setToBitSet fields set =
  foldl setBit 0 [ i | (i,a) <- fields, Set.member a set ]

mapToBitSets :: (Ord a, Bits b, Num b) => [(Int,a)] -> Map a Bool -> (b,b)
mapToBitSets fields m = (toBitSet trueSet, toBitSet allSet)
  where
    trueSet = Set.fromList $ [ a | (a, True) <- Map.assocs m]
    allSet  = Set.fromList $ Map.keys m
    toBitSet = setToBitSet fields
