{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

module Network.Data.OpenFlow.Error ( 
  SwitchError (..)
  , HelloFailure (..)
  , RequestError (..)
  , ActionError (..)
  , FlowModError (..)
  , PortModError (..)
  , QueueOpError (..)
  ) where

import Data.Word
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

-- | When a switch encounters an error condition, it sends the controller
-- a message containing the information in @SwitchErrorRecord@.
data SwitchError = HelloFailed          HelloFailure String
                 | BadRequest           RequestError [Word8]
                 | BadAction            ActionError  [Word8]
                 | FlowModFailed        FlowModError [Word8]
                 | PortModFailed        PortModError [Word8]
                 | QueueOperationFailed QueueOpError [Word8]
                 deriving (Generic, Show, Eq)
                   
instance NFData SwitchError
             
data HelloFailure = IncompatibleVersions
                  | HelloPermissionsError
                  deriving (Generic, Show, Eq, Ord, Enum)

instance NFData HelloFailure
                           
data RequestError = VersionNotSupported
                  | MessageTypeNotSupported
                  | StatsRequestTypeNotSupported
                  | VendorNotSupported
                  | VendorSubtypeNotSupported
                  | RequestPermissionsError
                  | BadRequestLength
                  | BufferEmpty
                  | UnknownBuffer
                  deriving (Generic, Show, Eq, Ord, Enum)

instance NFData RequestError

data ActionError = UnknownActionType
                 | BadActionLength
                 | UnknownVendorID
                 | UnknownActionTypeForVendor
                 | BadOutPort
                 | BadActionArgument
                 | ActionPermissionsError
                 | TooManyActions
                 | InvalidQueue
                 deriving (Generic, Show, Eq, Ord, Enum)
                          
instance NFData ActionError

data FlowModError = TablesFull
                  | OverlappingFlow
                  | FlowModPermissionsError
                  | EmergencyModHasTimeouts
                  | BadCommand
                  | UnsupportedActionList
                  deriving (Generic, Show, Eq, Ord, Enum)
                    
instance NFData FlowModError

data PortModError = BadPort
                  | BadHardwareAddress
                  deriving (Generic, Show, Eq, Ord, Enum)                    

instance NFData PortModError

data QueueOpError = QueueOpBadPort
                  | QueueDoesNotExist
                  | QueueOpPermissionsError
                  deriving (Generic, Show, Eq, Ord, Enum)

instance NFData QueueOpError
