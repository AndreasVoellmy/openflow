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

-- | When a switch encounters an error condition, it sends the controller
-- a message containing the information in @SwitchErrorRecord@.
data SwitchError = HelloFailed          HelloFailure String
                 | BadRequest           RequestError [Word8]
                 | BadAction            ActionError  [Word8]
                 | FlowModFailed        FlowModError [Word8]
                 | PortModFailed        PortModError [Word8]
                 | QueueOperationFailed QueueOpError [Word8]
                 deriving (Show, Eq)
                                
data HelloFailure = IncompatibleVersions
                  | HelloPermissionsError
                  deriving (Show, Eq, Ord, Enum)
                           
data RequestError = VersionNotSupported
                  | MessageTypeNotSupported
                  | StatsRequestTypeNotSupported
                  | VendorNotSupported
                  | VendorSubtypeNotSupported
                  | RequestPermissionsError
                  | BadRequestLength
                  | BufferEmpty
                  | UnknownBuffer
                  deriving (Show, Eq, Ord, Enum)


data ActionError = UnknownActionType
                 | BadActionLength
                 | UnknownVendorID
                 | UnknownActionTypeForVendor
                 | BadOutPort
                 | BadActionArgument
                 | ActionPermissionsError
                 | TooManyActions
                 | InvalidQueue
                 deriving (Show, Eq, Ord, Enum)
                          
data FlowModError = TablesFull
                  | OverlappingFlow
                  | FlowModPermissionsError
                  | EmergencyModHasTimeouts
                  | BadCommand
                  | UnsupportedActionList
                  deriving (Show, Eq, Ord, Enum)
                    
data PortModError = BadPort
                  | BadHardwareAddress
                  deriving (Show, Eq, Ord, Enum)                    

data QueueOpError = QueueOpBadPort
                  | QueueDoesNotExist
                  | QueueOpPermissionsError
                  deriving (Show, Eq, Ord, Enum)

