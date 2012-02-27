{-# LANGUAGE CPP #-}

module Nettle.OpenFlow.Error ( 
  SwitchError (..)
  , HelloFailure (..)
  , RequestError (..)
  , ActionError (..)
  , FlowModError (..)
  , PortModError (..)
#if OPENFLOW_VERSION==152 || OPENFLOW_VERSION==1  
  , QueueOpError (..)
#endif
  ) where

import Data.Word

-- | When a switch encounters an error condition, it sends the controller
-- a message containing the information in @SwitchErrorRecord@.
data SwitchError = HelloFailed          HelloFailure String
                 | BadRequest           RequestError [Word8]
#if OPENFLOW_VERSION==151
                 | BadAction Word16 [Word8]
                 | FlowModFailed Word16 [Word8]
#endif
#if OPENFLOW_VERSION==152 || OPENFLOW_VERSION==1                       
                 | BadAction            ActionError  [Word8]
                 | FlowModFailed        FlowModError [Word8]
                 | PortModFailed        PortModError [Word8]
                 | QueueOperationFailed QueueOpError [Word8]
#endif
                       deriving (Show, Eq)
                                
data HelloFailure = IncompatibleVersions
#if OPENFLOW_VERSION==152 || OPENFLOW_VERSION==1
                  | HelloPermissionsError
#endif
                  deriving (Show, Eq, Ord, Enum)
                           
data RequestError = VersionNotSupported
                  | MessageTypeNotSupported
                  | StatsRequestTypeNotSupported
                  | VendorNotSupported
                  | VendorSubtypeNotSupported
                  | RequestPermissionsError
#if OPENFLOW_VERSION==1                  
                  | BadRequestLength
                  | BufferEmpty
                  | UnknownBuffer
#endif
                  deriving (Show, Eq, Ord, Enum)


data ActionError = UnknownActionType
                 | BadActionLength
                 | UnknownVendorID
                 | UnknownActionTypeForVendor
                 | BadOutPort
                 | BadActionArgument
#if OPENFLOW_VERSION==152 || OPENFLOW_VERSION==1 
                 | ActionPermissionsError
#endif
#if OPENFLOW_VERSION==1                   
                 | TooManyActions
                 | InvalidQueue
#endif
                 deriving (Show, Eq, Ord, Enum)
                          
data FlowModError = TablesFull
                  | OverlappingFlow
                  | FlowModPermissionsError
                  | EmergencyModHasTimeouts
#if OPENFLOW_VERSION==1                  
                  | BadCommand
                  | UnsupportedActionList
#endif
                  deriving (Show, Eq, Ord, Enum)
                    
data PortModError = BadPort | BadHardwareAddress deriving (Show, Eq, Ord, Enum)                    

data QueueOpError = QueueOpBadPort | QueueDoesNotExist | QueueOpPermissionsError deriving (Show, Eq, Ord, Enum)

