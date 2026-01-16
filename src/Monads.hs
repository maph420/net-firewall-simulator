module Monads 
    (
        RWMonad,
        logMsg
    )
where

import Control.Monad.Writer.Strict (Writer, tell)
import Control.Monad.Reader (ReaderT, lift)
import Common
import qualified Data.Text as T

-- Se crea una monada usando un transformador, "envolviendo" la monada writer sobre la transformadora reader
type RWMonad a = ReaderT Env (Writer [LogEntry]) a

-- Helper function to log
logMsg :: LogLevel -> T.Text -> Maybe Packet -> RWMonad ()
logMsg level msg pkt = lift $ tell [LogEntry level msg pkt]
