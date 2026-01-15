module Monads 
    (
        RWMonad
    )
where

import Control.Monad.Writer.Strict (Writer)
import Control.Monad.Reader (ReaderT)
import Common
import qualified Data.Text as T
-- capaz hay que importar text y la def de Env

-- Se crea una monada usando un transformador, "envolviendo" la monada writer sobre la transformadora reader
type RWMonad a = ReaderT Env (Writer T.Text) a
