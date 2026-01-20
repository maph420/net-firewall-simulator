module Monads 
    (
        RWMonad,
        logMsg,
        P,
        thenP,
        returnP,
        failP,
        catchP,
        mapP
    )
where

import Control.Monad.Writer.Strict (Writer, tell)
import Control.Monad.Reader (ReaderT, lift)
import Common
import qualified Data.Text as T

-- Se crea una monada usando un transformador, "envolviendo" la monada writer sobre la transformadora reader
type RWMonad a = ReaderT Env (Writer [LogEntry]) a

-- Funcion helper para loggueo
logMsg :: LogLevel -> T.Text -> Maybe Packet -> RWMonad ()
logMsg level msg pkt = lift $ tell [LogEntry level msg pkt]

-- Monada para el lexer, guarda dos valores de estado: la continuacion del cómputo y el numero de linea
type P a = String -> Int -> ParseResult a

-- definicion de operaciones de la monada
thenP :: P a -> (a -> P b) -> P b
m `thenP` k = \s l-> case m s l of
                         Ok a     -> k a s l
                         Failed e -> Failed e
                   
returnP :: a -> P a
returnP a = \_ _-> Ok a

-- Operaciones adicionales de la monada (no se usaron aun)
failP :: String -> P a
failP err = \_ _ -> Failed err

catchP :: P a -> (String -> P a) -> P a
catchP m k = \s l -> case m s l of
                        Ok a     -> Ok a
                        Failed e -> k e s l

mapP :: (a -> P b) -> [a] -> P [b]
mapP f []     = returnP []
mapP f (x:xs) = f x `thenP` \r ->
                mapP f xs `thenP` \rs ->
                returnP (r:rs)