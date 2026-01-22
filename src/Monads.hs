module Monads 
    (
        WriterMonad,
        logMsg',
        P,
        thenP,
        returnP,
        failP,
        catchP,
        mapP,
        ErrAST,
        throwError
    )
where

import Control.Monad.Writer.Strict (Writer, tell)
import Common
import qualified Data.Text as T
import Control.Monad.Except(throwError)

-- Monada usada para la logica del firewall, permite loggear informacion.
type WriterMonad a = Writer [LogEntry] a

-- Funcion helper para loggueo
logMsg' :: LogLevel -> T.Text -> Maybe Packet -> WriterMonad ()
logMsg' level msg mpkt = tell [LogEntry level msg mpkt]

-- Monada para el lexer, guarda dos valores de estado: la continuacion del computo y el numero de linea
type P a = String -> Int -> ParseResult a

-- definicion de operaciones de la monada
thenP :: P a -> (a -> P b) -> P b
m `thenP` k = \s l-> case m s l of
                         Ok a     -> k a s l
                         Failed e -> Failed e
                   
returnP :: a -> P a
returnP a = \_ _-> Ok a

failP :: String -> P a
failP err = \_ _ -> Failed err

catchP :: P a -> (String -> P a) -> P a
catchP m k = \s l -> case m s l of
                        Ok a     -> Ok a
                        Failed e -> k e s l

mapP :: (a -> P b) -> [a] -> P [b]
mapP _ []     = returnP []
mapP f (x:xs) = f x `thenP` \r ->
                mapP f xs `thenP` \rs ->
                returnP (r:rs)

-- monada para validacion del AST, permite propagar errores durante los multiples chequeos
type ErrAST a = Either T.Text a
