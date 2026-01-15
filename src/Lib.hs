-- se exporta el metodo someFunc para poder ser usado por otros modulos
module Lib
    ( someFunc
    ) where

someFunc :: IO ()
someFunc = putStrLn "someFunc"
