module Main (main) where

import FirewallParser (parseFirewall)
import Common

-- la ruta debe ser DESDE DONDE SE CORRE, no importa la ubicacion del main.
testfile :: String
testfile = "examples/multips.fws"

-- entry point
-- capaz ver si se puede hacer un readFile safe.
main :: IO ()
main = do
    input <- readFile testfile
    let res = parseFirewall input
    case res of
        Failed errstr -> putStrLn $ "Ocurrio un error durante el parseo: \n" ++ errstr
        Ok info -> putStrLn $ "Parsed successfully!\n" ++ (show info)
   

