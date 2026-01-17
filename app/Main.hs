module Main (main) where

import FirewallParser (parseFirewall)
import Firewall (runFirewallSimulation, buildEnv, formatLogs)
import Common
import Data.Text as T

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
        Failed errstr   ->  putStrLn $ "Ocurrio un error durante el parseo: \n" ++ errstr
        Ok info         ->  do
                            putStrLn $ "Parsed successfully!\n" ++ (Prelude.show info)
                            let (resols, logs) = runFirewallSimulation info
                            putStrLn $ "Decisiones tomadas sobre cada paquete: " ++ (Prelude.show resols)
                            putStrLn $ "Logs extraidos: " ++ (T.unpack (formatLogs logs))



-- TODO: ponerle id's a las reglas
-- pretty printer, parece que no me escapo..........