-- a module serves the purpose of controlling namespaces and creating datatypes, functions, classes, use imports
-- Convention: module names capitalized, function names lowercased
module Main (main) where

import FirewallParser (parseFirewall, debugTokens)

-- la ruta debe ser DESDE DONDE SE CORRE, no importa la ubicacion del main.
testfile = "examples/test.fws"

-- what you want ur program to do (entry point of the whole application)
main :: IO ()
main = do
    input <- readFile testfile
    --putStrLn "TOKENS:" 
    --debugTokens input
    let info = parseFirewall input
    putStrLn $ "Parsed successfully! " ++ (show info)