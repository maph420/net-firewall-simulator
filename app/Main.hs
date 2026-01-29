module Main 
    (
        main
    )
where

import System.Console.Haskeline
import Control.Monad.Trans (liftIO)
import FirewallParser (parseFirewall)
import Common
import Control.Exception (catch, IOException)
import Data.Text as T
import Firewall (runFirewallSimulation, formatLogs, formatResults)

exampleFile :: String
exampleFile = "examples/test.fws"

firewallSimFileExtension :: String
firewallSimFileExtension = "fws"

-- Comandos a disposicion
data Command = Load String | Quit | Help | Unknown String

firewallText :: String
firewallText = 
  "  __ _                        _ _ \n\
  \ / _(_)                      | | |\n\
  \| |_ _ _ __ _____      ____ _| | |\n\
  \|  _| | '__/ _ \\ \\ /\\ / / _` | | |\n\
  \| | | | | |  __/\\ V  V / (_| | | |\n\
  \|_| |_|_|  \\___| \\_/\\_/ \\__,_|_|_|"

simulatorText :: String
simulatorText = "\tSimulator"

currVersionText :: String
currVersionText = "1.1"

-- punto de entrada del programa
main :: IO ()
main = do
    putStrLn "======================================================="
    putStrLn $ firewallText ++ simulatorText ++ " v" ++ currVersionText
    putStrLn "=======================================================\n"
    putStrLn "Escribir :help o :? para ver los comandos disponibles."
    putStrLn ""
    runInputT defaultSettings shellLoop

shellLoop :: InputT IO ()
shellLoop = do
    input <- getInputLine "FW> "
    case input of
        Nothing -> return () 
        Just "" -> shellLoop
        Just line -> do
            let cmd = parseCommand line
            continue <- handleCommand cmd
            if continue 
                then shellLoop
                else return ()

-- Interpretar texto ingresado por consola en un comando (se permite cargar archivos con espacio)
parseCommand :: String -> Command
parseCommand input  | (safeHdParts == ":load" || safeHdParts == ":l") && Prelude.length parts > 1 = Load (Prelude.unwords $ (Prelude.drop 1) parts)
                    | safeHdParts == ":quit" || safeHdParts == ":q" = Quit
                    | safeHdParts == ":help" || safeHdParts == ":h" || safeHdParts == ":?" = Help
                    | otherwise = Unknown input
  where
    parts = Prelude.words input
    safeHdParts = case parts of
                        [] -> ""
                        (x:_) -> x

-- Manejar comandos segun lo ingresado por terminal
handleCommand :: Command -> InputT IO Bool
handleCommand cmd = case cmd of
    Load filename -> do 
        liftIO $ putStrLn $ "Cargando archivo: " ++ filename
        result <- liftIO $ parseAndLoad filename
        case result of
            Left err -> do
                outputStrLn $ "Error: " ++ err
                return True
            Right info -> do
                outputStrLn "Configuracion cargada..."
                outputStrLn $ "----------------------------------------------------------------------------"
                let (resols, logs) = runFirewallSimulation info
                let res = formatResults resols
                if (T.null res)
                    then outputStrLn $ "Sin decisiones tomadas.\n"
                    else do
                        outputStrLn $ "==========================================="
                        outputStrLn $ "Decisiones tomadas sobre cada paquete:"
                        outputStrLn $ "==========================================="
                        outputStrLn $ T.unpack res
                
                outputStrLn $ "================="
                outputStrLn $ "Logs extraidos"
                outputStrLn $ "================="
                outputStrLn $ T.unpack $ formatLogs logs
                outputStrLn $ "----------------------------------------------------------------------------"
                return True
    
    Quit -> do
        outputStrLn "Saliendo del simulador de firewall..."
        return False
    
    Help -> do
        outputStrLn "Comandos disponibles:"
        outputStrLn "  :load <filename>    Cargar el archivo especificado"
        outputStrLn "  :quit               Salir del simulador"
        outputStrLn "  :help, :?           Mostrar ayuda"
        outputStrLn ""
        outputStrLn "Tambien se pueden usar las abreviaciones :l, :q, :h"
        outputStrLn ""
        outputStrLn "Ejemplo:"
        outputStrLn $ "  :load " ++ exampleFile 
        outputStrLn $ "  :l " ++ exampleFile 
        outputStrLn ""
        return True
    
    Unknown input -> do
        outputStrLn $ "Comando desconocido: " ++ input
        outputStrLn "Escribir :help o :? para ver los comandos disponibles."
        return True

-- Cargar un archivo de firewall, de manera segura
parseAndLoad :: String -> IO (Either String Info)
parseAndLoad filename = do
    let prefix = Prelude.drop ((Prelude.length filename) - 4) filename
    if prefix /= ("." ++ firewallSimFileExtension)
        then return $ Left $ "Extension de archivo no coincide con la del simulador (." ++ firewallSimFileExtension ++ ") o bien no existe ruta especificada."
        else do
            content' <- (fmap Right $ readFile filename) `catch` (\exc -> return $ Left $ Prelude.show (exc :: IOException))
            case content' of
                Left err -> return $ Left err
                Right content ->
                        case parseFirewall content  of
                            Failed err -> return $ Left err
                            Ok info -> return $ Right info
