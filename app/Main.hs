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

-- State of the interactive shell
data ShellState = ShellState
    { currentConfig :: Maybe Info
    , exitFlag :: Bool
    }

exampleFile :: String
exampleFile = "examples/test.fws"

firewallSimFileExtension :: String
firewallSimFileExtension = "fws"

initialState :: ShellState
initialState = ShellState Nothing False

-- Available commands
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
currVersionText = "1.0"

-- Main REPL
main :: IO ()
main = do
    putStrLn "======================================================="
    putStrLn $ firewallText ++ simulatorText ++ " v" ++ currVersionText
    putStrLn "=======================================================\n"
    putStrLn "Escribir :help o :? para ver los comandos disponibles."
    putStrLn ""
    runInputT defaultSettings (shellLoop initialState)

shellLoop :: ShellState -> InputT IO ()
shellLoop state = do
    if exitFlag state then
        return ()
    else do
        input <- getInputLine "FW> "
        
        case input of
            Nothing -> return ()  
            Just "" -> shellLoop state 
            Just line -> do
                let cmd = parseCommand line
                newState <- handleCommand state cmd
                shellLoop newState

-- Parse user input into a Command
parseCommand :: String -> Command
parseCommand input
    | (hd == ":load" || hd == ":l") && Prelude.length parts > 1 = Load (Prelude.unwords $ (Prelude.drop 1) parts)
    | hd == ":quit" || hd == ":q" = Quit
    | hd == ":help" || hd == ":h" || hd == ":?" = Help
    | otherwise = Unknown input
  where
    parts = Prelude.words input
    hd = case parts of
        [] -> ""
        (x:_) -> x

-- Handle commands
handleCommand :: ShellState -> Command -> InputT IO ShellState
handleCommand state cmd = case cmd of
    Load filename -> do 
        liftIO $ putStrLn $ "Cargando archivo: " ++ filename
        result <- liftIO $ parseAndLoad filename
        case result of
            Left err -> do
                outputStrLn $ "Error: " ++ err
                return state
            Right info -> do
                outputStrLn "Configuracion cargada..."
                outputStrLn $ "----------------------------------------------------------------------------"
                let (resols, logs) = runFirewallSimulation info
                --outputStrLn $ Prelude.show info
                let res = formatResults resols
                if (T.null res)
                    then outputStrLn $ "Sin decisiones tomadas.\n"
                    else do
                        outputStrLn $ "==========================================="
                        outputStrLn $ "Decisiones tomadas sobre cada paquete:"
                        outputStrLn $ "==========================================="
                        outputStrLn $ T.unpack res
                
                outputStrLn $ "==========================================="
                outputStrLn $ "Logs extraidos:"
                outputStrLn $ "==========================================="
                outputStrLn $ T.unpack $ formatLogs logs
                outputStrLn $ "----------------------------------------------------------------------------"
                return $ state { currentConfig = Just info }
    
    Quit -> do
        outputStrLn "Saliendo del simulador de firewall..."
        return $ state { exitFlag = True }
    
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
        return state
    
    Unknown input -> do
        outputStrLn $ "Comando desconocido: " ++ input
        outputStrLn "Escribir :help o :? para ver los comandos disponibles."
        return state

-- Parse and load a firewall configuration file
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


