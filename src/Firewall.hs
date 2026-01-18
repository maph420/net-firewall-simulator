{-# LANGUAGE OverloadedStrings #-}
-- para que trate a los String como Data.Text 

-- implementar, dados los AST de: la config de red, los envios realizados y las reglas, el firewall que decidirá qué paquetes
-- pasan y cuales no.

-- -srcip 192.168.1.0 -dstip 192.168.2.0 -prot udp -outif eth0
-- MatchAnd (MatchAnd (MarchSrcIP 192.168.1.0) (MatchDstIP 192.168.2.0)) (MatchAnd (MatchProt UDP) (MatchOutIf "eth0"))

-- -dstip 10.0.0.1 -prot tcp -inif eth1 -outif ppp0 -dstp [80]
-- MatchAnd (MatchAnd (MatchDstIP 10.0.0.1) (MatchProt TCP)) (MatchAnd (MatchInIf "eth1") (MatchAnd (MatchOutIf "ppp0") (MatchDstIP PortList)))

-- -srcip 10.0.0.2/16 -prot udp -dstp [53,443]
-- MatchAnd (MatchAnd (MatchSrcSubnet 10.0.0.2/16) (MatchProt UDP)) (MatchSrcPort [53, 443])

-- lo que nos llega a nosotros desp del parseo, 

module Firewall
    ( 
        runFirewallSimulation,
        buildEnv,
        formatLogs
    ) where

import Common
import Monads
import Control.Monad.Writer.Strict (runWriter)
import Control.Monad.Reader (ask, runReaderT)
import qualified Net.IPv4 as IPV4
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import PrettyPrinter (renderMatch)

-- Verificamos que el paquete provenga de una IP conocida y de una interfaz de red existente del origen.
-- Previene un posible ataque de spoofing

-- Tambien aca (o en la misma fase) CHEQUEAR que se haya provisto un IP de firewall,
-- y que la misma sea valida (sin IP de firewall no se puede proseguir)

securityCheck :: Packet -> RWMonad Bool
securityCheck p = do 
    env <- ask
    case M.lookup (srcip p) (deviceInterfaces env) of
        Nothing -> do
            logMsg Warning "paquete proveniente de IP desconocida en la red." (Just p)
            return False
        Just ifs -> do
            if (elem (ingressif p) ifs)
                then return True
                else do
                    logMsg Warning "paquete proveniente de una interfaz de red incorrecta." (Just p)
                    return False

-- decidir, segun el origen/destino del paquete, el objetivo del mismo (input/output/forward)
getTargetChain :: Packet -> RWMonad [Rule]
getTargetChain p = do
    env <- ask
    let fwIP = firewallIP env
        chainsMap = rulesChains env
        key = if dstip p == fwIP
                 then Input
                 else if srcip p == fwIP
                       then Output
                       else Forward
    -- returns the value at key k or returns default value def when the key is not in the map. (capaz no hay reglas para input, por ejemplo)
    return $ M.findWithDefault [] key chainsMap

processPacket :: Packet -> RWMonad Action
processPacket p = do
    valid <- securityCheck p
    if (not valid)
        then return Drop -- lo recomendado con paquetes sospechosos es descartarlos "silenciosamente", en lugar de reject y avisar a la fuente
        else do 
            chain <- getTargetChain p
            evalChain chain p
            

-- conj de reglas vacias -> no corto antes -> no matchea ninguna regla (esto es si ni siquiera se especifico drop policy para la chain)
evalChain :: [Rule] -> Packet -> RWMonad Action
evalChain [ ] _ = return Drop
evalChain (r:rs) pkt = do
                    success <- eval (ruleMatch r) pkt
                    if success 
                        then do
                            logMsg Information ("Paquete " `T.append` packid pkt `T.append` " coincidió con regla " `T.append` (renderMatch $ ruleMatch r) `T.append` " (id: " `T.append` (ruleId r) `T.append`
                                            "), acción: " `T.append` T.pack (show (ruleAction r))) (Just pkt)
                            return (ruleAction r) 
                        else do
                            logMsg Information ("Paquete "  `T.append` packid pkt  `T.append` 
                                            " no coincidió con regla "  `T.append` (renderMatch $ ruleMatch r) `T.append` " (id " `T.append` (ruleId r) `T.append` ")") (Just pkt)
                            evalChain rs pkt


-- evaluador puro???
eval :: Match -> Packet -> RWMonad Bool
eval m pkt = let matched = eval' m in return matched
    where
        eval' :: Match -> Bool
        eval'  MatchAny = True
        eval' (MatchSrcIP msip) = msip == (srcip pkt)
        eval' (MatchDstIP mdip) = mdip == (dstip pkt)
        eval' (MatchSrcSubnet mss) = IPV4.contains mss (srcip pkt)
        eval' (MatchDstSubnet mds) = IPV4.contains mds (dstip pkt)
        eval' (MatchProt prot) = prot == (protocol pkt)
        eval' (MatchInIf mii) = mii == (ingressif pkt) 
        eval' (MatchOutIf moi) = moi == (egressif pkt)
        eval' (MatchSrcPort sps) = any (== srcport pkt) sps
        eval' (MatchDstPort dps) = any (== dstport pkt) dps
        eval' (AndMatch m1 m2) = (eval' m1) && (eval' m2)
        -- capaz no hacen falta estas
        eval' (OrMatch m1 m2) = (eval' m1) || (eval' m2)
        eval' (NotMatch m') = not (eval' m')


-- funca a priori
buildEnv :: Info -> Either T.Text Env
buildEnv info = do
    -- encontrar el dispositivo de firewall, por nombre
    let firewallDevices = filter (\d -> devName d == "firewall") (infoNetwork info)
    
    firewall <- case firewallDevices of
        [] -> Left "Error: No se encontro ningún dispositivo 'firewall' en la config de red. Abortando."
        [d] -> Right d
        _ -> Left "Error: Se encontraron multiples dispositivos 'firewall' en la config de red. Abortando."
    
    -- armar el mapa de interfaces
    let interfaceMap = M.fromList $ 
            map (\d -> (ipv4Dir d, interfaces d)) (infoNetwork info)
    
    return Env {
        deviceInterfaces = interfaceMap,
        firewallIP = ipv4Dir firewall,
        rulesChains = infoRules info
    }


-- Dada una estructura de informacion del parseo retorna o bien:
-- Una lista de tuplas (paquete_procesado, accion_tomada)
-- o bien un texto de error, simbolizando un error de sanidad de input del script (e.g. no se especifico un dispositivo firewall)


runFirewallSimulation :: Info -> ([(Packet, Action)], [LogEntry])
runFirewallSimulation info = 
    case buildEnv info of
        Left err -> 
            ([], [LogEntry Error ("Error durante la creacion del ambiente: " `T.append` err) Nothing])
        Right env -> runSimulation env (infoPackets info)

runSimulation :: Env -> [Packet] -> ([(Packet, Action)], [LogEntry])
-- le pasa a la monada: la estructura resultado ([Packet,Action]) y el ambiente estatico a utilizar
runSimulation env packets = 
    runWriter $ runReaderT (processAll packets) env
  where
    processAll :: [Packet] -> RWMonad [(Packet, Action)]
    processAll pkts = mapM (\p -> do
                            act <- processPacket p
                            return (p, act)) pkts


-- pasar de logs a texto.
formatLogs :: [LogEntry] -> T.Text
formatLogs logs = T.unlines $ map formatLogEntry logs
  where
    formatLogEntry :: LogEntry -> T.Text
    formatLogEntry (LogEntry level msg mpkt) = 
        let levelStr = case level of
                         Information -> "INFO"
                         Warning -> "ADVERTENCIA"
                         Error -> "ERROR"
            pktInfo = case mpkt of
                        Nothing -> ""
                        Just pkt' -> " [Paquete: " `T.append` packid pkt' `T.append` "]"
        in levelStr `T.append` ": " `T.append` msg `T.append` pktInfo