{-# LANGUAGE OverloadedStrings #-}

module Firewall
    ( 
        runFirewallSimulation,
        buildConfig,
        formatLogs,
        formatResults
    ) where

import Common
import Monads
import Validator (astValidation)
import Control.Monad.Writer.Strict (runWriter)
import qualified Net.IPv4 as IPV4
import qualified Data.Text as T
import Text.Printf (printf)
import PrettyPrinter (renderMatch)
import Data.List (find)

-- Agregar un Id a cada regla de cada chain.
addRuleIds :: Info -> Info
addRuleIds info = info { infoRules = map addIdsToChain (infoRules info) }
  where
    addIdsToChain (target, rules) = (target, zipWith (\i r -> r {ruleId = "Rule Id " <> T.pack (show i)}) ([1..] :: [Int]) rules)

-- Configuracion del firewall
data FirewallConfig = FirewallConfig {
    fwIP :: IPV4.IPv4,
    fwRules :: RulesChains,
    fwDevices :: [Device]
}

-- Buscar dispositivo por IP (?)
findDeviceByIP :: IPV4.IPv4 -> [Device] -> Maybe Device
findDeviceByIP ip = find (\d -> ipv4Dir d == ip)

-- Determinar el target del paquete
getPacketTarget :: Packet -> IPV4.IPv4 -> PacketTarget
getPacketTarget pkt fwIPAddr
    | dstip pkt == fwIPAddr = Input
    | srcip pkt == fwIPAddr = Output
    | otherwise = Forward

-- Obtener reglas para el target
getRulesForTarget :: PacketTarget -> RulesChains -> [Rule]
getRulesForTarget target chains = case filter (\(t, _) -> t == target) chains of
                                [(_, rules)] -> rules
                                _ -> [] 

-- Modificar interfaz de entrada al firewall, para paquetes externos a la red.
adjustInternetPacket :: [Device] -> Packet -> Packet
adjustInternetPacket devices pkt =
    case findDeviceByIP (srcip pkt) devices of
        Nothing -> pkt { ingressif = defaultInIf }  -- IP desconocida => viene de internet, convenimos usar "eth3"
        Just _ -> pkt  -- IP conocida => mantener interfaz original

-- Verificación de seguridad (con ajuste de interfaz para internet)
securityCheck :: Packet -> [Device] -> WriterMonad ()
securityCheck p devices = 
    case findDeviceByIP (srcip p) devices of
        Nothing -> do 
            logMsg' Warning ("Paquete proveniente de una IP desconocida (" `T.append` IPV4.encode (srcip p) `T.append` "). Se asume interfaz de entrada: "  `T.append` defaultInIf) (Just p)
        Just device -> do
            let iif = ingressif p
            if (T.null iif) || (iif == defaultInIf) || (elem iif (interfaces device))
                then return ()
                else do logMsg' Warning ("Paquete proveniente de interfaz incorrecta. (" 
                           `T.append` iif `T.append` ")") (Just p)

-- El paquete, pasa por el firewall?
shouldBeProcessedByFirewall :: Packet -> [Device] -> Bool
shouldBeProcessedByFirewall p devices =
    case (findDeviceByIP (srcip p) devices, findDeviceByIP (dstip p) devices) of
        (Just src, Just dst) -> subnet src /= subnet dst
        _ -> True

-- Procesar paquete con configuración explícita
processPacket :: FirewallConfig -> Packet -> WriterMonad Action
processPacket config p = do
    -- Primero ajustar el paquete si viene de internet
    let adjustedPkt = adjustInternetPacket (fwDevices config) p
    
    if shouldBeProcessedByFirewall adjustedPkt (fwDevices config)
        then do
            securityCheck adjustedPkt (fwDevices config)
            let target = getPacketTarget adjustedPkt (fwIP config)
                rules = getRulesForTarget target (fwRules config)
            evalChain rules adjustedPkt
        else do
            logMsg' Warning ("Paquete intra-subnet (no pasa por firewall): " 
                           `T.append` packid adjustedPkt) (Just adjustedPkt)
            return Accept

-- Evaluar cadena de reglas
evalChain :: [Rule] -> Packet -> WriterMonad Action
evalChain [] _ = return Drop
evalChain (r:rs) pkt = do
    let success = eval (ruleMatch r) pkt
    if success 
        then do
            logMsg' Information ("Regla matcheada: " `T.append` (renderMatch $ ruleMatch r) 
                               `T.append` " (" `T.append` ruleId r `T.append` ")") (Just pkt)
            return (ruleAction r)
        else do
            logMsg' Information ("Regla NO matcheada: " `T.append` (renderMatch $ ruleMatch r) 
                               `T.append` " (" `T.append` ruleId r `T.append` ")") (Just pkt)
            evalChain rs pkt

-- Evaluar match contra paquete
eval :: Match -> Packet -> Bool
eval m pkt = eval' m
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
    eval' (OrMatch m1 m2) = (eval' m1) || (eval' m2)
    eval' (NotMatch m') = not (eval' m')

-- Crear entorno (?)
buildConfig :: Info -> ErrAST FirewallConfig
buildConfig info = do
    validatedInfo <- astValidation info
    
    let firewallDevices = filter (\d -> T.toLower (devName d) == "firewall") 
                           (infoNetwork validatedInfo)
    
    firewall <- case firewallDevices of
        [d] -> Right d
        _ -> Left "Error: El validador fallo en verificar el firewall"
    
    return FirewallConfig {
        fwIP = ipv4Dir firewall,
        fwRules = infoRules validatedInfo,
        fwDevices = infoNetwork validatedInfo
    }

runFirewallSimulation :: Info -> ([(Packet, Action)], [LogEntry])
runFirewallSimulation info = 
    -- primero aplicamos las id antes de verificar.
    let infoWithIds = addRuleIds info
    in case buildConfig infoWithIds of
        Left err -> 
            ([], [LogEntry Error err Nothing])
        Right config -> runSimulation config (infoPackets infoWithIds)

runSimulation :: FirewallConfig -> [Packet] -> ([(Packet, Action)], [LogEntry])
runSimulation config packets = 
    runWriter $ processAll config packets
  where
    processAll :: FirewallConfig -> [Packet] -> WriterMonad [(Packet, Action)]
    processAll cfg pkts = mapM (\p -> do
                                        act <- processPacket cfg p
                                        return (p, act)) pkts

-- pasar de logs a texto.
formatLogs :: [LogEntry] -> T.Text
formatLogs logs = T.unlines $ zipWith formatEntry ([1..] :: [Int]) logs
  where
    formatEntry :: Int -> LogEntry -> T.Text
    formatEntry n (LogEntry level msg mpkt) = 
        let levelStr = case level of
                         Information -> "INFO"
                         Warning -> "ADVERTENCIA"
                         Error -> "ERROR"
            pktInfo = case mpkt of
                        Nothing -> ""
                        Just pkt' -> "Paquete " `T.append` packid pkt' `T.append` " - "
        in T.justifyRight 4 ' ' (T.pack (show n)) `T.append` ". [" 
           `T.append` levelStr `T.append` "] " `T.append` pktInfo `T.append` msg `T.append` "\n"

formatResults :: [(Packet, Action)] -> T.Text
formatResults pas = T.pack $ concatMap formatLine pas
  where
    formatLine (pkt, act) = printf "%-15s : \t%s\n" (show $ packid pkt) (T.unpack $ verboseAction act)
    verboseAction :: Action -> T.Text
    verboseAction Accept = "Accepted"
    verboseAction Drop = "Dropped"
    verboseAction Reject = "Rejected"