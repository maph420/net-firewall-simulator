{-# LANGUAGE OverloadedStrings #-}

module Firewall
    ( 
        runFirewallSimulation,
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

--------------------------
-- Funciones auxiliares --
--------------------------

-- Agregar un Id a cada regla de cada chain
addRuleIds :: Info -> Info
addRuleIds info = info { infoRules = map addIdsToChain (infoRules info) }
  where
    addIdsToChain (target, rules) = (target, zipWith (\i r -> r {ruleId = "Rule Id " `T.append` T.pack (show i)}) ([1..] :: [Int]) rules)

-- Buscar dispositivo por IP 
findDeviceByIP :: IPV4.IPv4 -> [Device] -> Maybe Device
findDeviceByIP _ [] = Nothing
findDeviceByIP ip (d:ds) = if (ipv4Dir d) == ip then Just d else findDeviceByIP ip ds

-- Determinar el target del paquete, basado en si lo envia/recibe el firewall, o no
getPacketTarget :: Packet -> IPV4.IPv4 -> PacketTarget
getPacketTarget pkt fwIPAddr    | dstip pkt == fwIPAddr = Input
                                | srcip pkt == fwIPAddr = Output
                                | otherwise = Forward

-- Obtener reglas para el target (se admite que no haya sido definida un tipo de cadena, 
-- simplemente no retorna ninguna regla)
getRulesByTarget :: PacketTarget -> RulesChains -> [Rule]
getRulesByTarget target chains = case filter (\(t, _) -> t == target) chains of
                                    [(_, rules)] -> rules
                                    _ -> [] 

-- Modificar interfaz de entrada al firewall, para paquetes externos a la red.
-- (se asume que las IP desconocidas para la red provienen de internet)
adjustPacketInIf :: [Device] -> Packet -> Packet
adjustPacketInIf devices pkt =
    case (findDeviceByIP (srcip pkt) devices) of
        Nothing -> pkt { ingressif = defaultFwIf } 
        Just _ -> pkt 

-- Modificar interfaz de salida al firewall, para paquetes externos a la red.
adjustPacketOutIf :: [Device] -> Packet -> Packet
adjustPacketOutIf devices pkt =
    case (findDeviceByIP (dstip pkt) devices) of
        Nothing -> pkt { egressif = defaultFwIf } 
        Just _ -> pkt

-- Verifica si el paquete se envía desde y hacia una misma subnet (no pasa por firewall)
isIntraSubnetPacket :: Packet -> [Device] -> Bool
isIntraSubnetPacket p devices = (dstip p == IPV4.loopback) || intToInt
    where
    intToInt = case (findDeviceByIP (srcip p) devices, findDeviceByIP (dstip p) devices) of
                    (Just src, Just dst) -> subnetDir src == subnetDir dst
                    _ -> False

-- Verifica si el paquete se envía desde y hacia una IP remota (no pasa por firewall)
isExtToExtPacket :: Packet -> [Device] -> Bool
isExtToExtPacket p devices = isNothing (findDeviceByIP (srcip p) devices) && isNothing (findDeviceByIP (dstip p) devices)
  where
    isNothing Nothing = True
    isNothing _ = False

-- Buscar el dispositivo asociado al firewall
lookForFw :: [Device] -> Maybe Device
lookForFw [] = Nothing
lookForFw (d:ds) = if (T.toLower (devName d)) == "firewall" then Just d else lookForFw ds

-------------------------------------------------
-- Funciones de seguridad/chequeo del firewall --
-------------------------------------------------

-- Verificaciones de seguridad del firewall
-- Verifica y advierte de paquetes provenientes/hacia una ip desconocida y aquellos que
-- dicen salir/entrar por una interfaz que no corresponde a la definida en la  seccion subnets (posible ataque de spoofing)

securityCheck :: Packet -> [Device] -> WriterMonad ()
securityCheck p devices = do    
    -- origen
    case findDeviceByIP (srcip p) devices of
        Nothing -> do 
            logMsg' Warning ("Paquete proveniente de una IP desconocida (" 
                           `T.append` IPV4.encode (srcip p) `T.append` "). Se asume interfaz de entrada: "  
                           `T.append` defaultFwIf) (Just p)
        Just srcDevice -> do
            let iif = ingressif p
            if (T.null iif) || (iif == defaultFwIf) || (elem iif (interfaces srcDevice))
                then return ()
                else do logMsg' Warning ("Interfaz de entrada especificada en paquete incorrecta para " `T.append` devName srcDevice 
                               `T.append` ": " `T.append` ingressif p) (Just p)

    -- destino
    case findDeviceByIP (dstip p) devices of
        Nothing -> do
            logMsg' Warning ("Paquete destinado a una IP desconocida (" 
                           `T.append` IPV4.encode (dstip p) `T.append` "). Se asume interfaz de salida: "  
                           `T.append` defaultFwIf) (Just p)
        Just dstDevice -> do
            let oif = egressif p
            if (T.null oif) || (oif == defaultFwIf) || (elem oif (interfaces dstDevice))
                then return ()
                else do logMsg' Warning ("Interfaz de salida especificada en paquete incorrecta para " `T.append` devName dstDevice 
                               `T.append` ": " `T.append` egressif p) (Just p)


--------------------------------------
-- Funciones de logica del firewall --
--------------------------------------

-- Procesar un paquete de red. 
-- Dada la configuracion del firewall, determinar que accion realizar sobre el paquete

processPacket :: FirewallConfig -> Packet -> WriterMonad Action
processPacket config p = do
    
    let fwConf = fwDevices config
        adjustedPkt = adjustPacketInIf fwConf (adjustPacketOutIf fwConf p)
    
    if isIntraSubnetPacket adjustedPkt fwConf
        then do
            logMsg' Warning "Paquete intra-subnet (NO pasa por firewall)" (Just adjustedPkt)
            return Accept

        else 
            if isExtToExtPacket adjustedPkt fwConf
                then do
                    logMsg' Warning "Paquete externo detectado (NO pasa por firewall)" (Just adjustedPkt)
                    return Accept
                else do
                    securityCheck adjustedPkt fwConf
                    let target = getPacketTarget adjustedPkt (fwIP config)
                        rules = getRulesByTarget target (fwRules config)
                    evalChain rules adjustedPkt
 
                  
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
    eval' (MatchProt prot) = if (prot == ANY) then True else prot == (protocol pkt)
    eval' (MatchInIf mii) = mii == (ingressif pkt) 
    eval' (MatchOutIf moi) = moi == (egressif pkt)
    eval' (MatchSrcPort sps) = any (== srcport pkt) sps
    eval' (MatchDstPort dps) = any (== dstport pkt) dps
    eval' (AndMatch m1 m2) = (eval' m1) && (eval' m2)
    eval' (OrMatch m1 m2) = (eval' m1) || (eval' m2)


-- Crear estructura de informacion del firewall, partiendo de la estructura parseada Info
-- Si hay alguna inconsistencia semántica de la estructura parseada, lo detectará el validador de ast
buildConfig :: Info -> ErrAST FirewallConfig
buildConfig info = do
    astValidation info
    
    -- Obtiene una tupla con EL firewall, y el resto de dispositivos
    -- Si paso el ast validation, sabemos que existe exactamente 1 dispositivo firewall
    let devices = infoNetwork info
        firewall = lookForFw devices
    
    case firewall of
        Just fw -> do
            return FirewallConfig {
                fwIP = ipv4Dir fw,
                fwRules = infoRules info,
                fwDevices = devices
            }
        Nothing -> throwError "Error: El validador fallo en verificar el firewall"

-------------------------------------
-- funcion para iniciar simulacion --
-------------------------------------

runFirewallSimulation :: Info -> ([(Packet, Action)], [LogEntry])
runFirewallSimulation info = 
    -- primero aplicamos las id antes de verificar.
    let infoWithIds = addRuleIds info
    in case buildConfig infoWithIds of
        Left err -> 
            ([], [LogEntry Error err Nothing])
        Right config -> runSimulation config (infoPackets infoWithIds) 
    where
        runSimulation :: FirewallConfig -> [Packet] -> ([(Packet, Action)], [LogEntry])
        runSimulation config packets = 
            runWriter $ processAll config packets

        processAll :: FirewallConfig -> [Packet] -> WriterMonad [(Packet, Action)]
        processAll cfg pkts = mapM (\p -> do
                                        act <- processPacket cfg p
                                        return (p, act)) pkts

---------------------------
-- funciones de formateo --
---------------------------

-- Pasar de logs a texto imprimible.
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

-- Pasar de resultados a texto imprimible.
formatResults :: [(Packet, Action)] -> T.Text
formatResults pas = T.pack $ concatMap formatLine pas
  where
    formatLine (pkt, act) = printf "%-15s : \t%-10s\n" (show $ packid pkt) (T.unpack $ verboseAction act)
    verboseAction :: Action -> T.Text
    verboseAction Accept = "Accepted"
    verboseAction Drop = "Dropped"
    verboseAction Reject = "Rejected"
