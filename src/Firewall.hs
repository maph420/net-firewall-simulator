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
    ( firewall
    ) where

import Common
import Monads
import Control.Monad.Writer.Strict (tell)
import Control.Monad.Reader (ask)
import qualified Data.Map.Strict as M

-- Verificamos que el paquete provenga de una IP conocida y de una interfaz de red existente del origen.
-- Previene un posible ataque de spoofing
securityCheck :: Packet -> RWMonad Bool
securityCheck p = do 
    env <- ask
    case M.lookup (srcip p) (deviceInterfaces env) of
        Nothing -> do
            tell "Advertencia: paquete proveniente de IP desconocida en la red."
            return False
        Just ifs -> do
            if (elem (ingressif p) ifs)
                then return True
                else do
                    tell "Advertencia: paquete proveniente de una interfaz de red incorrecta!"
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
            act <- evalChain chain p
            return act


-- TODO: implementar logica del firewall para filtrar 1 paquete
evalChain :: [Rule] -> Packet -> RWMonad Action
evalChain p = undefined


-- falta: hacer extractor de informacion raw (desde info) hacia el entorno de la mónada, Env

-- funcion que mapee la funcion processPacket a cada paquete
-- funcion que junte los resultados y vaya loggeando la informacion


firewall = undefined
