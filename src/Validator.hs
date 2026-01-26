{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
module Validator
(
    astValidation
) 
where

import Common
import Monads
import Data.Text as T
import Net.IPv4 as IPV4
import qualified Data.Set as S

astValidation :: Info -> ErrAST Info
astValidation inf = do 
                        let rules = infoRules inf
                            network = infoNetwork inf
                            packets = infoPackets inf

                        checkRepeatedChains rules 
                        checkSubnetRanges network 
                        checkFirewall network 
                        -- unicidad de identificadores de dispositivos, paquetes, dir mac, ip
                        checkForIdentifiers network devName (\dn -> "el dispositivo de nombre '" `T.append` dn `T.append` "' aparece repetido\n")
                        checkForIdentifiers packets packid (\paid -> "el paquete de nombre '" `T.append` paid `T.append` "' aparece repetido\n")
                        checkForIdentifiers network macDir (\md -> "la direccion MAC '" `T.append` md `T.append` "' aparece repetida\n")
                        checkForIPIdentif network (\ipdir -> "la direccion IPv4 '" `T.append` (IPV4.encode ipdir) `T.append` "' aparece repetida.\n")
                        checkChainRules rules  
                        return inf

-- Verifica si una misma chain fue declarada mas de una vez
checkRepeatedChains :: RulesChains -> ErrAST ()
checkRepeatedChains rulc = mapM_ check rulc
    where
        check :: (PacketTarget, [Rule]) -> ErrAST ()
        check (target, _) =  let 
                                matches = Prelude.filter (\(pt, _) -> target == pt) rulc
                             in
                                if (Prelude.length matches > 1)
                                    then throwError $ "cadena " `T.append` (T.show target) `T.append` " aparece repetida\n" 
                                    else return ()

-- Verifica que toda ip suministrada coincida con la subnet en donde esta definida
checkSubnetRanges :: Network -> ErrAST ()
checkSubnetRanges = mapM_ checkDevice 
    where
        checkDevice :: Device -> ErrAST ()
        checkDevice d = if (subnet d) `IPV4.contains` (ipv4Dir d) 
                            then return ()
                            else throwError $ "la ip " `T.append` (encode (ipv4Dir d)) `T.append` 
                            " no pertenece al rango subnet: " `T.append` (encodeRange (subnet d)) `T.append` "\n"

-- Verifica si un identificador dado aparece repetido en la lista pasada. Se pasa el extractor de campo para saber por cual del registro se quiere chequear.
-- Si hay repeticion, llama a una funcion que formatea el error.
checkForIdentifiers :: [a] -> (a -> T.Text) -> (T.Text -> T.Text) -> ErrAST ()
checkForIdentifiers xs fieldExtr formatErr = checkForIdentifiers' xs S.empty
  where
        checkForIdentifiers' [] _ = return ()
        checkForIdentifiers' (y:ys) acc = do
                                        let identif = T.toLower $ fieldExtr y 
                                        if S.member identif acc
                                            then throwError $ formatErr identif
                                            else checkForIdentifiers' ys (S.insert identif acc)

-- Similar a checkForIdentifiers, pero trabaja con ipv4 en vez de identificadores de texto
checkForIPIdentif :: Network -> (IPV4.IPv4 -> T.Text) -> ErrAST ()
checkForIPIdentif net formatErr = checkForIPIdentif' net S.empty
    where
        checkForIPIdentif' [] _ = return ()
        checkForIPIdentif' (x:xs) acc = do
                                    let currip = ipv4Dir x
                                    if S.member currip acc
                                        then throwError $ formatErr currip
                                        else checkForIPIdentif' xs (S.insert currip acc)

-- Verifica que exista un dispositivo llamado 'firewall' y que sea ruteable a internet (para recibir paquetes del exterior)
-- adicionalmente chequea, para todo dispositivo que no sea el firewall, que tenga exactamente 1 interfaz definida. (aclarar en el readme)
checkFirewall :: Network -> ErrAST ()
checkFirewall [] = throwError $ "no se reconoce ningún dispostivo llamado 'firewall', abortando\n"
checkFirewall (d:ds) = if (T.toLower $ devName d) == "firewall"
                        then if IPV4.public (ipv4Dir d)
                                then return ()
                                else throwError $ "la IP del dispositivo de firewall debe ser ruteable en internet (IP pública). Ip provista: " `T.append` (IPV4.encode (ipv4Dir d))
                        else 
                            if (Prelude.length $ interfaces d) > 1
                                then throwError $ "Un dispositivo que no es el firewall posee más de una interfaz. Interfaces provistas: " `T.append` (T.show (interfaces d))
                                else checkFirewall ds

-- Verifica que ninguna regla de la cadena INPUT tenga una restriccion '-outif', ni una OUTPUT una '-inif'
checkChainRules :: RulesChains -> ErrAST ()
checkChainRules = mapM_ checkChainRule
    where
        checkChainRule :: (PacketTarget, [Rule]) -> ErrAST ()
        checkChainRule (pt, rs) = mapM_ (checkRuleForChain pt) rs

        checkRuleForChain :: PacketTarget -> Rule -> ErrAST ()
        checkRuleForChain target rule   | target == Input && containsMatchType (MatchOutIf "") (ruleMatch rule) =
            throwError $ "No está permitido el uso de la opción '-outif' en una cadena INPUT \n"
                                        | target == Output && containsMatchType (MatchInIf "") (ruleMatch rule) =
            throwError $ "No está permitido el uso de la opción '-inif' en una cadena OUTPUT \n\n"
                                        | otherwise = return ()

        -- Verificar si un Match contiene un tipo específico
        containsMatchType :: Match -> Match -> Bool
        containsMatchType (MatchInIf _) (MatchInIf _) = True
        containsMatchType (MatchOutIf _) (MatchOutIf _) = True
        containsMatchType ty (AndMatch m1 m2) = containsMatchType ty m1 || containsMatchType ty m2
        containsMatchType _ _ = False
