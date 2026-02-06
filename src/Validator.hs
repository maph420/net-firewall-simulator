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

astValidation :: Info -> ErrAST ()
astValidation inf = do 
                        let rules = infoRules inf
                            network = infoNetwork inf
                            packets = infoPackets inf
                            subnetInfo = infoSubnets inf
                        checkRepeatedChains rules 
                        checkSubnetRanges network 
                        checkNoDefaultIf subnetInfo
                        -- unicidad de identificadores de dispositivos, paquetes, dir mac, ip
                        checkForIdentifiers network devName (\dn -> "El dispositivo de nombre '" `T.append` dn `T.append` "' aparece repetido\n")
                        checkForIdentifiers packets packid (\paid -> "El paquete de nombre '" `T.append` paid `T.append` "' aparece repetido\n")
                        checkForIdentifiers network macDir (\md -> "La direccion MAC '" `T.append` md `T.append` "' aparece repetida\n")
                        checkForIdentifiers subnetInfo subnetName (\sn -> "El nombre de subnet '" `T.append` sn `T.append` "' aparece repetido\n")
                        checkForDups network ipv4Dir (\ipdir -> "La direccion IPv4 '" `T.append` (IPV4.encode ipdir) `T.append` "' aparece repetida.\n")
                        checkForDups subnetInfo subnetRange (\ipran -> "El rango de direcciones IPv4 '" `T.append` (IPV4.encodeRange ipran) `T.append` "' aparece repetido.\n")
                        checkForDups subnetInfo subnetInterface (\snif -> "La interfaz: " `T.append` snif `T.append` " aparece repetida.")
                        checkChainRules rules  

checkNoDefaultIf :: [Subnet] -> ErrAST ()
checkNoDefaultIf [] = return ()
checkNoDefaultIf (s:ss) = if (subnetInterface s == defaultFwIf)
                            then throwError $ "No está permitido que una subred tenga interfaz: " `T.append`  defaultFwIf `T.append` ", está reservada para la salida al exterior del firewall"
                            else checkNoDefaultIf ss

-- Verifica si una misma chain fue declarada mas de una vez
checkRepeatedChains :: RulesChains -> ErrAST ()
checkRepeatedChains rulc = mapM_ check rulc
    where
        check :: (PacketTarget, [Rule]) -> ErrAST ()
        check (target, _) =     let 
                                    matches = Prelude.filter (\(pt, _) -> target == pt) rulc
                                in
                                    if (Prelude.length matches > 1)
                                        then throwError $ "Cadena " `T.append` (T.show target) `T.append` " aparece repetida\n" 
                                        else return ()

-- Verifica que toda ip suministrada coincida con la subnet en donde esta definida.
checkSubnetRanges :: Network -> ErrAST ()
checkSubnetRanges = mapM_ checkDevice 
    where
        checkDevice :: Device -> ErrAST ()
        checkDevice d = if (subnetDir d) `IPV4.contains` (ipv4Dir d) 
                            then return ()
                            else throwError $ "La ip " `T.append` (encode (ipv4Dir d)) `T.append` 
                            " no pertenece al rango subnet: " `T.append` (encodeRange (subnetDir d)) `T.append` "\n"

-- Verifica si un elemento dado aparece repetido en la lista pasada. Se pasa el extractor de campo para saber por cual del registro se quiere chequear.
-- Si hay repeticion, llama a una funcion que formatea el error.
checkForDups :: Ord k => [a] -> (a -> k) -> (k -> Text) -> ErrAST ()
checkForDups xs fieldExtr formatErr = checkForDups' xs S.empty
  where
        checkForDups' [] _ = return ()
        checkForDups' (y:ys) acc = do
                                        let identif = fieldExtr y 
                                        if S.member identif acc
                                            then throwError $ formatErr identif
                                            else checkForDups' ys (S.insert identif acc)

-- Verifica la repeticion de un identificador textual
checkForIdentifiers :: [a] -> (a -> T.Text) -> (T.Text -> T.Text) -> ErrAST ()
checkForIdentifiers xs fieldExtr formatErr = checkForDups xs (T.toLower . fieldExtr) formatErr


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

        -- Verificar si un Match contiene un tipo especifico
        containsMatchType :: Match -> Match -> Bool
        containsMatchType (MatchInIf _) (MatchInIf _) = True
        containsMatchType (MatchOutIf _) (MatchOutIf _) = True
        containsMatchType ty (AndMatch m1 m2) = containsMatchType ty m1 || containsMatchType ty m2
        containsMatchType _ _ = False
