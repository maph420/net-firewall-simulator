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

-- TODO: chequeo que ninguna subred se llame "INTERNET"

astValidation :: Info -> ErrAST ()
astValidation inf = do 
                        let rules = infoRules inf
                            network = infoNetwork inf
                            packets = infoPackets inf
                            subnetNames = infoSubnets inf
                            

                        checkRepeatedChains rules 
                        checkSubnetRanges network 

                        -- unicidad de identificadores de dispositivos, paquetes, dir mac, ip
                        checkForIdentifiers network devName (\dn -> "El dispositivo de nombre '" `T.append` dn `T.append` "' aparece repetido\n")
                        checkForIdentifiers packets packid (\paid -> "El paquete de nombre '" `T.append` paid `T.append` "' aparece repetido\n")
                        checkForIdentifiers network macDir (\md -> "La direccion MAC '" `T.append` md `T.append` "' aparece repetida\n")
                        checkForIdentifiers subnetNames subnetName (\sn -> "El nombre de subnet '" `T.append` sn `T.append` "' aparece repetido\n")

                        checkForIPIdentif network (\ipdir -> "La direccion IPv4 '" `T.append` (IPV4.encode ipdir) `T.append` "' aparece repetida.\n")
                         
                        checkChainRules rules  
                        return ()


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

-- Verifica que toda ip suministrada coincida con la subnet en donde esta definida
checkSubnetRanges :: Network -> ErrAST ()
checkSubnetRanges = mapM_ checkDevice 
    where
        checkDevice :: Device -> ErrAST ()
        checkDevice d = if (subnetDir d) `IPV4.contains` (ipv4Dir d) 
                            then return ()
                            else throwError $ "La ip " `T.append` (encode (ipv4Dir d)) `T.append` 
                            " no pertenece al rango subnet: " `T.append` (encodeRange (subnetDir d)) `T.append` "\n"

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

