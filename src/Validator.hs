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

-- cheqyear si T.show equivale a T.pack $ Prelude.show

astValidation :: Info -> ErrAST Info
astValidation inf = do 
                        let rules = infoRules inf
                        let network = infoNetwork inf
                        let packets = infoPackets inf

                        checkRepeatedChains rules -- una misma chain, fue declarada mas de una vez?
                        checkSubnetRanges network -- toda ip suministrada coincide con la subnet en donde esta definida?
                        checkFirewall network -- existe dispositivo llamado 'firewall'? es ruteable a internet? (para recibir paquetes del exterior)

                       -- checkMatches rules -- verifica que no se repitan restricciones (e.g. multiples '-srcip ...' en la misma regla)

                        -- verificar por unicidad de identificadores de dispositivos y paquetes
                        checkForIdentifiers network devName (\dn -> "el dispositivo de nombre '" `T.append` dn `T.append` "' aparece repetido\n")

                        checkForIdentifiers packets packid (\paid -> "el paquete de nombre '" `T.append` paid `T.append` "' aparece repetido\n")

                        -- verificar que ninguna regla de la cadena INPUT tenga una restriccion '-outif'
                        -- ídem OUTPUT no tenga ninguna restriccion '-inif'
                        checkChainRules rules

                        return inf

checkRepeatedChains :: RulesChains -> ErrAST ()
checkRepeatedChains rulc = mapM_ check rulc
    where
        check :: (PacketTarget, [Rule]) -> ErrAST ()
        check (target, _) =  let 
                                matches = Prelude.filter (\(pt, _) -> target == pt) rulc
                             in
                                if (Prelude.length matches > 1)
                                    then throwError $ "cadena " `T.append` (T.pack $ Prelude.show target) `T.append` " aparece repetida\n" 
                                    else return ()

checkMatches :: RulesChains -> ErrAST ()
checkMatches = mapM_ getMatch

-- mapM_ labura igual que mapM, ignorando el val de retorno (como >>)
getMatch :: (PacketTarget, [Rule]) -> ErrAST ()
getMatch (_, rs) = mapM_ checkMatch rs

-- tipo de datos temporal
data MatchType 
    = SrcIP | DstIP | SrcSubnet | DstSubnet 
    | Prot | InIf | OutIf | SrcPort | DstPort
    deriving (Eq, Ord, Show)

-- mapeo a constructor que corresponda
getMatchType :: Match -> Maybe MatchType
getMatchType m = case m of
    MatchSrcIP _      -> Just SrcIP
    MatchDstIP _      -> Just DstIP
    MatchSrcSubnet _  -> Just SrcSubnet
    MatchDstSubnet _  -> Just DstSubnet
    MatchProt _       -> Just Prot
    MatchInIf _       -> Just InIf
    MatchOutIf _      -> Just OutIf
    MatchSrcPort _    -> Just SrcPort
    MatchDstPort _    -> Just DstPort
    _     -> Nothing

checkMatch :: Rule -> ErrAST ()
checkMatch r = checkMatch' (ruleMatch r) S.empty >> return ()
    where
        checkMatch' :: Match -> S.Set MatchType -> ErrAST (S.Set MatchType)
        checkMatch' (AndMatch m1 m2) acc = do
            acc' <- checkMatch' m1 acc
            checkMatch' m2 acc'

        checkMatch' m acc = case getMatchType m of
            Nothing -> return acc
            Just t  -> 
                if S.member t acc
                then throwError $ "El filtro " `T.append` T.pack (Prelude.show m) `T.append` " aperece duplicado en una regla.\n"
                else return (S.insert t acc)
                -- TODO: mostrar show m con el pretty printer


checkSubnetRanges :: Network -> ErrAST ()
checkSubnetRanges = mapM_ checkDevice 


checkDevice :: Device -> ErrAST ()
checkDevice d = if (subnet d) `IPV4.contains` (ipv4Dir d) 
                    then return ()
                    else throwError $ "la ip " `T.append` (encode (ipv4Dir d)) `T.append` " no pertenece al rango subnet: " `T.append` (encodeRange (subnet d)) `T.append` "\n"



checkForIdentifiers :: [a] -> (a -> T.Text) -> (T.Text -> T.Text) -> ErrAST ()
checkForIdentifiers xs fieldExtr formatErr = checkForIdentifiers' xs S.empty
  where
    checkForIdentifiers' [] _ = return ()
    checkForIdentifiers' (y:ys) acc = do
                                        let identif = fieldExtr y 
                                        if S.member identif acc
                                            then throwError $ formatErr identif
                                            else checkForIdentifiers' ys (S.insert identif acc)

checkFirewall :: Network -> ErrAST ()
checkFirewall [] = throwError $ "no se reconoce ningún dispostivo llamado 'firewall', abortando\n"
checkFirewall (d:ds) = if (T.toLower $ devName d) == "firewall"
                        then if IPV4.public (ipv4Dir d)
                                then return ()
                                else throwError $ "la IP del dispositivo de firewall debe ser ruteable en internet (IP pública). Ip provista: " `T.append` (IPV4.encode (ipv4Dir d))
                        else checkFirewall ds

-- Función para verificar si un Match contiene un tipo específico
containsMatchType :: MatchType -> Match -> Bool
containsMatchType InIf (MatchInIf _) = True
containsMatchType OutIf (MatchOutIf _) = True
containsMatchType ty (AndMatch m1 m2) = containsMatchType ty m1 || containsMatchType ty m2
containsMatchType _ _ = False

checkRuleForChain :: PacketTarget -> Rule -> ErrAST ()
checkRuleForChain target rule
  | target == Input && containsMatchType OutIf (ruleMatch rule) =
      throwError $ "No está permitido el uso de la opción '-outif' en una cadena INPUT \n"
  | target == Output && containsMatchType InIf (ruleMatch rule) =
      throwError $ "No está permitido el uso de la opción '-inif' en una cadena OUTPUT \n\n"
  | otherwise = return ()



checkChainRule :: (PacketTarget, [Rule]) -> ErrAST ()
checkChainRule (pt, rs) = mapM_ (checkRuleForChain pt) rs

checkChainRules :: RulesChains -> ErrAST ()
checkChainRules = mapM_ checkChainRule
