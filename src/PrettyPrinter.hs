{-# LANGUAGE OverloadedStrings #-}

module PrettyPrinter
  ( renderMatch
  )
where

-- Implementa un Pretty printing para la estructura Match, la cual es expuesta en los logs
-- Como el resto de las estructuras no se muestran por pantalla, no se les realizó una función de pretty print.

import  Common
import Prettyprinter as PP
import qualified Net.IPv4 as IPV4
import Prettyprinter.Render.Text (renderStrict)
import Data.Text as T

printMatch :: Match -> Doc ()
printMatch (MatchSrcIP sip) = "source-ip =" <+> (PP.pretty . IPV4.encode) sip 
printMatch (MatchDstIP dip) = "destination-ip =" <+> (PP.pretty . IPV4.encode) dip
printMatch (MatchSrcSubnet mss) = "source-subnet-range =" <+> (PP.pretty . IPV4.encodeRange) mss 
printMatch (MatchDstSubnet mds) = "destination-subnet-range =" <+> (PP.pretty . IPV4.encodeRange) mds
printMatch (MatchProt prot) = "protocol =" <+> (PP.pretty . Prelude.show) prot 
printMatch (MatchInIf inif) = "in-interface =" <+> (pretty inif)
printMatch (MatchOutIf outif) = "out-interface =" <+> (pretty outif)
printMatch (MatchSrcPort msp) = "source-port =" <+> (prettyList (msp :: PortList))
printMatch (MatchDstPort mdp) = "destination-port =" <+> (prettyList (mdp :: PortList))
printMatch (AndMatch m1 m2) = (printMatch m1) <> "," <+> (printMatch m2)
printMatch (OrMatch m1 m2) = (printMatch m1) <+> "/" <+> (printMatch m2)
printMatch (MatchAny) = "default-policy"

-- renderizar texto, de formato documento a lejible
renderMatch :: Match -> T.Text
renderMatch m = renderStrict (layoutPretty opts doc)
  where
    doc = "<<<" <+> printMatch m <+> ">>>"
    opts = LayoutOptions { layoutPageWidth = Unbounded } -- de lo contrario, las listas de puertos se imprimian con saltos de linea
