{-# LANGUAGE OverloadedStrings #-}

module PrettyPrinter
  ( renderMatch
  )
where

import  Common
import Prettyprinter as PP
import qualified Net.IPv4 as IPV4
import Prettyprinter.Render.Text (renderStrict)
import Data.Text as T

printMatch :: Match -> Doc ()
printMatch (MatchSrcIP sip) = "source_ip =" <+> (PP.pretty . IPV4.encode) sip 
printMatch (MatchDstIP dip) = "destination_ip =" <+> (PP.pretty . IPV4.encode) dip
printMatch (MatchSrcSubnet mss) = "source_subnet_range =" <+> (PP.pretty . IPV4.encodeRange) mss 
printMatch (MatchDstSubnet mds) = "destination_subnet_range =" <+> (PP.pretty . IPV4.encodeRange) mds
printMatch (MatchProt prot) = "protocol =" <+> (PP.pretty . Prelude.show) prot 
printMatch (MatchInIf inif) = "in_interface =" <+> (pretty inif)
printMatch (MatchOutIf outif) = "out_interface =" <+> (pretty outif)
printMatch (MatchSrcPort msp) = "source_port =" <+> (prettyList (msp :: PortList))
printMatch (MatchDstPort mdp) = "destination_port =" <+> (prettyList (mdp :: PortList))
printMatch (AndMatch m1 m2) = (printMatch m1) <> "," <+> (printMatch m2)
-- capaz no hacen falta
printMatch (OrMatch m1 m2) = (printMatch m1) <+> "OR" <+> (printMatch m2)
printMatch (NotMatch m) = "NOT" <+> (printMatch m)
printMatch (MatchAny) = "default-policy"

-- renderizar texto, de formato documento a lejible
renderMatch :: Match -> T.Text
renderMatch m = renderStrict (layoutPretty opts doc)
  where
    doc = "<<<" <+> printMatch m <+> ">>>"
    -- de lo contrario, las listas de puertos se imprimian con saltos de linea
    opts = LayoutOptions { layoutPageWidth = Unbounded }