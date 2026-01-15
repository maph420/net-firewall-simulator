-- definir aca las estructuras de datos del AST a utilizar
-- that alerts you when a module doesn't explicitly list the items it exports; 
-- instead of exporting everything by default, you should add a specific list
-- imagino que deberia exportar los constructores y observadores

-- stack repl para terminal interactiva
-- agregar al path: echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc    source ~/.bashrc

-- the import qualified syntax is used to bring a module's functions and data types 
-- into scope such that they must be explicitly prefixed by the module's name (or an alias) when used. 

-- ver si conviene usar data o newtype (depende si voy a usar el unwrapper o no)

module Common
    (   Interface,
        Protocol(..),
        Port,
        PortList,
        Action(..),
        PacketTarget(..),
        Device(..),
        Network,
        Packet(..),
        SentPackets,
        Match(..),
        Rule(..),
        RulesChain,
        Info(..)
    ) where

import qualified Net.IPv4 as IPV4
import qualified Data.Text as T

-------------------------
-- general definitions --
-------------------------

-- deberia fijar las interfaces? o dejarlas simplemente como texto?
type Interface = T.Text

data Protocol = TCP | UDP | ANY

-- un numero entero en el intervalo [0, 65535]. TODO: realizar saneamiento de input: descartar numeros de puerto imposibles
-- en el firewall, si no se especifican puertos, se admiten todos
type Port = Int
type PortList = [Port]

-- procurar que al hacer reject se escriba en el log.
data Action = Accept | Drop | Reject

data PacketTarget = Input | Output | Forward

------------------------
-- network structures --
------------------------

data Device = Device {
    devName     :: T.Text,
    macDir      :: T.Text,
    ipv4Dir     :: IPV4.IPv4,
    subnet      :: Maybe IPV4.IPv4Range, -- obligatoriamente pertenece a una subnet??
    interfaces  :: [Interface]
}

type Network = [Device]

-----------------------------------
-- packets/deliveries structures --
-----------------------------------

-- timestamp? a priori, no
-- id, Text o int?
--     decision de diseño? chequear
--    si bien no necesariamente en el paquete se deben especificar cosas como la dir fuente (puede ser que el nodo remitente no espere
--    respuesta) o la interfaz a la que llegará un paquete, por propósitos de la simulación los dejamos como campos obligatorios

-- Paquete de red, representa un envío en la red en la que se está trabajando.
data Packet = Packet {
    id          :: T.Text,
    srcip       :: IPV4.IPv4,
    dstip       :: IPV4.IPv4,
    srcport     :: Port,
    dstport     :: Port,
    protocol    :: Protocol,
    ingressif   :: Interface,
    egressif    :: Interface
}

type SentPackets = [Packet]

-------------------------
-- firewall structures --
-------------------------

-- operador algebraico al cual deben traducirse las sentencias durante el parseo

-- -srcip 192.168.1.0 -dstip 192.168.2.0 -prot udp -outif eth0
-- MatchAnd (MatchAnd (MarchSrcIP 192.168.1.0) (MatchDstIP 192.168.2.0)) (MatchAnd (MatchProt UDP) (MatchOutIf "eth0"))

-- -dstip 10.0.0.1 -prot tcp -inif eth1 -outif ppp0 -dstp [80]
-- MatchAnd (MatchAnd (MatchDstIP 10.0.0.1) (MatchProt TCP)) (MatchAnd (MatchInIf "eth1") (MatchAnd (MatchOutIf "ppp0") (MatchDstIP PortList)))

-- -srcip 10.0.0.2/16 -prot udp -dstp [53,443]
-- MatchAnd (MatchAnd (MatchSrcSubnet 10.0.0.2/16) (MatchProt UDP)) (MatchSrcPort [53, 443])

data Match = MatchAny 
    | MatchSrcIP IPV4.IPv4
    | MatchDstIP IPV4.IPv4
    | MatchSrcSubnet T.Text
    | MatchDstSubnet T.Text
    | MatchProt Protocol
    | MatchInIf Interface
    | MatchOutIf Interface
    | MatchSrcPort PortList
    | MatchDstPort PortList
    | AndMatch Match Match -- encadenar todo lo que pide 1 regla
    | OrMatch Match Match -- para multipuertos: e.g. que matchee puerto src == 80 o == 443
    | NotMatch Match -- capaz no hace falta (chequear)


--UNA regla: target (input,output,forward), match (conds a cumplir),action(rechazar,soltar,aceptar), log (opcional?)
data Rule = Rule {
    ruleTarget  :: PacketTarget,
    ruleMatch   :: Match,
    ruleAction  :: Action,
    ruleLog     :: Maybe T.Text	
} 

-- TODO: chequear. a priori con una lista enlazada parece lo más eficiente
type RulesChain = [Rule]

-- aca está toda la información. esta estructura podria verse como el entorno de una mónada reader/writer. averiguar.
data Info = Info {
    infoNetwork :: Network,
    infoPackets :: SentPackets,
    infoRules :: RulesChain
}
