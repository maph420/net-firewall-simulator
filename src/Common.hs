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
        RulesChains,
        Info(..),
        LogLevel(..),
        LogEntry(..),
        defaultFwIf,
        FirewallConfig(..),
        ParseResult(..)
    ) where

import qualified Net.IPv4 as IPV4
import qualified Data.Text as T

----------------------------
-- definiciones generales --
----------------------------

type Interface = T.Text

-- Interfaz de entrada/salida al firewall desde el exterior (convenida)
defaultFwIf :: Interface
defaultFwIf = T.pack "eth3"

type Port = Int
type PortList = [Port]

------------------------
-- estructuras de red --
------------------------

data Device = Device {
    devName     :: T.Text,
    macDir      :: T.Text,
    ipv4Dir     :: IPV4.IPv4,
    subnet      :: IPV4.IPv4Range, 
    interfaces  :: [Interface]
} deriving Show

type Network = [Device]

------------------------------------
-- estructuras de paquetes/envios --
------------------------------------

data Protocol = TCP | UDP | ANY deriving (Eq, Show)

-- Paquete de red, representa un envío en la red en la que se está trabajando.
data Packet = Packet {
    packid      :: T.Text,
    srcip       :: IPV4.IPv4,
    dstip       :: IPV4.IPv4,
    srcport     :: Port,
    dstport     :: Port,
    protocol    :: Protocol,
    ingressif   :: Interface,
    egressif    :: Interface
} deriving (Show)

type SentPackets = [Packet]

------------------------------
-- estructuras del firewall --
------------------------------

data PacketTarget = Input | Output | Forward deriving (Eq, Show, Ord)
data Action = Accept | Drop | Reject deriving (Eq,Show)

-- operador algebraico al cual deben traducirse las sentencias durante el parseo
data Match = MatchAny 
    | MatchSrcIP IPV4.IPv4
    | MatchDstIP IPV4.IPv4
    | MatchSrcSubnet IPV4.IPv4Range
    | MatchDstSubnet IPV4.IPv4Range
    | MatchProt Protocol
    | MatchInIf Interface
    | MatchOutIf Interface
    | MatchSrcPort PortList
    | MatchDstPort PortList
    | AndMatch Match Match -- encadenar todo lo que pide 1 regla con mas de 1 restriccion
    deriving (Show)

data Rule = Rule {
    ruleId      :: T.Text,
    ruleMatch   :: Match,
    ruleAction  :: Action,
    ruleLog     :: Maybe T.Text
} deriving (Show)

type RulesChains = [(PacketTarget, [Rule])]

-- Estructura obtenida como resultado del parseo
data Info = Info {
    infoNetwork :: Network,
    infoPackets :: SentPackets,
    infoRules :: RulesChains
} deriving (Show)

-- Configuracion del firewall (informacion ya curada mediante un ast validation)
data FirewallConfig = FirewallConfig {
    fwIP :: IPV4.IPv4,
    fwRules :: RulesChains,
    fwDevices :: [Device]
} deriving Show

-- Tipo de mensaje de log
data LogLevel = Information | Warning | Error deriving Show

-- Informacion de loggeo
data LogEntry = LogEntry {
    logLevel :: LogLevel,
    logMessage :: T.Text,
    logPacket :: Maybe Packet
} deriving (Show)

-- Estructura para manejar errores de validacion durante el parseo.
data ParseResult a = Ok a | Failed String
                     deriving Show