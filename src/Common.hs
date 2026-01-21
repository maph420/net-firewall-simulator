-- definir aca las estructuras de datos del AST a utilizar

-- stack repl para terminal interactiva
-- agregar al path: echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc    source ~/.bashrc

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
        Env(..),
        LogLevel(..),
        LogEntry(..),
        Token(..),
        ParseResult(..),
        DeviceFieldsData(..)
    ) where

import qualified Net.IPv4 as IPV4
import qualified Data.Text as T
import qualified Data.Map.Strict as M

----------------------------
-- definiciones generales --
----------------------------

-- deberia fijar las interfaces? o dejarlas simplemente como texto?
type Interface = T.Text

data Protocol = TCP | UDP | ANY deriving (Eq, Show)

-- un numero entero en el intervalo [0, 65535]. TODO: realizar saneamiento de input: descartar numeros de puerto imposibles
-- en el firewall, si no se especifican puertos, se admiten todos
type Port = Int
type PortList = [Port]

-- procurar que al hacer reject se escriba en el log.
data Action = Accept | Drop | Reject deriving (Eq,Show)

data PacketTarget = Input | Output | Forward deriving (Eq, Show, Ord)

------------------------
-- estructuras de red --
------------------------

data Device = Device {
    devName     :: T.Text, -- nombre del dispostivio
    macDir      :: T.Text,
    ipv4Dir     :: IPV4.IPv4,
    subnet      :: IPV4.IPv4Range, 
    interfaces  :: [Interface]
} deriving Show

type Network = [Device]

------------------------------------
-- estructuras de paquetes/envios --
------------------------------------

-- timestamp? a priori, no
-- id, Text o int?
--     decision de diseño? chequear
--    si bien no necesariamente en el paquete se deben especificar cosas como la dir fuente (puede ser que el nodo remitente no espere
--    respuesta) o la interfaz a la que llegará un paquete, por propósitos de la simulación los dejamos como campos obligatorios

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

-- operador algebraico al cual deben traducirse las sentencias durante el parseo

-- -srcip 192.168.1.0 -dstip 192.168.2.0 -prot udp -outif eth0
-- MatchAnd (MatchAnd (MarchSrcIP 192.168.1.0) (MatchDstIP 192.168.2.0)) (MatchAnd (MatchProt UDP) (MatchOutIf "eth0"))

-- -dstip 10.0.0.1 -prot tcp -inif eth1 -outif ppp0 -dstp [80]
-- MatchAnd (MatchAnd (MatchDstIP 10.0.0.1) (MatchProt TCP)) (MatchAnd (MatchInIf "eth1") (MatchAnd (MatchOutIf "ppp0") (MatchDstIP PortList)))

-- -srcip 10.0.0.2/16 -prot udp -dstp [53,443]
-- MatchAnd (MatchAnd (MatchSrcSubnet 10.0.0.2/16) (MatchProt UDP)) (MatchSrcPort [53, 443])

-- chain DROPPOLICY { acciones a realizar por defecto, si el paquete no matchea ninguna de las otras }

-- lo guardo como una regla más, la cual tiene como match: MatchAny

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
    | AndMatch Match Match -- encadenar todo lo que pide 1 regla
    | NotMatch Match
    | OrMatch Match Match

    deriving (Show)


--UNA regla: target (input,output,forward), match (conds a cumplir),action(rechazar,soltar,aceptar), log (opcional?)
data Rule = Rule {
    ruleId      :: T.Text, -- (?)
    ruleMatch   :: Match,
    ruleAction  :: Action,
    ruleLog     :: Maybe T.Text
} deriving (Show)

-- TODO: chequear. a priori con una lista enlazada parece lo más eficiente.
-- pinta que va a haber que agregar con (:) una por una las reglas a medida que se parsean, y por ultimo revertir la lista.
-- asi: reverse r5 : r4 : r3 : r2 : r1 : [] = [r1,r2,r3,r4,r5]

-- para mayor claridad semantica
type RulesChains = [(PacketTarget, [Rule])]

-- aca está toda la información. esta estructura podria verse como el entorno de una mónada reader/writer. averiguar.
data Info = Info {
    infoNetwork :: Network,
    infoPackets :: SentPackets,
    infoRules :: RulesChains
} deriving (Show)

-- Informacion que lleva el entorno, "procesar" la info
data Env = Env {
    deviceInterfaces :: M.Map IPV4.IPv4 [Interface],
    deviceSubnets :: M.Map IPV4.IPv4 IPV4.IPv4Range,
    firewallIP :: IPV4.IPv4,
    rulesChains :: RulesChains
} deriving Show

-- Informacion de loggeo

data LogLevel = Information | Warning | Error deriving Show

data LogEntry = LogEntry {
    logLevel :: LogLevel,
    logMessage :: T.Text,
    logPacket :: Maybe Packet
} deriving (Show)

data Token
    = TokenDevice String
    | TokenDeviceMac 
    | TokenDeviceIP
    | TokenDeviceSubnet
    | TokenDeviceInterfaces
    | TokenOpenBracket
    | TokenCloseBracket
    | TokenAssign
    | TokenSemicolon
    | TokenPackets
    | TokenArrow
    | TokenColon
    | TokenTCP
    | TokenUDP
    | TokenANY
    | TokenComma
    | TokenRules
    | TokenChain
    | TokenInput
    | TokenOutput
    | TokenForward
    | TokenFrom
    | TokenTo
    | TokenSlash
    | TokenString String
    | TokenIdent String
    | TokenNumber Int
    | TokenIP String
    | TokenAccept
    | TokenDrop
    | TokenReject
    | TokenDash
    | TokenAnd
    | TokenOr
    | TokenNot
    | TokenLParen
    | TokenRParen
    | TokenNetwork
    | TokenSrcIP
    | TokenDstIP
    | TokenProt
    | TokenInIf
    | TokenOutIf
    | TokenSrcPort
    | TokenDstPort
    | TokenSrcSubnet
    | TokenDstSubnet
    | TokenDo
    | TokenDefault
    | TokenEOF     
    deriving Show

data ParseResult a = Ok a | Failed String
                     deriving Show    

-- Estructura intermedia para realizar el parseo de un dispositivo
data DeviceFieldsData = DeviceFieldsData
    { macAddr :: T.Text
    , ipAddr :: IPV4.IPv4
    , subnetRange :: IPV4.IPv4Range
    , ifaces :: [Interface]
    }