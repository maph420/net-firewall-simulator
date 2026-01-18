{
module FirewallParser (parseFirewall) where

import Common
import qualified Data.Text as T
import qualified Data.Map.Strict as M
import qualified Net.IPv4 as IPV4
import Data.Char (isSpace, isAlpha, isAlphaNum, isDigit)
import Data.Word (Word8)
import Monads
}

%monad { P } { thenP } { returnP }
%name parseScript
%tokentype { Token }
%lexer {lexer} {TokenEOF}


%token
    device          { TokenDevice $$ }
    desc            { TokenDeviceDescription }
    mac             { TokenDeviceMac }
    ip              { TokenDeviceIP }
    subnet          { TokenDeviceSubnet }
    interfaces      { TokenDeviceInterfaces }
    '{'             { TokenOpenBracket }
    '}'             { TokenCloseBracket }
    '='             { TokenAssign }
    ';'             { TokenSemicolon }
    packets         { TokenPackets }
    '->'            { TokenArrow }
    ':'             { TokenColon }
    tcp             { TokenTCP }
    udp             { TokenUDP }
    any             { TokenANY }
    ','             { TokenComma }
    '['             { TokenOpenSquareBracket }
    ']'             { TokenCloseSquareBracket }
    rules           { TokenRules }
    chain           { TokenChain }
    INPUT           { TokenInput }
    OUTPUT          { TokenOutput }
    FORWARD         { TokenForward }
    via             { TokenVia }
    STRING          { TokenString $$ }
    IDENT           { TokenIdent $$ }
    NUMBER          { TokenNumber $$ }
    IP_ADDR         { TokenIP $$ }
    '('             { TokenLParen }
    ')'             { TokenRParen }
    '!'             { TokenNot }
    '&'             { TokenAnd }
    '|'             { TokenOr }
    '-'             { TokenDash }
    '/'             { TokenSlash }
    network         { TokenNetwork }
    srcip           { TokenSrcIP }
    dstip           { TokenDstIP }
    prot            { TokenProt }
    inif            { TokenInIf }
    outif           { TokenOutIf }
    srcp            { TokenSrcPort }
    dstp            { TokenDstPort }
    srcsubnet       { TokenSrcSubnet }
    dstsubnet       { TokenDstSubnet }
    do              { TokenDo }
    default         { TokenDefault }
    ACCEPT          { TokenAccept }
    DROP            { TokenDrop }
    REJECT          { TokenReject }

%right '|'
%left '&'
%nonassoc not

%%

Script : Network Packets Rules { Info $1 $2 $3 }

Network : network '{' DeviceList '}' { $3 }

DeviceList : Device { [ $1] } 
    | Device DeviceList { $1 : $2 }

Device : device IDENT '{' DeviceFields '}' 
    { Device (T.pack $2) Nothing (macAddr $4) (ipAddr $4) (subnetRange $4) (ifaces $4) }

SubnetVal : STRING { Just (parseSubnet $1) }
          | IP_ADDR '/' NUMBER { Just (readSubnet $1 $3) }
          ;

DeviceFields : mac '=' STRING ';' ip '=' IP_ADDR ';' subnet '=' SubnetVal ';' interfaces '=' IfList ';'
    { DeviceFieldsData
        { macAddr = T.pack $3
        , ipAddr = readIP $7
        , subnetRange = $11
        , ifaces = map T.pack $15
        } }

IfList : STRING { [$1] }
    | STRING ',' IfList { $1 : $3 }

Packets : packets '[' PacketList ']' { $3 }
-- VER: hice la gramatica tq no se admiten dispositivos sin interfaces
-- o un script con 0 envios de paquetes

PacketList : Packet { [$1] }
    | Packet PacketList { $1 : $2 }

Packet : IDENT ':' IP_ADDR '->' IP_ADDR ':' Protocol NUMBER via STRING ';'
    { Packet (T.pack $1) (readIP $3) (readIP $5) 0 $8 $7 (T.pack $10) (T.pack $10) }

Protocol : tcp { TCP }
    | udp { UDP }
    | any { ANY }

Rules : rules '{' ChainDecls '}' { M.fromList $3 }

ChainDecls : {- empty -} { [] }
    | ChainDecl ChainDecls { $1 : $2 }

-- ?
ChainDecl : ChainBlock { $1 }

ChainBlock : chain CHAIN_NAME '{' RuleList '}' { ($2, reverse $4) }


CHAIN_NAME : INPUT  { Input }
    | OUTPUT { Output }
    | FORWARD { Forward }

RuleList : {- empty -} { [] }
    | RulesSemiList { reverse $1 }

RulesSemiList : Rule ';' { [$1] }
    | Rule ';' RulesSemiList { $1 : $3 }

-- cambiar string "rule"
Rule : SpecList '-' do ACTION { Rule (T.pack "rule") $1 $4 Nothing }

ACTION : ACCEPT { Accept }
    | DROP { Drop }
    | REJECT { Reject }

SpecList : Spec { $1 }
    | SpecList Spec { AndMatch $1 $2 }
    | SpecList '&' Spec { AndMatch $1 $3 }
    | SpecList '|' Spec { OrMatch $1 $3 }
    | '!' Spec { NotMatch $2 }

Spec : '-' srcip IPList { conjunctIPMatches $3 MatchSrcIP }
    | '-' dstip IPList { conjunctIPMatches $3 MatchDstIP }
    | '-' prot Protocol { MatchProt $3 }
    | '-' inif IfList { conjunctIfMatches $3 MatchInIf }
    | '-' outif IfList { conjunctIfMatches $3 MatchOutIf}
    | '-' srcp PortSpec { MatchSrcPort $3 }
    | '-' dstp PortSpec { MatchDstPort $3 }
    | '-' srcsubnet SubnetList { conjunctIPRangeMatches $3 MatchSrcSubnet }
    | '-' dstsubnet SubnetList { conjunctIPRangeMatches $3 MatchDstSubnet }
    | '(' SpecList ')' { $2 }

IPList : IP_ADDR { [$1] }
    | IP_ADDR ',' IPList { $1 : $3 }

SubnetList : IP_ADDR '/' NUMBER { [($1, $3)] }
    | IP_ADDR '/' NUMBER ',' SubnetList { ($1, $3) : $5 }


PortSpec : NUMBER { [$1] }
    |  PortList { $1 }

PortList : NUMBER { [$1] }
    | NUMBER ',' PortList { $1 : $3 }

{

-- obtener numero de linea del estado de la mónada      
getLineNo :: P Int
getLineNo = \s l -> Ok l


lexer :: (Token -> P a) -> P a
lexer cont s = \line -> 
    case s of
        [] -> cont TokenEOF [] line
        ('\n':cs) -> lexer cont cs (line + 1)
        (c:cs) 
            | isSpace c -> lexer cont cs line
            | isDigit c -> lexIPOrNumber cont (c:cs) s line
            | c == '"'  -> lexString cont cs s line
            | isAlpha c -> lexKeywordOrIdent cont (c:cs) s line
            | otherwise -> case c of
                '&' -> cont TokenAnd cs line
                '|' -> cont TokenOr cs line
                '!' -> cont TokenNot cs line
                '(' -> cont TokenLParen cs line
                ')' -> cont TokenRParen cs line
                '/' -> cont TokenSlash cs line
                '{' -> cont TokenOpenBracket cs line
                '}' -> cont TokenCloseBracket cs line
                '[' -> cont TokenOpenSquareBracket cs line
                ']' -> cont TokenCloseSquareBracket cs line
                '=' -> cont TokenAssign cs line
                ';' -> cont TokenSemicolon cs line
                ':' -> cont TokenColon cs line
                ',' -> cont TokenComma cs line
                '-' -> if not (null cs) && head cs == '>' 
                       then cont TokenArrow (tail cs) line
                       else cont TokenDash cs line
                _   -> Failed $ "Línea " ++ show line ++ ": Caracter inesperado " ++ [c]

-- numero detectado: retornar token segun si es IP o un natural
lexIPOrNumber :: (Token -> P a) -> String -> P a
lexIPOrNumber cont tokenRaw = \_ line ->
    let (tokenStr, rest) = span (\c -> isDigit c || c == '.') tokenRaw
        token = if any (== '.') tokenStr
                then TokenIP tokenStr
                else TokenNumber (read tokenStr)
    in cont token rest line

-- sacar validacion de ip
lexString :: (Token -> P a) -> String -> P a
lexString cont s = \_ line -> 
    case break (== '"') s of
        (str, '"':rest) -> cont (TokenString str) rest line
        _               -> Failed $ "String no cerrado en línea " ++ show line


lexKeywordOrIdent :: (Token -> P a) -> String -> P a
lexKeywordOrIdent cont tokenRaw = \_ line -> 
    let (ident, rest) = span (\c -> isAlphaNum c || c == '.' || c == '-') tokenRaw
        token = case ident of
            "device"     -> TokenDevice ident
            "desc"       -> TokenDeviceDescription
            "mac"        -> TokenDeviceMac
            "ip"         -> TokenDeviceIP
            "subnet"     -> TokenDeviceSubnet
            "interfaces" -> TokenDeviceInterfaces
            "packets"    -> TokenPackets
            "rules"      -> TokenRules
            "chain"      -> TokenChain
            "INPUT"      -> TokenInput
            "OUTPUT"     -> TokenOutput
            "FORWARD"    -> TokenForward
            "tcp"        -> TokenTCP
            "udp"        -> TokenUDP
            "any"        -> TokenANY
            "via"        -> TokenVia
            "ACCEPT"     -> TokenAccept
            "DROP"       -> TokenDrop
            "REJECT"     -> TokenReject
            "network"    -> TokenNetwork
            "srcip"      -> TokenSrcIP
            "dstip"      -> TokenDstIP
            "prot"       -> TokenProt
            "inif"       -> TokenInIf
            "outif"      -> TokenOutIf
            "srcp"       -> TokenSrcPort
            "dstp"       -> TokenDstPort
            "srcsubnet"  -> TokenSrcSubnet
            "dstsubnet"  -> TokenDstSubnet
            "do"         -> TokenDo
            "default"    -> TokenDefault
            _            -> if isValidIP ident then TokenIP ident else TokenIdent ident
    in cont token rest line

-- helper (si voy a hacer AST validation, no hace falta aca)
isValidIP :: String -> Bool
isValidIP s = 
    let parts = split '.' s
    in length parts == 4 && all (\p -> not (null p) && all isDigit p && let n = read p in n >= 0 && n <= 255) parts
    
split :: Char -> String -> [String]
split _ [] = []
split c s = let (part, rest) = break (== c) s in part : split c (drop 1 rest)

-- funcion helper para leer una direccion IPv4 desde string
readIP :: String -> IPV4.IPv4
readIP ipStr = case IPV4.decodeString ipStr of
    Just ip -> ip
    Nothing -> error $ "Invalid IP address: " ++ ipStr

-- funcion helper para leer un rango de subnet IPv4 desde string
readSubnet :: String -> Int -> IPV4.IPv4Range
readSubnet ipStr prefix = case IPV4.decodeString ipStr of
    Just ip -> IPV4.range ip (fromIntegral prefix)
    Nothing -> error $ "Invalid IP address in subnet: " ++ ipStr

-- helper para parsear una string que representa una subnet, e.g. "192.168.1.0/24"
parseSubnet :: String -> IPV4.IPv4Range
parseSubnet s = 
    let (ipStr, rest) = break (== '/') s
        prefixStr = drop 1 rest
        prefix = read prefixStr
    in readSubnet ipStr prefix

-- precond: la gramatica debe garantizar que la lista de strings tiene al menos 1 elemento.
conjunctIPMatches :: [ String ] -> (IPV4.IPv4 -> Match) -> Match
conjunctIPMatches [ipStr] construct = construct (readIP ipStr)
conjunctIPMatches (ipStr : ipStrs) construct = AndMatch (construct (readIP ipStr)) (conjunctIPMatches ipStrs construct)

conjunctIPRangeMatches :: [(String, Int)] -> (IPV4.IPv4Range -> Match) -> Match
conjunctIPRangeMatches [(ipRangeStr, n)] c = c (readSubnet ipRangeStr n)
conjunctIPRangeMatches ((ipRangeStr, n) : ipRangeStrs) c = AndMatch (c (readSubnet ipRangeStr n)) (conjunctIPRangeMatches ipRangeStrs c)

conjunctIfMatches :: [String] -> (T.Text -> Match) -> Match
conjunctIfMatches [ifStr] c = c (T.pack ifStr)
conjunctIfMatches (ifstr : ifstrs) c = AndMatch (c $ T.pack ifstr) (conjunctIfMatches ifstrs c)

-- Manejador de errores de parseo usado por Happy
happyError :: P a
happyError = \s i -> Failed $ "Linea " ++ show i ++ ": Error de parseo cerca de ----->" ++ take 10 s ++ "<-----"

-- Funcion a invocar para parsear.
parseFirewall :: String -> ParseResult Info
parseFirewall input = parseScript input 1
}

-- happy src/FirewallParser.y -o src/FirewallParser.hs --ghc
-- stack build
-- stack run