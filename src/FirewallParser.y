{
module FirewallParser (parseFirewall) where

import Common
import qualified Data.Text as T
import qualified Net.IPv4 as IPV4
import Data.Char (isSpace, isAlpha, isAlphaNum, isDigit, isHexDigit)
import Data.Word (Word8)
import Monads
import Data.List (find)

}

%monad { P } { thenP } { returnP } 
%name parseScript
%tokentype { Token }
%lexer {lexer} {TokenEOF}

%token
    device          { TokenDevice $$ }
    mac             { TokenDeviceMac }
    ip              { TokenDeviceIP }
    subnet          { TokenDeviceSubnet }
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
    rules           { TokenRules }
    chain           { TokenChain }
    INPUT           { TokenInput }
    OUTPUT          { TokenOutput }
    FORWARD         { TokenForward }
    from            { TokenFrom }
    to              { TokenTo }
    STRING          { TokenString $$ }
    IDENT           { TokenIdent $$ }
    NUMBER          { TokenNumber $$ }
    IP_ADDR         { TokenIP $$ }
    '('             { TokenLParen }
    ')'             { TokenRParen }
    '-'             { TokenDash }
    '/'             { TokenSlash }
    srcip           { TokenSrcIP }
    dstip           { TokenDstIP }
    prot            { TokenProt }
    inif            { TokenInIf }
    outif           { TokenOutIf }
    subnets         { TokenSubnets }
    range           { TokenRange }
    interface       {TokenFirewallInterface}
    devices         { TokenDevices}
    publicip       { TokenPublicIP }
    srcp            { TokenSrcPort }
    dstp            { TokenDstPort }
    srcsubnet       { TokenSrcSubnet }
    dstsubnet       { TokenDstSubnet }
    do              { TokenDo }
    default         { TokenDefault }
    ACCEPT          { TokenAccept }
    DROP            { TokenDrop }
    REJECT          { TokenReject }

%%

Script : Subnets Devices Packets Rules { 
    % processRawDevices $1 $2 `thenP` \validDevices ->
    returnP $ Info $1 validDevices $3 $4 
 }

Subnets : subnets '{' SubnetDeclList '}' { $3 }
        | {- empty -} { [] }

SubnetDeclList : Subnet { [$1] }
               | Subnet SubnetDeclList { $1 : $2 }

Subnet : subnet IDENT '{' SubnetFields '}' 
    { let sfields = $4 in Subnet (T.pack $2) (subnetRan sfields) (subnetIf sfields) }

SubnetFields : range '=' SubnetVal ';' interface '=' STRING ';'
    { % readSubnet $3 `thenP` \validRange ->
      checkValidIf $7 `thenP` \validIf -> 
      returnP (SubnetFieldsData validRange (T.pack validIf)) }


SubnetVal : IP_ADDR '/' NUMBER { ($1, $3) }

Devices : devices '{' DeviceList '}' { $3 }

DeviceList : Device { [ $1 ] } 
           | Device DeviceList { $1 : $2 }

Device : device IDENT '{' DeviceFields '}' 
    { let isFirewall = ($2 == "firewall") in
      RawDevice (T.pack $2) (macAddr $4) (ipAddr $4) (subnetRef $4) isFirewall }

DeviceFields : mac '=' STRING ';' ip '=' IP_ADDR ';' subnet '=' IDENT ';'
    { % checkValidMAC $3 `thenP` \validMAC -> 
      returnP (DeviceFieldsData (T.pack validMAC) (readIP $7) (T.pack $11)) }
    | mac '=' STRING ';' publicip '=' IP_ADDR ';' 
    { % checkValidMAC $3 `thenP` \validMAC -> 
      returnP (DeviceFieldsData (T.pack validMAC) (readIP $7) (T.pack "INTERNET")) }

IfList : STRING { [$1] }
       | STRING ',' IfList { $1 : $3 }

Packets : packets '{' PacketList '}' { $3 }

PacketList : Packet { [$1] }
           | Packet PacketList { $1 : $2 }

Packet : IDENT ':' IP_ADDR '->' IP_ADDR ':' Protocol NUMBER '->' NUMBER ':' from STRING to STRING ';'
    { % checkValidPort $8 `thenP` \validSrcPort -> 
      checkValidPort $10 `thenP` \validDstPort ->
      checkValidIf $13 `thenP` \validInIf -> 
      checkValidIf $15 `thenP` \validOutIf ->
      returnP $ Packet (T.pack $1) (readIP $3) (readIP $5) validSrcPort validDstPort $7 (T.pack validInIf) (T.pack validOutIf) }

Protocol : tcp { TCP }
         | udp { UDP }
         | any { ANY }

Rules : rules '{' ChainDecls '}' { $3 }

ChainDecls : {- empty -} { [] }
           | ChainBlock ChainDecls { $1 : $2 }

ChainBlock : chain CHAIN_NAME '{' Stmts '}' { ($2, $4) }

Stmts : {- empty -} { [] }
      | Stmt Stmts { $1 : $2 }

Stmt : Rule ';' { $1 }
     | DefaultPolicy { $1 }

DefaultPolicy : '-' default ACTION ';' { Rule (T.pack "") MatchAny $3 Nothing }

CHAIN_NAME : INPUT  { Input }
           | OUTPUT { Output }
           | FORWARD { Forward }

Rule : SpecList '-' do ACTION { Rule (T.pack "") $1 $4 Nothing }

ACTION : ACCEPT { Accept }
       | DROP { Drop }
       | REJECT { Reject }

SpecList : Spec { $1 }
         | SpecList Spec { AndMatch $1 $2 }

Spec : '-' srcip IPList { conjunctIPMatches $3 MatchSrcIP }
     | '-' dstip IPList { conjunctIPMatches $3 MatchDstIP }
     | '-' prot Protocol { MatchProt $3 }
     | '-' inif IfList { % mapP checkValidIf $3 `thenP` \vIfs -> 
                         returnP $ conjunctIfMatches vIfs MatchInIf }
     | '-' outif IfList { % mapP checkValidIf $3 `thenP` \vIfs -> 
                         returnP $ conjunctIfMatches vIfs MatchOutIf }
     | '-' srcp PortSpec { MatchSrcPort $3 }
     | '-' dstp PortSpec { MatchDstPort $3 }
     | '-' srcsubnet RuleSubnetList { % checkSubnetList $3 `thenP` \vranges -> 
                                     returnP $ conjunctIPRangeMatches vranges MatchSrcSubnet }
     | '-' dstsubnet RuleSubnetList { % checkSubnetList $3 `thenP` \vranges -> 
                                     returnP $ conjunctIPRangeMatches vranges MatchDstSubnet }
     | '(' SpecList ')' { $2 }

IPList : IP_ADDR { [$1] }
       | IP_ADDR ',' IPList { $1 : $3 }

RuleSubnetList : IP_ADDR '/' NUMBER { [($1, $3)] }
               | IP_ADDR '/' NUMBER ',' RuleSubnetList { ($1, $3) : $5 }

PortSpec : PortList { % mapP checkValidPort $1 `thenP` \ps -> returnP ps }

PortList : NUMBER { [$1] }
         | NUMBER ',' PortList { $1 : $3 }

{
-- Estructuras intermedias para realizar el parseo de un dispositivo/subred

data SubnetFieldsData = SubnetFieldsData
    { subnetRan :: IPV4.IPv4Range
    , subnetIf :: T.Text
    }

data DeviceFieldsData = DeviceFieldsData
    { macAddr :: T.Text
    , ipAddr :: IPV4.IPv4
    , subnetRef :: T.Text  -- Nombre de la subred o "INTERNET" para firewall
    }

-- Estructura para parsear un dispositivo, el cual tiene el identificador de subred asociado, en
-- lugar de la direccion de la misma. Se incluye la flag "rawIsFirewall" para chequeos
data RawDevice = RawDevice {
    rawName     :: T.Text,
    rawMac      :: T.Text,
    rawIP       :: IPV4.IPv4,
    rawSubnetRef :: T.Text,
    rawIsFirewall :: Bool
} deriving (Show)

data Token
    = TokenDevice String
    | TokenDeviceMac 
    | TokenDeviceIP
    | TokenDeviceSubnet
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
    | TokenLParen
    | TokenRParen
    | TokenDevices
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
    | TokenSubnets
    | TokenRange
    | TokenFirewallInterface
    | TokenPublicIP

    deriving Show
    
-- obtener numero de linea del estado de la monada      
getLineNo :: P Int
getLineNo = \s l -> Ok l

lexer :: (Token -> P a) -> P a
lexer cont s = \line -> 
    case s of
        [] -> cont TokenEOF [] line
        ('\n':cs) -> lexer cont cs (line + 1)
        ('/':('/':cs)) -> lexer cont (dropWhile ((/=) '\n') cs) line -- comentarios
        (c:cs) 
            | isSpace c -> lexer cont cs line
            | isDigit c -> lexIPOrNumber cont (c:cs) s line
            | c == '"'  -> lexString cont cs s line
            | isAlpha c -> lexKeywordOrIdent cont (c:cs) s line
            | otherwise -> case c of
                '(' -> cont TokenLParen cs line
                ')' -> cont TokenRParen cs line
                '/' -> cont TokenSlash cs line
                '{' -> cont TokenOpenBracket cs line
                '}' -> cont TokenCloseBracket cs line
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
  in if any (== '.') tokenStr
       then case IPV4.decodeString tokenStr of
              Just _  -> cont (TokenIP tokenStr) rest line
              Nothing -> Failed $ "[Linea " ++ show line ++ "] Direccion IPv4 inválida (" ++ tokenStr ++ ")"
       else cont (TokenNumber (read tokenStr)) rest line

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
            "mac"        -> TokenDeviceMac
            "ip"         -> TokenDeviceIP
            "subnet"     -> TokenDeviceSubnet
            "packets"    -> TokenPackets
            "rules"      -> TokenRules
            "chain"      -> TokenChain
            "INPUT"      -> TokenInput
            "OUTPUT"     -> TokenOutput
            "FORWARD"    -> TokenForward
            "tcp"        -> TokenTCP
            "udp"        -> TokenUDP
            "any"        -> TokenANY
            "from"       -> TokenFrom
            "to"         -> TokenTo
            "ACCEPT"     -> TokenAccept
            "DROP"       -> TokenDrop
            "REJECT"     -> TokenReject
            "subnets"    -> TokenSubnets
            "devices"    -> TokenDevices
            "range"      -> TokenRange
            "interface" -> TokenFirewallInterface
            "publicip"  -> TokenPublicIP
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
            _            -> TokenIdent ident
    in cont token rest line

-- Dada una cadena, retornar una lista de slices separadas por el separador especificado
mySplit :: String -> Char -> [String]
mySplit [] _ = []
mySplit str c = let (slice, rest) = break (== c) str in slice : (mySplit (drop 1 rest) c)

-- Esta funcion se llama durante el parseo. No deberia hacer falta verificar que efectivamente sea una ip (ya verifico el parser)
-- pero por las dudas se deja el chequeo
readIP :: String -> IPV4.IPv4
readIP ipStr = case IPV4.decodeString ipStr of
    Just ip -> ip
    Nothing -> error $ "Direccion IP invalida: " ++ ipStr

-- validar lista de subnets
-- poner la tupla de una como t
checkSubnetList :: [(String, Int)] -> P [IPV4.IPv4Range]
checkSubnetList [] = returnP []
checkSubnetList ((ipStr, pref):rest) = 
    readSubnet (ipStr, pref) `thenP` (\subnet ->
    checkSubnetList rest `thenP` (\subnets ->
    returnP (subnet : subnets)))

-- Monadico para chequear por errores en el prefijo de red
readSubnet :: (String, Int) -> P IPV4.IPv4Range
readSubnet (ipStr, pref) = case IPV4.decodeString ipStr of
    Just ip -> do
                if (pref <= 0 || pref > 32) 
                then failP $ "Rango CIDR inválido para la subred (" ++ show pref ++ ")"
                else returnP $ IPV4.range ip (fromIntegral pref)
    Nothing -> failP $ "Direccion IP invalida en rango de subnet: " ++ ipStr

checkValidPort :: Int -> P Int
checkValidPort portnum  | (portnum < 0 || portnum > 65535) = failP $ "Numero de puerto inválido (" ++ (show portnum) ++ ")"
                        | otherwise = returnP portnum
                        
checkValidIf :: String -> P String
checkValidIf str = if (length str) > 15 
                    then failP $ "Nombre muy largo para ser una interfaz de red válida (" ++ str ++ ")"
                    else returnP str

checkValidMAC :: String -> P String
checkValidMAC macStr =
    let parts = mySplit macStr ':'
    in if length parts == 6 && all (\p -> (length p == 1 || length p == 2) && all isHexDigit p) parts
       then returnP macStr
       else failP $ "Dirección MAC inválida (" ++ macStr ++ ") \nFormato esperado: ?? : ?? : ?? : ?? : ?? : ?? (donde ? es un hexadecimal)"

-- como precondicion, para estas funciones las producciones de la gramatica deben garantizar que la lista de strings tenga al menos 1 elemento.
-- dada una lista de strings que identifican IPs y un constructor de tipo, retornar el tipo de match correspondiente segun el constructor
conjunctIPMatches :: [ String ] -> (IPV4.IPv4 -> Match) -> Match
conjunctIPMatches [ipStr] construct = construct (readIP ipStr)
conjunctIPMatches (ipStr : ipStrs) construct = OrMatch (construct (readIP ipStr)) (conjunctIPMatches ipStrs construct)


conjunctIPRangeMatches :: [IPV4.IPv4Range] -> (IPV4.IPv4Range -> Match) -> Match
conjunctIPRangeMatches [r] construct = construct r
conjunctIPRangeMatches (r:rs) construct = OrMatch (construct r) (conjunctIPRangeMatches rs construct)

conjunctIfMatches :: [String] -> (T.Text -> Match) -> Match
conjunctIfMatches [ifStr] c = c (T.pack ifStr)
conjunctIfMatches (ifstr : ifstrs) c = OrMatch (c $ T.pack ifstr) (conjunctIfMatches ifstrs c)


processRawDevices :: [Subnet] -> [RawDevice] -> P [Device]
processRawDevices subnets rawDevs = mapP (resolveDevice subnets) rawDevs

resolveDevice :: [Subnet] -> RawDevice -> P Device
resolveDevice subnets (RawDevice name mac ip subnetRef isFirewall)
    | isFirewall = do
        -- Para el firewall, obtener todas las interfaces de las subredes + eth3
        let subnetIfaces = map subnetInterface subnets
        let allIfaces = (subnetIfaces ++ [defaultFwIf]) -- capaz lo saco a esto
        -- El firewall no tiene una subred específica, usar un rango /32 con su IP
        let fwRange = IPV4.range ip 32 -- ?
        returnP $ Device name mac ip fwRange allIfaces -- ?
    | otherwise = do
        -- Para dispositivos normales, buscar la subred por nombre
        case find (\s -> subnetName s == subnetRef) subnets of
            Just subnet -> do
                -- Verificar que la IP esté en el rango, chequeo x las dudas, capaz no hace falta
                if subnetRange subnet `IPV4.contains` ip
                    then returnP $ Device name mac ip (subnetRange subnet) [subnetInterface subnet]
                    else failP $ "IP " ++ show ip ++ " no está en la subred " ++ T.unpack subnetRef
            Nothing -> 
                    -- el unico dispositivo cuyo identificador de
                    if subnetRef == (T.pack "INTERNET")
                    then failP $ "No se reconoce el dispositivo asociado al firewall o bien un dispositivo tiene 'INTERNET' como subred asignada."
                    else failP $ "Subred no encontrada (" ++ T.unpack subnetRef ++ ")"

-- Esta funcion se invoca al ocurrir un error de parseo
happyError :: P a
happyError = \s i -> Failed $ "[Linea " ++ show i ++ "] Error de parseo cerca de ----->" ++ take 10 s ++ "<-----"

-- Funcion a invocar para parsear.
parseFirewall :: String -> ParseResult Info
parseFirewall input = parseScript input 1
}
