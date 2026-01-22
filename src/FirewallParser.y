{
module FirewallParser (parseFirewall) where

import Common
import qualified Data.Text as T
import qualified Net.IPv4 as IPV4
import Data.Char (isSpace, isAlpha, isAlphaNum, isDigit, isHexDigit)
import Data.Word (Word8)
import Monads
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

%%

Script : Network Packets Rules { Info $1 $2 $3 }

Network : network '{' DeviceList '}' { $3 }

DeviceList : Device { [ $1] } 
    | Device DeviceList { $1 : $2 }

Device : device IDENT '{' DeviceFields '}' 
    { Device (T.pack $2) (macAddr $4) (ipAddr $4) (subnetRange $4) (ifaces $4) }

SubnetVal : IP_ADDR '/' NUMBER { % readSubnet $1 $3 }
          

DeviceFields : mac '=' STRING ';' ip '=' IP_ADDR ';' subnet '=' SubnetVal ';' interfaces '=' IfList ';'
    { % checkValidMAC $3 `thenP` \validMAC -> mapP checkValidIf $15 `thenP` \validIfs -> 
    returnP $ DeviceFieldsData
        { macAddr = T.pack validMAC
        , ipAddr = readIP $7
        , subnetRange = $11
        , ifaces = map T.pack validIfs
        } }

IfList : STRING { [$1] }
    | STRING ',' IfList { $1 : $3 }

Packets : packets '{' PacketList '}' { $3 }
-- VER: hice la gramatica tq no se admiten dispositivos sin interfaces
-- o un script con 0 envios de paquetes

PacketList : Packet { [$1] }
    | Packet PacketList { $1 : $2 }

Packet : IDENT ':' IP_ADDR '->' IP_ADDR ':' Protocol NUMBER '->' NUMBER ':' from STRING to STRING ';'
    { % checkValidPort $8 `thenP` \validSrcPort -> checkValidPort $10 `thenP` \validDstPort ->
     checkValidIf $13 `thenP` \validInIf -> checkValidIf $15 `thenP` \validOutIf ->
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

DefaultPolicy : '-' default ACTION ';' { Rule (T.pack "default") MatchAny $3 Nothing }

CHAIN_NAME : INPUT  { Input }
    | OUTPUT { Output }
    | FORWARD { Forward }

-- cambiar string "rule"
Rule : SpecList '-' do ACTION { Rule (T.pack "rule") $1 $4 Nothing }

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
    | '-' srcsubnet SubnetList { conjunctIPRangeMatches $3 MatchSrcSubnet }
    | '-' dstsubnet SubnetList { conjunctIPRangeMatches $3 MatchDstSubnet }
    | '(' SpecList ')' { $2 }

IPList : IP_ADDR { [$1] }
    | IP_ADDR ',' IPList { $1 : $3 }

SubnetList : IP_ADDR '/' NUMBER { [($1, $3)] }
    | IP_ADDR '/' NUMBER ',' SubnetList { ($1, $3) : $5 }


PortSpec : PortList { % mapP checkValidPort $1 `thenP` \ps -> returnP ps }

PortList : NUMBER { [$1] }
    | NUMBER ',' PortList { $1 : $3 }

{
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
            "from"       -> TokenFrom
            "to"         -> TokenTo
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
            _            -> TokenIdent ident
    in cont token rest line

    
mySplit :: String -> Char -> [String]
mySplit [] _ = []
mySplit str c = let (slice, rest) = break (== c) str in slice : (mySplit (drop 1 rest) c)

-- deberia alcanzar con un fromJust (IPV4.decodeString), se supone que el lexer
-- ya hizo la verificacion, pero por las dudas tiramos el error, por si el lexer falla
readIP :: String -> IPV4.IPv4
readIP ipStr = case IPV4.decodeString ipStr of
    Just ip -> ip
    Nothing -> error $ "Direccion IP invalida: " ++ ipStr

-- monadico para chequear por errores en el prefijo de red
readSubnet :: String -> Int -> P IPV4.IPv4Range
readSubnet ipStr pref = case IPV4.decodeString ipStr of
    Just ip -> do
                if (pref < 0 || pref > 32) 
                then failP $ "Rango CIDR inválido para la subred (" ++ show pref ++ ")"
                else returnP $ IPV4.range ip (fromIntegral pref)
    Nothing -> failP $ "Direccion IP invalida en rango de subnet: " ++ ipStr


checkValidPort :: Int -> P Int
checkValidPort portnum  | (portnum < 0 || portnum > 65535) = failP $ "Numero de puerto inválido (" ++ (show portnum) ++ ")"
                        | otherwise = returnP portnum
                        
checkValidIf :: String -> P String
checkValidIf str = if (length str) > 15 
                    then failP $ "Nombre de interfaz de red invalido, muy largo (" ++ str ++ ")"
                    else returnP str

checkValidMAC :: String -> P String
checkValidMAC macStr =
    let parts = mySplit macStr ':'
    in if length parts == 6 && all (\p -> (length p == 1 || length p == 2) && all isHexDigit p) parts
       then returnP macStr
       else failP $ "Dirección MAC inválida (" ++ macStr ++ ") \nFormato esperado: ?? : ?? : ?? : ?? : ?? : ?? (donde ? es un hexadecimal)"

-- precond: la gramatica debe garantizar que la lista de strings tiene al menos 1 elemento.
conjunctIPMatches :: [ String ] -> (IPV4.IPv4 -> Match) -> Match
conjunctIPMatches [ipStr] construct = construct (readIP ipStr)
conjunctIPMatches (ipStr : ipStrs) construct = AndMatch (construct (readIP ipStr)) (conjunctIPMatches ipStrs construct)

conjunctIPRangeMatches :: [(String, Int)] -> (IPV4.IPv4Range -> Match) -> Match
conjunctIPRangeMatches [(ipStr, n)] c = c (IPV4.range (readIP ipStr) (fromIntegral n))
conjunctIPRangeMatches ((ipStr, n) : ipStrs) c = AndMatch (c (IPV4.range (readIP ipStr) (fromIntegral n))) (conjunctIPRangeMatches ipStrs c)

conjunctIfMatches :: [String] -> (T.Text -> Match) -> Match
conjunctIfMatches [ifStr] c = c (T.pack ifStr)
conjunctIfMatches (ifstr : ifstrs) c = AndMatch (c $ T.pack ifstr) (conjunctIfMatches ifstrs c)

-- Manejador de errores de parseo usado por Happy
happyError :: P a
happyError = \s i -> Failed $ "[Linea " ++ show i ++ "] Error de parseo cerca de ----->" ++ take 10 s ++ "<-----"

-- Funcion a invocar para parsear.
parseFirewall :: String -> ParseResult Info
parseFirewall input = parseScript input 1
}

-- happy src/FirewallParser.y -o src/FirewallParser.hs --ghc
-- stack build
-- stack run