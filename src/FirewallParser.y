{
module FirewallParser (parseFirewall, debugTokens) where

import Common
import qualified Data.Text as T
import qualified Data.Map.Strict as M
import qualified Net.IPv4 as IPV4
import Data.Char (isSpace, isAlpha, isAlphaNum, isDigit)
import Data.Word (Word8)
}

%name parseScript
%tokentype { Token }

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
    ACCEPT          { TokenAccept }
    DROP            { TokenDrop }
    REJECT          { TokenReject }

%right '|'
%left '&'
%nonassoc not

%%

Script : Network Packets Rules { Info $1 $2 $3 }

Network : network '{' DeviceList '}' { $3 }

DeviceList : {- empty -} { [] } 
    | Device DeviceList { $1 : $2 }

Device : device IDENT '{' DeviceFields '}' 
    { Device (T.pack $2) Nothing (macAddr $4) (ipAddr $4) (subnetRange $4) (ifaces $4) }

SubnetVal : STRING { Just (parseSubnet $1) }
          | IP_ADDR '/' NUMBER { Just (readSubnet $1 $3) }
          ;

DeviceFields : mac '=' STRING ';' ip '=' IP_ADDR ';' subnet '=' SubnetVal ';' interfaces '=' '[' IfList ']' ';'
    { DeviceFieldsData
        { macAddr = T.pack $3
        , ipAddr = readIP $7
        , subnetRange = $11
        , ifaces = map T.pack $16
        } }

IfList : {- empty -} { [] }
    | STRING { [$1] }
    | STRING ',' IfList { $1 : $3 }

Packets : packets '[' PacketList ']' { $3 }

PacketList : {- empty -} { [] }
    | Packet { [$1] }
    | Packet ',' PacketList { $1 : $3 }

Packet : IDENT ':' IP_ADDR '->' IP_ADDR ':' Protocol NUMBER via STRING 
    { Packet (T.pack $1) (readIP $3) (readIP $5) 0 $8 $7 (T.pack $10) (T.pack $10) }

Protocol : tcp { TCP }
    | udp { UDP }
    | any { ANY }

Rules : rules '{' ChainDecls '}' { M.fromList $3 }

ChainDecls : {- empty -} { [] }
    | ChainDecl ChainDecls { $1 : $2 }

ChainDecl : ChainBlock { $1 }

ChainBlock : chain CHAIN_NAME '{' RuleList '}' { ($2, reverse $4) }

CHAIN_NAME : INPUT  { Input }
    | OUTPUT { Output }
    | FORWARD { Forward }

RuleList : {- empty -} { [] }
    | RulesSemiList { reverse $1 }

RulesSemiList : Rule ';' { [$1] }
    | Rule ';' RulesSemiList { $1 : $3 }

Rule : SpecList '-' do ACTION { Rule (T.pack "rule") $1 $4 Nothing }

ACTION : ACCEPT { Accept }
    | DROP { Drop }
    | REJECT { Reject }

SpecList : Spec { $1 }
    | SpecList Spec { AndMatch $1 $2 }
    | SpecList '&' Spec { AndMatch $1 $3 }
    | SpecList '|' Spec { OrMatch $1 $3 }
    | '!' Spec { NotMatch $2 }

Spec : '-' srcip IP_ADDR { MatchSrcIP (readIP $3) }
    | '-' dstip IP_ADDR { MatchDstIP (readIP $3) }
    | '-' prot Protocol { MatchProt $3 }
    | '-' inif STRING { MatchInIf (T.pack $3) }
    | '-' outif STRING { MatchOutIf (T.pack $3) }
    | '-' srcp PortSpec { MatchSrcPort $3 }
    | '-' dstp PortSpec { MatchDstPort $3 }
    | '-' srcsubnet IP_ADDR '/' NUMBER { MatchSrcSubnet (readSubnet $3 $5) }
    | '-' dstsubnet IP_ADDR '/' NUMBER { MatchDstSubnet (readSubnet $3 $5) }
    | '(' SpecList ')' { $2 }

PortSpec : NUMBER { [$1] }
    | '[' PortList ']' { $2 }

PortList : NUMBER { [$1] }
    | NUMBER ',' PortList { $1 : $3 }

{
-- Error handling function that Happy expects
happyError :: [Token] -> a
happyError tokens = error $ "Parse error near tokens: " ++ show (take 5 tokens)

data DeviceFieldsData = DeviceFieldsData
    { macAddr :: T.Text
    , ipAddr :: IPV4.IPv4
    , subnetRange :: Maybe IPV4.IPv4Range
    , ifaces :: [Interface]
    }

lexer :: String -> [Token]
lexer = lexer' 1
  where
    lexer' :: Int -> String -> [Token]
    lexer' _ [] = []
    lexer' lineNo s@(c:cs)
        | isSpace c = lexer' (if c == '\n' then lineNo + 1 else lineNo) cs
        | c == '-' && not (null cs) && head cs == '>' = TokenArrow : lexer' lineNo (tail cs)
        | c == '-' = TokenDash : lexer' lineNo cs
        | c == '&' = TokenAnd : lexer' lineNo cs
        | c == '|' = TokenOr : lexer' lineNo cs
        | c == '!' = TokenNot : lexer' lineNo cs
        | c == '(' = TokenLParen : lexer' lineNo cs
        | c == ')' = TokenRParen : lexer' lineNo cs
        | c == '/' = TokenSlash : lexer' lineNo cs
        | c == '{' = TokenOpenBracket : lexer' lineNo cs
        | c == '}' = TokenCloseBracket : lexer' lineNo cs
        | c == '[' = TokenOpenSquareBracket : lexer' lineNo cs
        | c == ']' = TokenCloseSquareBracket : lexer' lineNo cs
        | c == '=' = TokenAssign : lexer' lineNo cs
        | c == ';' = TokenSemicolon : lexer' lineNo cs
        | c == ':' = TokenColon : lexer' lineNo cs
        | c == ',' = TokenComma : lexer' lineNo cs
        | isDigit c = lexIPOrNumber lineNo s  
        | c == '"' = lexString lineNo cs
        | isAlpha c = lexKeywordOrIdent lineNo s
        | otherwise = error $ "Unexpected character '" ++ [c] ++ "' at line " ++ show lineNo

    -- Number detected: check whether it's an IP address or a number and get its respective token
    lexIPOrNumber :: Int -> String -> [Token]
    lexIPOrNumber lineNo s = 
        -- Read a token that could be an IP address (digits and dots) or just a number
        let (token, rest) = span (\c -> isDigit c || c == '.') s
        in if any (== '.') token
            then if isValidIP token
                then TokenIP token : lexer' lineNo rest
                else error $ "Invalid IP address format: " ++ token
            else TokenNumber (read token) : lexer' lineNo rest

    -- unused for now
    lexNumber :: Int -> String -> [Token]
    lexNumber lineNo s = 
        let (num, rest) = span isDigit s
        in TokenNumber (read num) : lexer' lineNo rest

    lexString :: Int -> String -> [Token]
    lexString lineNo s =
        case break (== '"') s of
            (str, '"':rest) -> 
                -- Check if the string is a valid IP address
                if isValidIP str 
                then TokenIP str : lexer' lineNo rest
                else TokenString str : lexer' lineNo rest
            _ -> error $ "Unterminated string at line " ++ show lineNo

    lexKeywordOrIdent :: Int -> String -> [Token]
    lexKeywordOrIdent lineNo s =
        let (ident, rest) = span (\c -> isAlphaNum c || c == '.' || c == '-') s
            token = case ident of
                "device" -> TokenDevice ident
                "desc" -> TokenDeviceDescription
                "mac" -> TokenDeviceMac
                "ip" -> TokenDeviceIP
                "subnet" -> TokenDeviceSubnet
                "interfaces" -> TokenDeviceInterfaces
                "packets" -> TokenPackets
                "rules" -> TokenRules
                "chain" -> TokenChain
                "INPUT" -> TokenInput
                "OUTPUT" -> TokenOutput
                "FORWARD" -> TokenForward
                "tcp" -> TokenTCP
                "udp" -> TokenUDP
                "any" -> TokenANY
                "via" -> TokenVia
                "ACCEPT" -> TokenAccept
                "DROP" -> TokenDrop
                "REJECT" -> TokenReject
                "network" -> TokenNetwork
                "srcip" -> TokenSrcIP
                "dstip" -> TokenDstIP
                "prot" -> TokenProt
                "inif" -> TokenInIf
                "outif" -> TokenOutIf
                "srcp" -> TokenSrcPort
                "dstp" -> TokenDstPort
                "srcsubnet" -> TokenSrcSubnet
                "dstsubnet" -> TokenDstSubnet
                "do" -> TokenDo
                _ -> if isValidIP ident then TokenIP ident else TokenIdent ident
        in token : lexer' lineNo rest

    -- Helper function to check if a string is a valid IP address
    isValidIP :: String -> Bool
    isValidIP s = 
        let parts = split '.' s
        in length parts == 4 && all (\p -> not (null p) && all isDigit p && let n = read p in n >= 0 && n <= 255) parts
    
    split :: Char -> String -> [String]
    split _ [] = []
    split c s = let (part, rest) = break (== c) s in part : split c (drop 1 rest)

-- Helper functions for IP parsing
readIP :: String -> IPV4.IPv4
readIP ipStr = case IPV4.decodeString ipStr of
    Just ip -> ip
    Nothing -> error $ "Invalid IP address: " ++ ipStr


readSubnet :: String -> Int -> IPV4.IPv4Range
readSubnet ipStr prefix = case IPV4.decodeString ipStr of
    Just ip -> IPV4.range ip (fromIntegral prefix)
    Nothing -> error $ "Invalid IP address in subnet: " ++ ipStr

-- Helper function to parse a subnet string in the form "192.168.1.0/24"
parseSubnet :: String -> IPV4.IPv4Range
parseSubnet s = 
    let (ipStr, rest) = break (== '/') s
        prefixStr = drop 1 rest
        prefix = read prefixStr :: Int
    in readSubnet ipStr prefix

-- Main parsing function - parseScript returns Info directly, not Either
parseFirewall :: String -> Info
parseFirewall input = parseScript (lexer input)


-- testing function
debugTokens :: String -> IO ()
debugTokens input = mapM_ print (lexer input)
}

-- happy src/FirewallParser.y -o src/FirewallParser.hs --ghc
-- stack build
-- stack run