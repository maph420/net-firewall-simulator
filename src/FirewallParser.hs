{-# OPTIONS_GHC -w #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE NoStrictData #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE PartialTypeSignatures #-}
module FirewallParser (parseFirewall) where

import Common
import qualified Data.Text as T
import qualified Net.IPv4 as IPV4
import Data.Char (isSpace, isAlpha, isAlphaNum, isDigit, isHexDigit)
import Data.Word (Word8)
import Monads
import qualified Control.Monad as Happy_Prelude
import qualified Data.Bool as Happy_Prelude
import qualified Data.Function as Happy_Prelude
import qualified Data.Int as Happy_Prelude
import qualified Data.List as Happy_Prelude
import qualified Data.Maybe as Happy_Prelude
import qualified Data.String as Happy_Prelude
import qualified Data.Tuple as Happy_Prelude
import qualified GHC.Err as Happy_Prelude
import qualified GHC.Num as Happy_Prelude
import qualified Text.Show as Happy_Prelude
import qualified Data.Array as Happy_Data_Array
import qualified Data.Bits as Bits
import qualified GHC.Exts as Happy_GHC_Exts
import Control.Applicative(Applicative(..))
import Control.Monad (ap)

-- parser produced by Happy Version 2.1.7

data HappyAbsSyn t5 t6 t7 t8 t9 t10 t11 t12 t13 t14 t15 t16 t17 t18 t19 t20 t21 t22 t23 t24 t25 t26 t27 t28 t29 t30 t31 t32 t33 t34
        = HappyTerminal (Token)
        | HappyErrorToken Happy_Prelude.Int
        | HappyAbsSyn5 t5
        | HappyAbsSyn6 t6
        | HappyAbsSyn7 t7
        | HappyAbsSyn8 t8
        | HappyAbsSyn9 t9
        | HappyAbsSyn10 t10
        | HappyAbsSyn11 t11
        | HappyAbsSyn12 t12
        | HappyAbsSyn13 t13
        | HappyAbsSyn14 t14
        | HappyAbsSyn15 t15
        | HappyAbsSyn16 t16
        | HappyAbsSyn17 t17
        | HappyAbsSyn18 t18
        | HappyAbsSyn19 t19
        | HappyAbsSyn20 t20
        | HappyAbsSyn21 t21
        | HappyAbsSyn22 t22
        | HappyAbsSyn23 t23
        | HappyAbsSyn24 t24
        | HappyAbsSyn25 t25
        | HappyAbsSyn26 t26
        | HappyAbsSyn27 t27
        | HappyAbsSyn28 t28
        | HappyAbsSyn29 t29
        | HappyAbsSyn30 t30
        | HappyAbsSyn31 t31
        | HappyAbsSyn32 t32
        | HappyAbsSyn33 t33
        | HappyAbsSyn34 t34

{-# NOINLINE happyTokenStrings #-}
happyTokenStrings = ["device","mac","ip","subnet","'{'","'}'","'='","';'","packets","'->'","':'","tcp","udp","any","','","rules","chain","INPUT","OUTPUT","FORWARD","from","to","STRING","IDENT","NUMBER","IP_ADDR","'('","')'","'-'","'/'","srcip","dstip","prot","inif","outif","subnets","range","interface","devices","fwip","fwmac","srcp","dstp","srcsubnet","dstsubnet","do","default","ACCEPT","DROP","REJECT","%eof"]

happyActOffsets :: HappyAddr
happyActOffsets = HappyA# "\xec\xff\xff\xff\xec\xff\xff\xff\xdf\xff\xff\xff\x2e\x00\x00\x00\xf3\xff\xff\xff\x31\x00\x00\x00\x32\x00\x00\x00\x56\x00\x00\x00\x51\x00\x00\x00\x38\x00\x00\x00\x59\x00\x00\x00\x5b\x00\x00\x00\x5e\x00\x00\x00\x37\x00\x00\x00\x5f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x00\x00\x00\x00\x00\x00\x00\x63\x00\x00\x00\x5d\x00\x00\x00\x68\x00\x00\x00\x52\x00\x00\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x00\x00\x00\x69\x00\x00\x00\x54\x00\x00\x00\x65\x00\x00\x00\x50\x00\x00\x00\x6b\x00\x00\x00\x67\x00\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6d\x00\x00\x00\x6a\x00\x00\x00\x0a\x00\x00\x00\xfe\xff\xff\xff\x6e\x00\x00\x00\x6f\x00\x00\x00\x70\x00\x00\x00\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x00\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x71\x00\x00\x00\x61\x00\x00\x00\x64\x00\x00\x00\x10\x00\x00\x00\x6c\x00\x00\x00\x74\x00\x00\x00\x00\x00\x00\x00\x75\x00\x00\x00\x78\x00\x00\x00\x7b\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x7a\x00\x00\x00\x27\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\xe2\xff\xff\xff\x79\x00\x00\x00\x76\x00\x00\x00\x62\x00\x00\x00\x7e\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x77\x00\x00\x00\x77\x00\x00\x00\x13\x00\x00\x00\x7c\x00\x00\x00\x7c\x00\x00\x00\x7d\x00\x00\x00\x7d\x00\x00\x00\x7f\x00\x00\x00\x7f\x00\x00\x00\x08\x00\x00\x00\x21\x00\x00\x00\xf8\xff\xff\xff\x00\x00\x00\x00\xe8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x83\x00\x00\x00\x82\x00\x00\x00\x85\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x86\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8b\x00\x00\x00\x00\x00\x00\x00\x84\x00\x00\x00\x87\x00\x00\x00\x8a\x00\x00\x00\x91\x00\x00\x00\x8c\x00\x00\x00\x8d\x00\x00\x00\x8e\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x92\x00\x00\x00\x93\x00\x00\x00\x94\x00\x00\x00\x98\x00\x00\x00\x96\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00\x97\x00\x00\x00\x99\x00\x00\x00\x00\x00\x00\x00\x9d\x00\x00\x00\x9c\x00\x00\x00\x00\x00\x00\x00\x9a\x00\x00\x00\x9b\x00\x00\x00\x9e\x00\x00\x00\xa2\x00\x00\x00\x9f\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\xa3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyGotoOffsets :: HappyAddr
happyGotoOffsets = HappyA# "\x47\x00\x00\x00\xb0\x00\x00\x00\x8f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x00\x00\x00\xa8\x00\x00\x00\x00\x00\x00\x00\x45\x00\x00\x00\xa7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x49\x00\x00\x00\x00\x00\x00\x00\x4b\x00\x00\x00\x00\x00\x00\x00\xb5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4e\x00\x00\x00\xa6\x00\x00\x00\xb2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa5\x00\x00\x00\x00\x00\x00\x00\x43\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb1\x00\x00\x00\xa9\x00\x00\x00\xaa\x00\x00\x00\xb3\x00\x00\x00\xac\x00\x00\x00\xad\x00\x00\x00\x44\x00\x00\x00\x4a\x00\x00\x00\xa4\x00\x00\x00\xae\x00\x00\x00\xab\x00\x00\x00\xaf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb6\x00\x00\x00\xb8\x00\x00\x00\xb9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xba\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyDefActions :: HappyAddr
happyDefActions = HappyA# "\xfd\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xfa\xff\xff\xff\xfc\xff\xff\xff\x00\x00\x00\x00\xfe\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf5\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf4\xff\xff\xff\xf6\xff\xff\xff\xe8\xff\xff\xff\x00\x00\x00\x00\xef\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xee\xff\xff\xff\xf0\xff\xff\xff\x00\x00\x00\x00\xe8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\xff\xff\xff\xdf\xff\xff\xff\xde\xff\xff\xff\xe7\xff\xff\xff\xe9\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf9\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe5\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf3\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe5\xff\xff\xff\xe2\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xd9\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf7\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\xff\xff\xff\x00\x00\x00\x00\xe3\xff\xff\xff\xe4\xff\xff\xff\xe6\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xce\xff\xff\xff\x00\x00\x00\x00\xdc\xff\xff\xff\xdb\xff\xff\xff\xda\xff\xff\xff\xcf\xff\xff\xff\x00\x00\x00\x00\xd0\xff\xff\xff\xd1\xff\xff\xff\xc7\xff\xff\xff\xc6\xff\xff\xff\xd2\xff\xff\xff\xd3\xff\xff\xff\xcd\xff\xff\xff\xd4\xff\xff\xff\xd5\xff\xff\xff\xec\xff\xff\xff\xeb\xff\xff\xff\xea\xff\xff\xff\xd6\xff\xff\xff\xcb\xff\xff\xff\xd7\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe1\xff\xff\xff\xdd\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc9\xff\xff\xff\xc5\xff\xff\xff\xcc\xff\xff\xff\xca\xff\xff\xff\x00\x00\x00\x00\xf8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xf1\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xc8\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf2\xff\xff\xff\x00\x00\x00\x00\xed\xff\xff\xff"#

happyCheck :: HappyAddr
happyCheck = HappyA# "\xff\xff\xff\xff\x03\x00\x00\x00\x20\x00\x00\x00\x21\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x28\x00\x00\x00\x20\x00\x00\x00\x21\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x2b\x00\x00\x00\x2c\x00\x00\x00\x2d\x00\x00\x00\x2e\x00\x00\x00\x25\x00\x00\x00\x30\x00\x00\x00\x2b\x00\x00\x00\x2c\x00\x00\x00\x2d\x00\x00\x00\x2e\x00\x00\x00\x2f\x00\x00\x00\x20\x00\x00\x00\x21\x00\x00\x00\x22\x00\x00\x00\x23\x00\x00\x00\x24\x00\x00\x00\x13\x00\x00\x00\x14\x00\x00\x00\x15\x00\x00\x00\x0d\x00\x00\x00\x0e\x00\x00\x00\x0f\x00\x00\x00\x2b\x00\x00\x00\x2c\x00\x00\x00\x2d\x00\x00\x00\x2e\x00\x00\x00\x34\x00\x00\x00\x2a\x00\x00\x00\x11\x00\x00\x00\x12\x00\x00\x00\x13\x00\x00\x00\x1c\x00\x00\x00\x15\x00\x00\x00\x1e\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x11\x00\x00\x00\x12\x00\x00\x00\x13\x00\x00\x00\x06\x00\x00\x00\x15\x00\x00\x00\x05\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x31\x00\x00\x00\x32\x00\x00\x00\x33\x00\x00\x00\x0a\x00\x00\x00\x1c\x00\x00\x00\x1d\x00\x00\x00\x1e\x00\x00\x00\x31\x00\x00\x00\x32\x00\x00\x00\x33\x00\x00\x00\x1c\x00\x00\x00\x1c\x00\x00\x00\x1e\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x19\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x0f\x00\x00\x00\x10\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x06\x00\x00\x00\x0f\x00\x00\x00\x10\x00\x00\x00\x06\x00\x00\x00\x1c\x00\x00\x00\x1d\x00\x00\x00\x07\x00\x00\x00\x05\x00\x00\x00\x07\x00\x00\x00\x06\x00\x00\x00\x1c\x00\x00\x00\x1d\x00\x00\x00\x19\x00\x00\x00\x06\x00\x00\x00\x02\x00\x00\x00\x19\x00\x00\x00\x06\x00\x00\x00\x19\x00\x00\x00\x12\x00\x00\x00\x08\x00\x00\x00\x07\x00\x00\x00\x0c\x00\x00\x00\x07\x00\x00\x00\x1b\x00\x00\x00\x07\x00\x00\x00\x07\x00\x00\x00\x26\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x09\x00\x00\x00\x1b\x00\x00\x00\x12\x00\x00\x00\x0b\x00\x00\x00\x09\x00\x00\x00\x1b\x00\x00\x00\x1f\x00\x00\x00\x09\x00\x00\x00\x07\x00\x00\x00\x09\x00\x00\x00\x18\x00\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\xff\xff\xff\xff\x27\x00\x00\x00\x08\x00\x00\x00\xff\xff\xff\xff\x18\x00\x00\x00\x08\x00\x00\x00\xff\xff\xff\xff\x09\x00\x00\x00\x1a\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x09\x00\x00\x00\x18\x00\x00\x00\x06\x00\x00\x00\xff\xff\xff\xff\x1a\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x1b\x00\x00\x00\x10\x00\x00\x00\x0b\x00\x00\x00\x09\x00\x00\x00\x1a\x00\x00\x00\x18\x00\x00\x00\x1f\x00\x00\x00\x09\x00\x00\x00\x05\x00\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x00\x18\x00\x00\x00\x10\x00\x00\x00\x1b\x00\x00\x00\x1a\x00\x00\x00\x29\x00\x00\x00\x1a\x00\x00\x00\x09\x00\x00\x00\x09\x00\x00\x00\x1b\x00\x00\x00\x1b\x00\x00\x00\x1a\x00\x00\x00\x16\x00\x00\x00\x01\x00\x00\x00\x0a\x00\x00\x00\x18\x00\x00\x00\x1b\x00\x00\x00\x0e\x00\x00\x00\x17\x00\x00\x00\x19\x00\x00\x00\x18\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x09\x00\x00\x00\x05\x00\x00\x00\x18\x00\x00\x00\x0d\x00\x00\x00\x1b\x00\x00\x00\x0d\x00\x00\x00\x16\x00\x00\x00\xff\xff\xff\xff\x1a\x00\x00\x00\x1a\x00\x00\x00\x19\x00\x00\x00\x19\x00\x00\x00\x18\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x16\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1a\x00\x00\x00\x19\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x1b\x00\x00\x00\x1d\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"#

happyTable :: HappyAddr
happyTable = HappyA# "\x00\x00\x00\x00\x2a\x00\x00\x00\x4c\x00\x00\x00\x4d\x00\x00\x00\x4e\x00\x00\x00\x4f\x00\x00\x00\x50\x00\x00\x00\x08\x00\x00\x00\x4c\x00\x00\x00\x4d\x00\x00\x00\x4e\x00\x00\x00\x4f\x00\x00\x00\x50\x00\x00\x00\x51\x00\x00\x00\x52\x00\x00\x00\x53\x00\x00\x00\x54\x00\x00\x00\x04\x00\x00\x00\x55\x00\x00\x00\x51\x00\x00\x00\x52\x00\x00\x00\x53\x00\x00\x00\x54\x00\x00\x00\x61\x00\x00\x00\x4c\x00\x00\x00\x4d\x00\x00\x00\x4e\x00\x00\x00\x4f\x00\x00\x00\x50\x00\x00\x00\x2d\x00\x00\x00\x2e\x00\x00\x00\x2f\x00\x00\x00\x72\x00\x00\x00\x73\x00\x00\x00\x74\x00\x00\x00\x51\x00\x00\x00\x52\x00\x00\x00\x53\x00\x00\x00\x54\x00\x00\x00\xff\xff\xff\xff\x2b\x00\x00\x00\x3d\x00\x00\x00\x3e\x00\x00\x00\x3f\x00\x00\x00\x44\x00\x00\x00\x40\x00\x00\x00\x45\x00\x00\x00\x41\x00\x00\x00\x42\x00\x00\x00\x5a\x00\x00\x00\x3e\x00\x00\x00\x3f\x00\x00\x00\x06\x00\x00\x00\x40\x00\x00\x00\x0e\x00\x00\x00\x41\x00\x00\x00\x42\x00\x00\x00\x64\x00\x00\x00\x65\x00\x00\x00\x66\x00\x00\x00\x0b\x00\x00\x00\x44\x00\x00\x00\x62\x00\x00\x00\x57\x00\x00\x00\x64\x00\x00\x00\x65\x00\x00\x00\x66\x00\x00\x00\x44\x00\x00\x00\x44\x00\x00\x00\x59\x00\x00\x00\x57\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x14\x00\x00\x00\x0b\x00\x00\x00\x0c\x00\x00\x00\x14\x00\x00\x00\x15\x00\x00\x00\x0f\x00\x00\x00\x0c\x00\x00\x00\x0f\x00\x00\x00\x1b\x00\x00\x00\x1c\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x15\x00\x00\x00\x22\x00\x00\x00\x1c\x00\x00\x00\x24\x00\x00\x00\x25\x00\x00\x00\x55\x00\x00\x00\x42\x00\x00\x00\x09\x00\x00\x00\x2f\x00\x00\x00\x25\x00\x00\x00\x12\x00\x00\x00\x6c\x00\x00\x00\x6a\x00\x00\x00\x11\x00\x00\x00\x0e\x00\x00\x00\x1a\x00\x00\x00\x1f\x00\x00\x00\x69\x00\x00\x00\x6a\x00\x00\x00\x1e\x00\x00\x00\x1b\x00\x00\x00\x17\x00\x00\x00\x18\x00\x00\x00\x28\x00\x00\x00\x1e\x00\x00\x00\x27\x00\x00\x00\x33\x00\x00\x00\x24\x00\x00\x00\x22\x00\x00\x00\x34\x00\x00\x00\x32\x00\x00\x00\x31\x00\x00\x00\x3b\x00\x00\x00\x21\x00\x00\x00\x3a\x00\x00\x00\x39\x00\x00\x00\x38\x00\x00\x00\x48\x00\x00\x00\x36\x00\x00\x00\x27\x00\x00\x00\x37\x00\x00\x00\x5e\x00\x00\x00\x46\x00\x00\x00\x47\x00\x00\x00\x5d\x00\x00\x00\x5c\x00\x00\x00\x5a\x00\x00\x00\x3d\x00\x00\x00\x4b\x00\x00\x00\x79\x00\x00\x00\x5f\x00\x00\x00\x00\x00\x00\x00\x49\x00\x00\x00\x83\x00\x00\x00\x00\x00\x00\x00\x3c\x00\x00\x00\x82\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x4a\x00\x00\x00\x00\x00\x00\x00\x76\x00\x00\x00\x8b\x00\x00\x00\x6f\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x6c\x00\x00\x00\x7e\x00\x00\x00\x7d\x00\x00\x00\x68\x00\x00\x00\x7c\x00\x00\x00\x8a\x00\x00\x00\x8f\x00\x00\x00\x7b\x00\x00\x00\x7a\x00\x00\x00\x7f\x00\x00\x00\x8e\x00\x00\x00\x90\x00\x00\x00\x92\x00\x00\x00\x94\x00\x00\x00\x6f\x00\x00\x00\x8d\x00\x00\x00\x76\x00\x00\x00\x6c\x00\x00\x00\x60\x00\x00\x00\x86\x00\x00\x00\x98\x00\x00\x00\x9a\x00\x00\x00\x85\x00\x00\x00\x84\x00\x00\x00\x8c\x00\x00\x00\x93\x00\x00\x00\x02\x00\x00\x00\x09\x00\x00\x00\x96\x00\x00\x00\x68\x00\x00\x00\x12\x00\x00\x00\x97\x00\x00\x00\x95\x00\x00\x00\x99\x00\x00\x00\x1f\x00\x00\x00\x2b\x00\x00\x00\x28\x00\x00\x00\x34\x00\x00\x00\x57\x00\x00\x00\x77\x00\x00\x00\x68\x00\x00\x00\x70\x00\x00\x00\x62\x00\x00\x00\x00\x00\x00\x00\x76\x00\x00\x00\x74\x00\x00\x00\x6f\x00\x00\x00\x6d\x00\x00\x00\x57\x00\x00\x00\x00\x00\x00\x00\x66\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00\x00\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x86\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"#

happyReduceArr = Happy_Data_Array.array (1, 58) [
        (1 , happyReduce_1),
        (2 , happyReduce_2),
        (3 , happyReduce_3),
        (4 , happyReduce_4),
        (5 , happyReduce_5),
        (6 , happyReduce_6),
        (7 , happyReduce_7),
        (8 , happyReduce_8),
        (9 , happyReduce_9),
        (10 , happyReduce_10),
        (11 , happyReduce_11),
        (12 , happyReduce_12),
        (13 , happyReduce_13),
        (14 , happyReduce_14),
        (15 , happyReduce_15),
        (16 , happyReduce_16),
        (17 , happyReduce_17),
        (18 , happyReduce_18),
        (19 , happyReduce_19),
        (20 , happyReduce_20),
        (21 , happyReduce_21),
        (22 , happyReduce_22),
        (23 , happyReduce_23),
        (24 , happyReduce_24),
        (25 , happyReduce_25),
        (26 , happyReduce_26),
        (27 , happyReduce_27),
        (28 , happyReduce_28),
        (29 , happyReduce_29),
        (30 , happyReduce_30),
        (31 , happyReduce_31),
        (32 , happyReduce_32),
        (33 , happyReduce_33),
        (34 , happyReduce_34),
        (35 , happyReduce_35),
        (36 , happyReduce_36),
        (37 , happyReduce_37),
        (38 , happyReduce_38),
        (39 , happyReduce_39),
        (40 , happyReduce_40),
        (41 , happyReduce_41),
        (42 , happyReduce_42),
        (43 , happyReduce_43),
        (44 , happyReduce_44),
        (45 , happyReduce_45),
        (46 , happyReduce_46),
        (47 , happyReduce_47),
        (48 , happyReduce_48),
        (49 , happyReduce_49),
        (50 , happyReduce_50),
        (51 , happyReduce_51),
        (52 , happyReduce_52),
        (53 , happyReduce_53),
        (54 , happyReduce_54),
        (55 , happyReduce_55),
        (56 , happyReduce_56),
        (57 , happyReduce_57),
        (58 , happyReduce_58)
        ]

happyRuleArr :: HappyAddr
happyRuleArr = HappyA# "\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x05\x00\x00\x00\x03\x00\x00\x00\x06\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x07\x00\x00\x00\x02\x00\x00\x00\x08\x00\x00\x00\x05\x00\x00\x00\x09\x00\x00\x00\x0c\x00\x00\x00\x09\x00\x00\x00\x08\x00\x00\x00\x0a\x00\x00\x00\x04\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x00\x00\x10\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x0d\x00\x00\x00\x01\x00\x00\x00\x0e\x00\x00\x00\x04\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x02\x00\x00\x00\x10\x00\x00\x00\x05\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x01\x00\x00\x00\x16\x00\x00\x00\x01\x00\x00\x00\x16\x00\x00\x00\x01\x00\x00\x00\x17\x00\x00\x00\x01\x00\x00\x00\x17\x00\x00\x00\x02\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x18\x00\x00\x00\x03\x00\x00\x00\x19\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x03\x00\x00\x00\x1a\x00\x00\x00\x01\x00\x00\x00\x1a\x00\x00\x00\x03\x00\x00\x00\x1b\x00\x00\x00\x03\x00\x00\x00\x1b\x00\x00\x00\x05\x00\x00\x00\x1c\x00\x00\x00\x01\x00\x00\x00\x1d\x00\x00\x00\x01\x00\x00\x00\x1d\x00\x00\x00\x03\x00\x00\x00"#

happyCatchStates :: [Happy_Prelude.Int]
happyCatchStates = []

happy_n_terms = 53 :: Happy_Prelude.Int
happy_n_nonterms = 30 :: Happy_Prelude.Int

happy_n_starts = 1 :: Happy_Prelude.Int

happyReduce_1 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_1 = happyMonadReduce 4# 0# happyReduction_1
happyReduction_1 ((HappyAbsSyn19  happy_var_4) `HappyStk`
        (HappyAbsSyn15  happy_var_3) `HappyStk`
        (HappyAbsSyn11  happy_var_2) `HappyStk`
        (HappyAbsSyn6  happy_var_1) `HappyStk`
        happyRest) tk
         = happyThen ((( processRawDevices happy_var_1 happy_var_2 `thenP` \validDevices ->
    returnP $ Info happy_var_1 validDevices happy_var_3 happy_var_4))
        ) (\r -> happyReturn (HappyAbsSyn5 r))

happyReduce_2 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_2 = happySpecReduce_0  1# happyReduction_2
happyReduction_2  =  HappyAbsSyn6
                 ([]
        )

happyReduce_3 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_3 = happyReduce 4# 1# happyReduction_3
happyReduction_3 (_ `HappyStk`
        (HappyAbsSyn7  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn6
                 (happy_var_3
        ) `HappyStk` happyRest

happyReduce_4 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_4 = happySpecReduce_1  2# happyReduction_4
happyReduction_4 (HappyAbsSyn8  happy_var_1)
         =  HappyAbsSyn7
                 ([happy_var_1]
        )
happyReduction_4 _  = notHappyAtAll 

happyReduce_5 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_5 = happySpecReduce_2  2# happyReduction_5
happyReduction_5 (HappyAbsSyn7  happy_var_2)
        (HappyAbsSyn8  happy_var_1)
         =  HappyAbsSyn7
                 (happy_var_1 : happy_var_2
        )
happyReduction_5 _ _  = notHappyAtAll 

happyReduce_6 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_6 = happyReduce 5# 3# happyReduction_6
happyReduction_6 (_ `HappyStk`
        (HappyAbsSyn9  happy_var_4) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIdent happy_var_2)) `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn8
                 (Subnet (T.pack happy_var_2) (subnetRan happy_var_4) (subnetIf happy_var_4)
        ) `HappyStk` happyRest

happyReduce_7 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_7 = happyMonadReduce 8# 4# happyReduction_7
happyReduction_7 (_ `HappyStk`
        (HappyTerminal (TokenString happy_var_7)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyAbsSyn10  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( readSubnet happy_var_3 `thenP` \validRange ->
      checkValidIf happy_var_7 `thenP` \validIf -> 
      returnP (SubnetFieldsData validRange (T.pack validIf))))
        ) (\r -> happyReturn (HappyAbsSyn9 r))

happyReduce_8 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_8 = happySpecReduce_3  5# happyReduction_8
happyReduction_8 (HappyTerminal (TokenNumber happy_var_3))
        _
        (HappyTerminal (TokenIP happy_var_1))
         =  HappyAbsSyn10
                 ((happy_var_1, happy_var_3)
        )
happyReduction_8 _ _ _  = notHappyAtAll 

happyReduce_9 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_9 = happyReduce 4# 6# happyReduction_9
happyReduction_9 (_ `HappyStk`
        (HappyAbsSyn12  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn11
                 (happy_var_3
        ) `HappyStk` happyRest

happyReduce_10 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_10 = happySpecReduce_1  7# happyReduction_10
happyReduction_10 (HappyAbsSyn13  happy_var_1)
         =  HappyAbsSyn12
                 ([ happy_var_1 ]
        )
happyReduction_10 _  = notHappyAtAll 

happyReduce_11 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_11 = happySpecReduce_2  7# happyReduction_11
happyReduction_11 (HappyAbsSyn12  happy_var_2)
        (HappyAbsSyn13  happy_var_1)
         =  HappyAbsSyn12
                 (happy_var_1 : happy_var_2
        )
happyReduction_11 _ _  = notHappyAtAll 

happyReduce_12 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_12 = happyReduce 5# 8# happyReduction_12
happyReduction_12 (_ `HappyStk`
        (HappyAbsSyn14  happy_var_4) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIdent happy_var_2)) `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn13
                 (RawDevice (T.pack happy_var_2) (macAddr happy_var_4) (ipAddr happy_var_4) (subnetRef happy_var_4) (happy_var_2 == "firewall")
        ) `HappyStk` happyRest

happyReduce_13 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_13 = happyMonadReduce 12# 9# happyReduction_13
happyReduction_13 (_ `HappyStk`
        (HappyTerminal (TokenIdent happy_var_11)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIP happy_var_7)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenString happy_var_3)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( checkValidMAC happy_var_3 `thenP` \validMAC -> 
            returnP (DeviceFieldsData (T.pack validMAC) (readIP happy_var_7) (T.pack happy_var_11))))
        ) (\r -> happyReturn (HappyAbsSyn14 r))

happyReduce_14 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_14 = happyMonadReduce 8# 9# happyReduction_14
happyReduction_14 (_ `HappyStk`
        (HappyTerminal (TokenIP happy_var_7)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenString happy_var_3)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( checkValidMAC happy_var_3 `thenP` \validMAC -> 
            returnP (DeviceFieldsData (T.pack validMAC) (readIP happy_var_7) (T.pack "INTERNET"))))
        ) (\r -> happyReturn (HappyAbsSyn14 r))

happyReduce_15 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_15 = happyReduce 4# 10# happyReduction_15
happyReduction_15 (_ `HappyStk`
        (HappyAbsSyn16  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn15
                 (happy_var_3
        ) `HappyStk` happyRest

happyReduce_16 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_16 = happySpecReduce_1  11# happyReduction_16
happyReduction_16 (HappyAbsSyn17  happy_var_1)
         =  HappyAbsSyn16
                 ([happy_var_1]
        )
happyReduction_16 _  = notHappyAtAll 

happyReduce_17 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_17 = happySpecReduce_2  11# happyReduction_17
happyReduction_17 (HappyAbsSyn16  happy_var_2)
        (HappyAbsSyn17  happy_var_1)
         =  HappyAbsSyn16
                 (happy_var_1 : happy_var_2
        )
happyReduction_17 _ _  = notHappyAtAll 

happyReduce_18 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_18 = happyMonadReduce 16# 12# happyReduction_18
happyReduction_18 (_ `HappyStk`
        (HappyTerminal (TokenString happy_var_15)) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenString happy_var_13)) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenNumber happy_var_10)) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenNumber happy_var_8)) `HappyStk`
        (HappyAbsSyn18  happy_var_7) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIP happy_var_5)) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIP happy_var_3)) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIdent happy_var_1)) `HappyStk`
        happyRest) tk
         = happyThen ((( checkValidPort happy_var_8 `thenP` \validSrcPort -> 
      checkValidPort happy_var_10 `thenP` \validDstPort ->
      checkValidIf happy_var_13 `thenP` \validInIf -> 
      checkValidIf happy_var_15 `thenP` \validOutIf ->
      returnP $ Packet (T.pack happy_var_1) (readIP happy_var_3) (readIP happy_var_5) validSrcPort validDstPort happy_var_7 (T.pack validInIf) (T.pack validOutIf)))
        ) (\r -> happyReturn (HappyAbsSyn17 r))

happyReduce_19 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_19 = happySpecReduce_1  13# happyReduction_19
happyReduction_19 _
         =  HappyAbsSyn18
                 (TCP
        )

happyReduce_20 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_20 = happySpecReduce_1  13# happyReduction_20
happyReduction_20 _
         =  HappyAbsSyn18
                 (UDP
        )

happyReduce_21 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_21 = happySpecReduce_1  13# happyReduction_21
happyReduction_21 _
         =  HappyAbsSyn18
                 (ANY
        )

happyReduce_22 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_22 = happyReduce 4# 14# happyReduction_22
happyReduction_22 (_ `HappyStk`
        (HappyAbsSyn20  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn19
                 (happy_var_3
        ) `HappyStk` happyRest

happyReduce_23 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_23 = happySpecReduce_0  15# happyReduction_23
happyReduction_23  =  HappyAbsSyn20
                 ([]
        )

happyReduce_24 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_24 = happySpecReduce_2  15# happyReduction_24
happyReduction_24 (HappyAbsSyn20  happy_var_2)
        (HappyAbsSyn21  happy_var_1)
         =  HappyAbsSyn20
                 (happy_var_1 : happy_var_2
        )
happyReduction_24 _ _  = notHappyAtAll 

happyReduce_25 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_25 = happyReduce 5# 16# happyReduction_25
happyReduction_25 (_ `HappyStk`
        (HappyAbsSyn22  happy_var_4) `HappyStk`
        _ `HappyStk`
        (HappyAbsSyn25  happy_var_2) `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn21
                 ((happy_var_2, happy_var_4)
        ) `HappyStk` happyRest

happyReduce_26 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_26 = happySpecReduce_0  17# happyReduction_26
happyReduction_26  =  HappyAbsSyn22
                 ([]
        )

happyReduce_27 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_27 = happySpecReduce_2  17# happyReduction_27
happyReduction_27 (HappyAbsSyn22  happy_var_2)
        (HappyAbsSyn23  happy_var_1)
         =  HappyAbsSyn22
                 (happy_var_1 : happy_var_2
        )
happyReduction_27 _ _  = notHappyAtAll 

happyReduce_28 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_28 = happySpecReduce_2  18# happyReduction_28
happyReduction_28 _
        (HappyAbsSyn26  happy_var_1)
         =  HappyAbsSyn23
                 (happy_var_1
        )
happyReduction_28 _ _  = notHappyAtAll 

happyReduce_29 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_29 = happySpecReduce_1  18# happyReduction_29
happyReduction_29 (HappyAbsSyn24  happy_var_1)
         =  HappyAbsSyn23
                 (happy_var_1
        )
happyReduction_29 _  = notHappyAtAll 

happyReduce_30 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_30 = happyReduce 4# 19# happyReduction_30
happyReduction_30 (_ `HappyStk`
        (HappyAbsSyn27  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest)
         = HappyAbsSyn24
                 (Rule (T.pack "") MatchAny happy_var_3 Nothing
        ) `HappyStk` happyRest

happyReduce_31 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_31 = happySpecReduce_1  20# happyReduction_31
happyReduction_31 _
         =  HappyAbsSyn25
                 (Input
        )

happyReduce_32 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_32 = happySpecReduce_1  20# happyReduction_32
happyReduction_32 _
         =  HappyAbsSyn25
                 (Output
        )

happyReduce_33 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_33 = happySpecReduce_1  20# happyReduction_33
happyReduction_33 _
         =  HappyAbsSyn25
                 (Forward
        )

happyReduce_34 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_34 = happyReduce 4# 21# happyReduction_34
happyReduction_34 ((HappyAbsSyn27  happy_var_4) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        (HappyAbsSyn28  happy_var_1) `HappyStk`
        happyRest)
         = HappyAbsSyn26
                 (Rule (T.pack "") happy_var_1 happy_var_4 Nothing
        ) `HappyStk` happyRest

happyReduce_35 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_35 = happySpecReduce_1  22# happyReduction_35
happyReduction_35 _
         =  HappyAbsSyn27
                 (Accept
        )

happyReduce_36 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_36 = happySpecReduce_1  22# happyReduction_36
happyReduction_36 _
         =  HappyAbsSyn27
                 (Drop
        )

happyReduce_37 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_37 = happySpecReduce_1  22# happyReduction_37
happyReduction_37 _
         =  HappyAbsSyn27
                 (Reject
        )

happyReduce_38 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_38 = happySpecReduce_1  23# happyReduction_38
happyReduction_38 (HappyAbsSyn29  happy_var_1)
         =  HappyAbsSyn28
                 (happy_var_1
        )
happyReduction_38 _  = notHappyAtAll 

happyReduce_39 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_39 = happySpecReduce_2  23# happyReduction_39
happyReduction_39 (HappyAbsSyn29  happy_var_2)
        (HappyAbsSyn28  happy_var_1)
         =  HappyAbsSyn28
                 (AndMatch happy_var_1 happy_var_2
        )
happyReduction_39 _ _  = notHappyAtAll 

happyReduce_40 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_40 = happySpecReduce_3  24# happyReduction_40
happyReduction_40 (HappyAbsSyn31  happy_var_3)
        _
        _
         =  HappyAbsSyn29
                 (conjunctIPMatches happy_var_3 MatchSrcIP
        )
happyReduction_40 _ _ _  = notHappyAtAll 

happyReduce_41 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_41 = happySpecReduce_3  24# happyReduction_41
happyReduction_41 (HappyAbsSyn31  happy_var_3)
        _
        _
         =  HappyAbsSyn29
                 (conjunctIPMatches happy_var_3 MatchDstIP
        )
happyReduction_41 _ _ _  = notHappyAtAll 

happyReduce_42 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_42 = happySpecReduce_3  24# happyReduction_42
happyReduction_42 (HappyAbsSyn18  happy_var_3)
        _
        _
         =  HappyAbsSyn29
                 (MatchProt happy_var_3
        )
happyReduction_42 _ _ _  = notHappyAtAll 

happyReduce_43 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_43 = happyMonadReduce 3# 24# happyReduction_43
happyReduction_43 ((HappyAbsSyn30  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( mapP checkValidIf happy_var_3 `thenP` \vIfs -> 
                                        returnP $ conjunctIfMatches vIfs MatchInIf))
        ) (\r -> happyReturn (HappyAbsSyn29 r))

happyReduce_44 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_44 = happyMonadReduce 3# 24# happyReduction_44
happyReduction_44 ((HappyAbsSyn30  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( mapP checkValidIf happy_var_3 `thenP` \vIfs -> 
                                        returnP $ conjunctIfMatches vIfs MatchOutIf))
        ) (\r -> happyReturn (HappyAbsSyn29 r))

happyReduce_45 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_45 = happySpecReduce_3  24# happyReduction_45
happyReduction_45 (HappyAbsSyn33  happy_var_3)
        _
        _
         =  HappyAbsSyn29
                 (MatchSrcPort happy_var_3
        )
happyReduction_45 _ _ _  = notHappyAtAll 

happyReduce_46 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_46 = happySpecReduce_3  24# happyReduction_46
happyReduction_46 (HappyAbsSyn33  happy_var_3)
        _
        _
         =  HappyAbsSyn29
                 (MatchDstPort happy_var_3
        )
happyReduction_46 _ _ _  = notHappyAtAll 

happyReduce_47 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_47 = happyMonadReduce 3# 24# happyReduction_47
happyReduction_47 ((HappyAbsSyn32  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( checkSubnetList happy_var_3 `thenP` \vranges -> 
                                     returnP $ conjunctIPRangeMatches vranges MatchSrcSubnet))
        ) (\r -> happyReturn (HappyAbsSyn29 r))

happyReduce_48 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_48 = happyMonadReduce 3# 24# happyReduction_48
happyReduction_48 ((HappyAbsSyn32  happy_var_3) `HappyStk`
        _ `HappyStk`
        _ `HappyStk`
        happyRest) tk
         = happyThen ((( checkSubnetList happy_var_3 `thenP` \vranges -> 
                                     returnP $ conjunctIPRangeMatches vranges MatchDstSubnet))
        ) (\r -> happyReturn (HappyAbsSyn29 r))

happyReduce_49 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_49 = happySpecReduce_3  24# happyReduction_49
happyReduction_49 _
        (HappyAbsSyn28  happy_var_2)
        _
         =  HappyAbsSyn29
                 (happy_var_2
        )
happyReduction_49 _ _ _  = notHappyAtAll 

happyReduce_50 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_50 = happySpecReduce_1  25# happyReduction_50
happyReduction_50 (HappyTerminal (TokenString happy_var_1))
         =  HappyAbsSyn30
                 ([happy_var_1]
        )
happyReduction_50 _  = notHappyAtAll 

happyReduce_51 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_51 = happySpecReduce_3  25# happyReduction_51
happyReduction_51 (HappyAbsSyn30  happy_var_3)
        _
        (HappyTerminal (TokenString happy_var_1))
         =  HappyAbsSyn30
                 (happy_var_1 : happy_var_3
        )
happyReduction_51 _ _ _  = notHappyAtAll 

happyReduce_52 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_52 = happySpecReduce_1  26# happyReduction_52
happyReduction_52 (HappyTerminal (TokenIP happy_var_1))
         =  HappyAbsSyn31
                 ([happy_var_1]
        )
happyReduction_52 _  = notHappyAtAll 

happyReduce_53 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_53 = happySpecReduce_3  26# happyReduction_53
happyReduction_53 (HappyAbsSyn31  happy_var_3)
        _
        (HappyTerminal (TokenIP happy_var_1))
         =  HappyAbsSyn31
                 (happy_var_1 : happy_var_3
        )
happyReduction_53 _ _ _  = notHappyAtAll 

happyReduce_54 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_54 = happySpecReduce_3  27# happyReduction_54
happyReduction_54 (HappyTerminal (TokenNumber happy_var_3))
        _
        (HappyTerminal (TokenIP happy_var_1))
         =  HappyAbsSyn32
                 ([(happy_var_1, happy_var_3)]
        )
happyReduction_54 _ _ _  = notHappyAtAll 

happyReduce_55 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_55 = happyReduce 5# 27# happyReduction_55
happyReduction_55 ((HappyAbsSyn32  happy_var_5) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenNumber happy_var_3)) `HappyStk`
        _ `HappyStk`
        (HappyTerminal (TokenIP happy_var_1)) `HappyStk`
        happyRest)
         = HappyAbsSyn32
                 ((happy_var_1, happy_var_3) : happy_var_5
        ) `HappyStk` happyRest

happyReduce_56 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_56 = happyMonadReduce 1# 28# happyReduction_56
happyReduction_56 ((HappyAbsSyn34  happy_var_1) `HappyStk`
        happyRest) tk
         = happyThen ((( mapP checkValidPort happy_var_1 `thenP` \ps -> returnP ps))
        ) (\r -> happyReturn (HappyAbsSyn33 r))

happyReduce_57 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_57 = happySpecReduce_1  29# happyReduction_57
happyReduction_57 (HappyTerminal (TokenNumber happy_var_1))
         =  HappyAbsSyn34
                 ([happy_var_1]
        )
happyReduction_57 _  = notHappyAtAll 

happyReduce_58 :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)
happyReduce_58 = happySpecReduce_3  29# happyReduction_58
happyReduction_58 (HappyAbsSyn34  happy_var_3)
        _
        (HappyTerminal (TokenNumber happy_var_1))
         =  HappyAbsSyn34
                 (happy_var_1 : happy_var_3
        )
happyReduction_58 _ _ _  = notHappyAtAll 

happyTerminalToTok term = case term of {
        TokenEOF -> 52#;
        TokenDevice happy_dollar_dollar -> 2#;
        TokenDeviceMac -> 3#;
        TokenDeviceIP -> 4#;
        TokenDeviceSubnet -> 5#;
        TokenOpenBracket -> 6#;
        TokenCloseBracket -> 7#;
        TokenAssign -> 8#;
        TokenSemicolon -> 9#;
        TokenPackets -> 10#;
        TokenArrow -> 11#;
        TokenColon -> 12#;
        TokenTCP -> 13#;
        TokenUDP -> 14#;
        TokenANY -> 15#;
        TokenComma -> 16#;
        TokenRules -> 17#;
        TokenChain -> 18#;
        TokenInput -> 19#;
        TokenOutput -> 20#;
        TokenForward -> 21#;
        TokenFrom -> 22#;
        TokenTo -> 23#;
        TokenString happy_dollar_dollar -> 24#;
        TokenIdent happy_dollar_dollar -> 25#;
        TokenNumber happy_dollar_dollar -> 26#;
        TokenIP happy_dollar_dollar -> 27#;
        TokenLParen -> 28#;
        TokenRParen -> 29#;
        TokenDash -> 30#;
        TokenSlash -> 31#;
        TokenSrcIP -> 32#;
        TokenDstIP -> 33#;
        TokenProt -> 34#;
        TokenInIf -> 35#;
        TokenOutIf -> 36#;
        TokenSubnets -> 37#;
        TokenRange -> 38#;
        TokenFirewallInterface -> 39#;
        TokenDevices -> 40#;
        TokenFirewallIP -> 41#;
        TokenFirewallMAC -> 42#;
        TokenSrcPort -> 43#;
        TokenDstPort -> 44#;
        TokenSrcSubnet -> 45#;
        TokenDstSubnet -> 46#;
        TokenDo -> 47#;
        TokenDefault -> 48#;
        TokenAccept -> 49#;
        TokenDrop -> 50#;
        TokenReject -> 51#;
        _ -> -1#;
        }
{-# NOINLINE happyTerminalToTok #-}

happyLex kend kmore = lexer (\tk -> case tk of {
        TokenEOF -> kend tk;
        _ -> kmore (happyTerminalToTok tk) tk })
{-# INLINE happyLex #-}

happyNewToken action sts stk = happyLex (\tk -> happyDoAction 52# tk action sts stk) (\i tk -> happyDoAction i tk action sts stk)

happyReport 52# = happyReport'
happyReport _ = happyReport'


happyThen :: () => (P a) -> (a -> (P b)) -> (P b)
happyThen = (thenP)
happyReturn :: () => a -> (P a)
happyReturn = (returnP)
happyDoParse :: () => Happy_GHC_Exts.Int# -> P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)

happyNewToken :: () => Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> (P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _))

happyDoAction :: () => Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> (P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _))

happyReduceArr :: () => Happy_Data_Array.Array Happy_Prelude.Int (Happy_GHC_Exts.Int# -> Token -> Happy_GHC_Exts.Int# -> Happy_IntList -> HappyStk (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _) -> (P (HappyAbsSyn _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _)))

happyThen1 :: () => P a -> (a -> P b) -> P b
happyThen1 = happyThen
happyFmap1 f m = happyThen m (\a -> happyReturn (f a))
happyReturn1 :: () => a -> (P a)
happyReturn1 = happyReturn
happyReport' :: () => (Token) -> [Happy_Prelude.String] -> (P a) -> (P a)
happyReport' = (\tokens expected resume -> happyError)

happyAbort :: () => (P a)
happyAbort = Happy_Prelude.error "Called abort handler in non-resumptive parser"

parseScript = happySomeParser where
 happySomeParser = happyThen (happyDoParse 0#) (\x -> case x of {HappyAbsSyn5 z -> happyReturn z; _other -> notHappyAtAll })

happySeq = happyDontSeq


-- Estructuras intermedias para realizar el parseo de un dispositivo/subred

data SubnetFieldsData = SubnetFieldsData
    { subnetRan :: IPV4.IPv4Range
    , subnetIf :: T.Text
    }

data DeviceFieldsData = DeviceFieldsData
    { macAddr :: T.Text
    , ipAddr :: IPV4.IPv4
    , subnetRef :: T.Text 
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
    | TokenFirewallIP
    | TokenFirewallMAC

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
            "fwmac"      -> TokenFirewallMAC
            "fwip"       -> TokenFirewallIP
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
            "interface"  -> TokenFirewallInterface
            "fwip"       -> TokenFirewallIP
            "fwmac"      -> TokenFirewallMAC
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
checkSubnetList :: [(String, Int)] -> P [IPV4.IPv4Range]
checkSubnetList [] = returnP []
checkSubnetList (t:ts) = readSubnet t `thenP` (\subnet -> checkSubnetList ts `thenP` (\subnets ->
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
       else failP $ "Dirección MAC inválida (" ++ macStr ++ ") \nFormato esperado: ?? : ?? : ?? : ?? : ?? : ?? (donde '?' es un hexadecimal)"

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

-- Dada la lista de subnets y dispositivos parseadas, unificarlas en una lista de dispositivos definitiva, donde
-- los dispositivos tengan la direccion ip que corresponde al identificador de subred especificado, sino tirar error
processRawDevices :: [Subnet] -> [RawDevice] -> P [Device]
processRawDevices subnets rawDevices = mapP (resolveDevice subnets) rawDevices

resolveDevice :: [Subnet] -> RawDevice -> P Device
resolveDevice subnets (RawDevice name mac ip subnetRef isFirewall)
    | isFirewall = do
        if not (IPV4.public ip)
            then failP $ "La IP del dispositivo asociado al firewall debe ser pública. IP provista: " ++ (T.unpack $ IPV4.encode ip)
            else
                -- obtenemos todas las interfaces de las subredes definidas, a eso le agregamos la interfaz por defecto que conecta al enrutador
                do  let subnetIfaces = map subnetInterface subnets
                        fwIfaces = (defaultFwIf : subnetIfaces) 
                        fwRange = IPV4.range ip 24  -- convenimos esta subred para el firewall, pero no se usa
                    returnP $ Device name mac ip fwRange fwIfaces
    | otherwise = do
        case findSubnet subnetRef subnets of
            Just subnet -> returnP $ Device name mac ip (subnetRange subnet) [subnetInterface subnet]
                    
            Nothing -> 
                    -- el unico dispositivo cuyo identificador de subred es "INTERNET" deberia ser el firewall
                    if subnetRef == (T.pack "INTERNET")
                    then failP $ "No se reconoce el dispositivo asociado al firewall o bien un dispositivo tiene 'INTERNET' como subred asignada (fwmac/fwip solo son usadas para el dispositivo 'firewall')"
                    else failP $ "Subred no encontrada (" ++ T.unpack subnetRef ++ ")"

findSubnet :: T.Text -> [Subnet] -> Maybe Subnet
findSubnet _ [] = Nothing
findSubnet name (s:ss) = if (subnetName s) == name then Just s else findSubnet name ss

-- Esta funcion se invoca al ocurrir un error de parseo
happyError :: P a
happyError = \s i -> Failed $ "[Linea " ++ show i ++ "] Error de parseo cerca de ----->" ++ take 10 s ++ "<-----"

-- Funcion a invocar para parsear.
parseFirewall :: String -> ParseResult Info
parseFirewall input = parseScript input 1
-- $Id: GenericTemplate.hs,v 1.26 2005/01/14 14:47:22 simonmar Exp $

#if !defined(__GLASGOW_HASKELL__)
#  error This code isn't being built with GHC.
#endif

-- Get WORDS_BIGENDIAN (if defined)
#include "MachDeps.h"

-- Do not remove this comment. Required to fix CPP parsing when using GCC and a clang-compiled alex.
#define LT(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.<# m)) :: Happy_Prelude.Bool)
#define GTE(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.>=# m)) :: Happy_Prelude.Bool)
#define EQ(n,m) ((Happy_GHC_Exts.tagToEnum# (n Happy_GHC_Exts.==# m)) :: Happy_Prelude.Bool)
#define PLUS(n,m) (n Happy_GHC_Exts.+# m)
#define MINUS(n,m) (n Happy_GHC_Exts.-# m)
#define TIMES(n,m) (n Happy_GHC_Exts.*# m)
#define NEGATE(n) (Happy_GHC_Exts.negateInt# (n))

type Happy_Int = Happy_GHC_Exts.Int#
data Happy_IntList = HappyCons Happy_Int Happy_IntList

#define INVALID_TOK -1#
#define ERROR_TOK 0#
#define CATCH_TOK 1#

#if defined(HAPPY_COERCE)
#  define GET_ERROR_TOKEN(x)  (case Happy_GHC_Exts.unsafeCoerce# x of { (Happy_GHC_Exts.I# i) -> i })
#  define MK_ERROR_TOKEN(i)   (Happy_GHC_Exts.unsafeCoerce# (Happy_GHC_Exts.I# i))
#  define MK_TOKEN(x)         (happyInTok (x))
#else
#  define GET_ERROR_TOKEN(x)  (case x of { HappyErrorToken (Happy_GHC_Exts.I# i) -> i })
#  define MK_ERROR_TOKEN(i)   (HappyErrorToken (Happy_GHC_Exts.I# i))
#  define MK_TOKEN(x)         (HappyTerminal (x))
#endif

#if defined(HAPPY_DEBUG)
#  define DEBUG_TRACE(s)    (happyTrace (s)) Happy_Prelude.$
happyTrace string expr = Happy_System_IO_Unsafe.unsafePerformIO Happy_Prelude.$ do
    Happy_System_IO.hPutStr Happy_System_IO.stderr string
    Happy_Prelude.return expr
#else
#  define DEBUG_TRACE(s)    {- nothing -}
#endif

infixr 9 `HappyStk`
data HappyStk a = HappyStk a (HappyStk a)

-----------------------------------------------------------------------------
-- starting the parse

happyDoParse start_state = happyNewToken start_state notHappyAtAll notHappyAtAll

-----------------------------------------------------------------------------
-- Accepting the parse

-- If the current token is ERROR_TOK, it means we've just accepted a partial
-- parse (a %partial parser).  We must ignore the saved token on the top of
-- the stack in this case.
happyAccept ERROR_TOK tk st sts (_ `HappyStk` ans `HappyStk` _) =
        happyReturn1 ans
happyAccept j tk st sts (HappyStk ans _) =
        (happyTcHack j (happyTcHack st)) (happyReturn1 ans)

-----------------------------------------------------------------------------
-- Arrays only: do the next action

happyDoAction i tk st =
  DEBUG_TRACE("state: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++
              ",\ttoken: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++
              ",\taction: ")
  case happyDecodeAction (happyNextAction i st) of
    HappyFail             -> DEBUG_TRACE("failing.\n")
                             happyFail i tk st
    HappyAccept           -> DEBUG_TRACE("accept.\n")
                             happyAccept i tk st
    HappyReduce rule      -> DEBUG_TRACE("reduce (rule " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# rule) Happy_Prelude.++ ")")
                             (happyReduceArr Happy_Data_Array.! (Happy_GHC_Exts.I# rule)) i tk st
    HappyShift  new_state -> DEBUG_TRACE("shift, enter state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
                             happyShift new_state i tk st

{-# INLINE happyNextAction #-}
happyNextAction i st = case happyIndexActionTable i st of
  Happy_Prelude.Just (Happy_GHC_Exts.I# act) -> act
  Happy_Prelude.Nothing                      -> happyIndexOffAddr happyDefActions st

{-# INLINE happyIndexActionTable #-}
happyIndexActionTable i st
  | GTE(i, 0#), GTE(off, 0#), EQ(happyIndexOffAddr happyCheck off, i)
  -- i >= 0:   Guard against INVALID_TOK (do the default action, which ultimately errors)
  -- off >= 0: Otherwise it's a default action
  -- equality check: Ensure that the entry in the compressed array is owned by st
  = Happy_Prelude.Just (Happy_GHC_Exts.I# (happyIndexOffAddr happyTable off))
  | Happy_Prelude.otherwise
  = Happy_Prelude.Nothing
  where
    off = PLUS(happyIndexOffAddr happyActOffsets st, i)

data HappyAction
  = HappyFail
  | HappyAccept
  | HappyReduce Happy_Int -- rule number
  | HappyShift Happy_Int  -- new state
  deriving Happy_Prelude.Show

{-# INLINE happyDecodeAction #-}
happyDecodeAction :: Happy_Int -> HappyAction
happyDecodeAction  0#                        = HappyFail
happyDecodeAction -1#                        = HappyAccept
happyDecodeAction action | LT(action, 0#)    = HappyReduce NEGATE(PLUS(action, 1#))
                         | Happy_Prelude.otherwise = HappyShift MINUS(action, 1#)

{-# INLINE happyIndexGotoTable #-}
happyIndexGotoTable nt st = happyIndexOffAddr happyTable off
  where
    off = PLUS(happyIndexOffAddr happyGotoOffsets st, nt)

{-# INLINE happyIndexOffAddr #-}
happyIndexOffAddr :: HappyAddr -> Happy_Int -> Happy_Int
happyIndexOffAddr (HappyA# arr) off =
#if __GLASGOW_HASKELL__ >= 901
  Happy_GHC_Exts.int32ToInt# -- qualified import because it doesn't exist on older GHC's
#endif
#ifdef WORDS_BIGENDIAN
  -- The CI of `alex` tests this code path
  (Happy_GHC_Exts.word32ToInt32# (Happy_GHC_Exts.wordToWord32# (Happy_GHC_Exts.byteSwap32# (Happy_GHC_Exts.word32ToWord# (Happy_GHC_Exts.int32ToWord32#
#endif
  (Happy_GHC_Exts.indexInt32OffAddr# arr off)
#ifdef WORDS_BIGENDIAN
  )))))
#endif

happyIndexRuleArr :: Happy_Int -> (# Happy_Int, Happy_Int #)
happyIndexRuleArr r = (# nt, len #)
  where
    !(Happy_GHC_Exts.I# n_starts) = happy_n_starts
    offs = TIMES(MINUS(r,n_starts),2#)
    nt = happyIndexOffAddr happyRuleArr offs
    len = happyIndexOffAddr happyRuleArr PLUS(offs,1#)

data HappyAddr = HappyA# Happy_GHC_Exts.Addr#

-----------------------------------------------------------------------------
-- Shifting a token

happyShift new_state ERROR_TOK tk st sts stk@(x `HappyStk` _) =
     -- See "Error Fixup" below
     let i = GET_ERROR_TOKEN(x) in
     DEBUG_TRACE("shifting the error token")
     happyDoAction i tk new_state (HappyCons st sts) stk

happyShift new_state i tk st sts stk =
     happyNewToken new_state (HappyCons st sts) (MK_TOKEN(tk) `HappyStk` stk)

-- happyReduce is specialised for the common cases.

happySpecReduce_0 nt fn j tk st sts stk
     = happySeq fn (happyGoto nt j tk st (HappyCons st sts) (fn `HappyStk` stk))

happySpecReduce_1 nt fn j tk old_st sts@(HappyCons st _) (v1 `HappyStk` stk')
     = let r = fn v1 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happySpecReduce_2 nt fn j tk old_st
  (HappyCons _ sts@(HappyCons st _))
  (v1 `HappyStk` v2 `HappyStk` stk')
     = let r = fn v1 v2 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happySpecReduce_3 nt fn j tk old_st
  (HappyCons _ (HappyCons _ sts@(HappyCons st _)))
  (v1 `HappyStk` v2 `HappyStk` v3 `HappyStk` stk')
     = let r = fn v1 v2 v3 in
       happyTcHack old_st (happySeq r (happyGoto nt j tk st sts (r `HappyStk` stk')))

happyReduce k nt fn j tk st sts stk
     = case happyDrop MINUS(k,(1# :: Happy_Int)) sts of
         sts1@(HappyCons st1 _) ->
                let r = fn stk in -- it doesn't hurt to always seq here...
                st `happyTcHack` happyDoSeq r (happyGoto nt j tk st1 sts1 r)

happyMonadReduce k nt fn j tk st sts stk =
      case happyDrop k (HappyCons st sts) of
        sts1@(HappyCons st1 _) ->
          let drop_stk = happyDropStk k stk in
          j `happyTcHack` happyThen1 (fn stk tk)
                                     (\r -> happyGoto nt j tk st1 sts1 (r `HappyStk` drop_stk))

happyMonad2Reduce k nt fn j tk st sts stk =
      case happyDrop k (HappyCons st sts) of
        sts1@(HappyCons st1 _) ->
          let drop_stk = happyDropStk k stk
              off = happyIndexOffAddr happyGotoOffsets st1
              off_i = PLUS(off, nt)
              new_state = happyIndexOffAddr happyTable off_i
          in
            j `happyTcHack` happyThen1 (fn stk tk)
                                       (\r -> happyNewToken new_state sts1 (r `HappyStk` drop_stk))

happyDrop 0# l               = l
happyDrop n  (HappyCons _ t) = happyDrop MINUS(n,(1# :: Happy_Int)) t

happyDropStk 0# l                 = l
happyDropStk n  (x `HappyStk` xs) = happyDropStk MINUS(n,(1#::Happy_Int)) xs

-----------------------------------------------------------------------------
-- Moving to a new state after a reduction

happyGoto nt j tk st =
   DEBUG_TRACE(", goto state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
   happyDoAction j tk new_state
  where new_state = happyIndexGotoTable nt st

{- Note [Error recovery]
~~~~~~~~~~~~~~~~~~~~~~~~
When there is no applicable action for the current lookahead token `tk`,
happy enters error recovery mode. Depending on whether the grammar file
declares the two action form `%error { abort } { report }` for
    Resumptive Error Handling,
it works in one (not resumptive) or two phases (resumptive):

 1. Fixup mode:
    Try to see if there is an action for the error token ERROR_TOK. If there
    is, do *not* emit an error and pretend instead that an `error` token was
    inserted.
    When there is no ERROR_TOK action, report an error.

    In non-resumptive error handling, calling the single error handler
    (e.g. `happyError`) will throw an exception and abort the parser.
    However, in resumptive error handling we enter *error resumption mode*.

 2. Error resumption mode:
    After reporting the error (with `report`), happy will attempt to find
    a good state stack to resume parsing in.
    For each candidate stack, it discards input until one of the candidates
    resumes (i.e. shifts the current input).
    If no candidate resumes before the end of input, resumption failed and
    calls the `abort` function, to much the same effect as in non-resumptive
    error handling.

    Candidate stacks are declared by the grammar author using the special
    `catch` terminal and called "catch frames".
    This mechanism is described in detail in Note [happyResume].

The `catch` resumption mechanism (2) is what usually is associated with
`error` in `bison` or `menhir`. Since `error` is used for the Fixup mechanism
(1) above, we call the corresponding token `catch`.
Furthermore, in constrast to `bison`, our implementation of `catch`
non-deterministically considers multiple catch frames on the stack for
resumption (See Note [Multiple catch frames]).

Note [happyResume]
~~~~~~~~~~~~~~~~~~
`happyResume` implements the resumption mechanism from Note [Error recovery].
It is best understood by example. Consider

Exp :: { String }
Exp : '1'                { "1" }
    | catch              { "catch" }
    | Exp '+' Exp %shift { $1 Happy_Prelude.++ " + " Happy_Prelude.++ $3 } -- %shift: associate 1 + 1 + 1 to the right
    | '(' Exp ')'        { "(" Happy_Prelude.++ $2 Happy_Prelude.++ ")" }

The idea of the use of `catch` here is that upon encountering a parse error
during expression parsing, we can gracefully degrade using the `catch` rule,
still producing a partial syntax tree and keep on parsing to find further
syntax errors.

Let's trace the parser state for input 11+1, which will error out after shifting 1.
After shifting, we have the following item stack (growing downwards and omitting
transitive closure items):

  State 0: %start_parseExp -> . Exp
  State 5: Exp -> '1' .

(Stack as a list of state numbers: [5,0].)
As Note [Error recovery] describes, we will first try Fixup mode.
That fails because no production can shift the `error` token.
Next we try Error resumption mode. This works as follows:

  1. Pop off the item stack until we find an item that can shift the `catch`
     token. (Implemented in `pop_items`.)
       * State 5 cannot shift catch. Pop.
       * State 0 can shift catch, which would transition into
          State 4: Exp -> catch .
     So record the *stack* `[4,0]` after doing the shift transition.
     We call this a *catch frame*, where the top is a *catch state*,
     corresponding to an item in which we just shifted a `catch` token.
     There can be multiple such catch stacks, see Note [Multiple catch frames].

  2. Discard tokens from the input until the lookahead can be shifted in one
     of the catch stacks. (Implemented in `discard_input_until_exp` and
     `some_catch_state_shifts`.)
       * We cannot shift the current lookahead '1' in state 4, so we discard
       * We *can* shift the next lookahead '+' in state 4, but only after
         reducing, which pops State 4 and goes to State 3:
           State 3: %start_parseExp -> Exp .
                    Exp -> Exp . '+' Exp
         Here we can shift '+'.
     As you can see, to implement this machinery we need to simulate
     the operation of the LALR automaton, especially reduction
     (`happySimulateReduce`).

Note [Multiple catch frames]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
For fewer spurious error messages, it can be beneficial to trace multiple catch
items. Consider

Exp : '1'
    | catch
    | Exp '+' Exp %shift
    | '(' Exp ')'

Let's trace the parser state for input (;+1, which will error out after shifting (.
After shifting, we have the following item stack (growing downwards):

  State 0: %start_parseExp -> . Exp
  State 6: Exp -> '(' . Exp ')'

Upon error, we want to find items in the stack which can shift a catch token.
Note that both State 0 and State 6 can shift a catch token, transitioning into
  State 4: Exp -> catch .
Hence we record the catch frames `[4,6,0]` and `[4,0]` for possible resumption.

Which catch frame do we pick for resumption?
Note that resuming catch frame `[4,0]` will parse as "catch+1", whereas
resuming the innermost frame `[4,6,0]` corresponds to parsing "(catch+1".
The latter would keep discarding input until the closing ')' is found.
So we will discard + and 1, leading to a spurious syntax error at the end of
input, aborting the parse and never producing a partial syntax tree. Bad!

It is far preferable to resume with catch frame `[4,0]`, where we can resume
successfully on input +, so that is what we do.

In general, we pick the catch frame for resumption that discards the least
amount of input for a successful shift, preferring the topmost such catch frame.
-}

-- happyFail :: Happy_Int -> Token -> Happy_Int -> _
-- This function triggers Note [Error recovery].
-- If the current token is ERROR_TOK, phase (1) has failed and we might try
-- phase (2).
happyFail ERROR_TOK = happyFixupFailed
happyFail i         = happyTryFixup i

-- Enter Error Fixup (see Note [Error recovery]):
-- generate an error token, save the old token and carry on.
-- When a `happyShift` accepts the error token, we will pop off the error token
-- to resume parsing with the current lookahead `i`.
happyTryFixup i tk action sts stk =
  DEBUG_TRACE("entering `error` fixup.\n")
  happyDoAction ERROR_TOK tk action sts (MK_ERROR_TOKEN(i) `HappyStk` stk)
  -- NB: `happyShift` will simply pop the error token and carry on with
  --     `tk`. Hence we don't change `tk` in the call here

-- See Note [Error recovery], phase (2).
-- Enter resumption mode after reporting the error by calling `happyResume`.
happyFixupFailed tk st sts (x `HappyStk` stk) =
  let i = GET_ERROR_TOKEN(x) in
  DEBUG_TRACE("`error` fixup failed.\n")
  let resume   = happyResume i tk st sts stk
      expected = happyExpectedTokens st sts in
  happyReport i tk expected resume

-- happyResume :: Happy_Int -> Token -> Happy_Int -> _
-- See Note [happyResume]
happyResume i tk st sts stk = pop_items [] st sts stk
  where
    !(Happy_GHC_Exts.I# n_starts) = happy_n_starts   -- this is to test whether we have a start token
    !(Happy_GHC_Exts.I# eof_i) = happy_n_terms Happy_Prelude.- 1   -- this is the token number of the EOF token
    happy_list_to_list :: Happy_IntList -> [Happy_Prelude.Int]
    happy_list_to_list (HappyCons st sts)
      | LT(st, n_starts)
      = [(Happy_GHC_Exts.I# st)]
      | Happy_Prelude.otherwise
      = (Happy_GHC_Exts.I# st) : happy_list_to_list sts

    -- See (1) of Note [happyResume]
    pop_items catch_frames st sts stk
      | LT(st, n_starts)
      = DEBUG_TRACE("reached start state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", ")
        if Happy_Prelude.null catch_frames_new
          then DEBUG_TRACE("no resumption.\n")
               happyAbort
          else DEBUG_TRACE("now discard input, trying to anchor in states " Happy_Prelude.++ Happy_Prelude.show (Happy_Prelude.map (happy_list_to_list . Happy_Prelude.fst) (Happy_Prelude.reverse catch_frames_new)) Happy_Prelude.++ ".\n")
               discard_input_until_exp i tk (Happy_Prelude.reverse catch_frames_new)
      | (HappyCons st1 sts1) <- sts, _ `HappyStk` stk1 <- stk
      = pop_items catch_frames_new st1 sts1 stk1
      where
        !catch_frames_new
          | HappyShift new_state <- happyDecodeAction (happyNextAction CATCH_TOK st)
          , DEBUG_TRACE("can shift catch token in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", into state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# new_state) Happy_Prelude.++ "\n")
            Happy_Prelude.null (Happy_Prelude.filter (\(HappyCons _ (HappyCons h _),_) -> EQ(st,h)) catch_frames)
          = (HappyCons new_state (HappyCons st sts), MK_ERROR_TOKEN(i) `HappyStk` stk):catch_frames -- MK_ERROR_TOKEN(i) is just some dummy that should not be accessed by user code
          | Happy_Prelude.otherwise
          = DEBUG_TRACE("already shifted or can't shift catch in " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ "\n")
            catch_frames

    -- See (2) of Note [happyResume]
    discard_input_until_exp i tk catch_frames
      | Happy_Prelude.Just (HappyCons st (HappyCons catch_st sts), catch_frame) <- some_catch_state_shifts i catch_frames
      = DEBUG_TRACE("found expected token in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ " after shifting from " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# catch_st) Happy_Prelude.++ ": " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ "\n")
        happyDoAction i tk st (HappyCons catch_st sts) catch_frame
      | EQ(i,eof_i) -- is i EOF?
      = DEBUG_TRACE("reached EOF, cannot resume. abort parse :(\n")
        happyAbort
      | Happy_Prelude.otherwise
      = DEBUG_TRACE("discard token " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ "\n")
        happyLex (\eof_tk -> discard_input_until_exp eof_i eof_tk catch_frames) -- eof
                 (\i tk   -> discard_input_until_exp i tk catch_frames)         -- not eof

    some_catch_state_shifts _ [] = DEBUG_TRACE("no catch state could shift.\n") Happy_Prelude.Nothing
    some_catch_state_shifts i catch_frames@(((HappyCons st sts),_):_) = try_head i st sts catch_frames
      where
        try_head i st sts catch_frames = -- PRECONDITION: head catch_frames = (HappyCons st sts)
          DEBUG_TRACE("trying token " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ " in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ": ")
          case happyDecodeAction (happyNextAction i st) of
            HappyFail     -> DEBUG_TRACE("fail.\n")   some_catch_state_shifts i (Happy_Prelude.tail catch_frames)
            HappyAccept   -> DEBUG_TRACE("accept.\n") Happy_Prelude.Just (Happy_Prelude.head catch_frames)
            HappyShift _  -> DEBUG_TRACE("shift.\n")  Happy_Prelude.Just (Happy_Prelude.head catch_frames)
            HappyReduce r -> case happySimulateReduce r st sts of
              (HappyCons st1 sts1) -> try_head i st1 sts1 catch_frames

happySimulateReduce r st sts =
  DEBUG_TRACE("simulate reduction of rule " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# r) Happy_Prelude.++ ", ")
  let (# nt, len #) = happyIndexRuleArr r in
  DEBUG_TRACE("nt " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# nt) Happy_Prelude.++ ", len: " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# len) Happy_Prelude.++ ", new_st ")
  let !(sts1@(HappyCons st1 _)) = happyDrop len (HappyCons st sts)
      new_st = happyIndexGotoTable nt st1 in
  DEBUG_TRACE(Happy_Prelude.show (Happy_GHC_Exts.I# new_st) Happy_Prelude.++ ".\n")
  (HappyCons new_st sts1)

happyTokenToString :: Happy_Prelude.Int -> Happy_Prelude.String
happyTokenToString i = happyTokenStrings Happy_Prelude.!! (i Happy_Prelude.- 2) -- 2: errorTok, catchTok

happyExpectedTokens :: Happy_Int -> Happy_IntList -> [Happy_Prelude.String]
-- Upon a parse error, we want to suggest tokens that are expected in that
-- situation. This function computes such tokens.
-- It works by examining the top of the state stack.
-- For every token number that does a shift transition, record that token number.
-- For every token number that does a reduce transition, simulate that reduction
-- on the state state stack and repeat.
-- The recorded token numbers are then formatted with 'happyTokenToString' and
-- returned.
happyExpectedTokens st sts =
  DEBUG_TRACE("constructing expected tokens.\n")
  Happy_Prelude.map happyTokenToString (search_shifts st sts [])
  where
    search_shifts st sts shifts = Happy_Prelude.foldr (add_action st sts) shifts (distinct_actions st)
    add_action st sts (Happy_GHC_Exts.I# i, Happy_GHC_Exts.I# act) shifts =
      DEBUG_TRACE("found action in state " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# st) Happy_Prelude.++ ", input " Happy_Prelude.++ Happy_Prelude.show (Happy_GHC_Exts.I# i) Happy_Prelude.++ ", " Happy_Prelude.++ Happy_Prelude.show (happyDecodeAction act) Happy_Prelude.++ "\n")
      case happyDecodeAction act of
        HappyFail     -> shifts
        HappyAccept   -> shifts -- This would always be %eof or error... Not helpful
        HappyShift _  -> Happy_Prelude.insert (Happy_GHC_Exts.I# i) shifts
        HappyReduce r -> case happySimulateReduce r st sts of
          (HappyCons st1 sts1) -> search_shifts st1 sts1 shifts
    distinct_actions st
      -- The (token number, action) pairs of all actions in the given state
      = ((-1), (Happy_GHC_Exts.I# (happyIndexOffAddr happyDefActions st)))
      : [ (i, act) | i <- [begin_i..happy_n_terms], act <- get_act row_off i ]
      where
        row_off = happyIndexOffAddr happyActOffsets st
        begin_i = 2 -- +2: errorTok,catchTok
    get_act off (Happy_GHC_Exts.I# i) -- happyIndexActionTable with cached row offset
      | let off_i = PLUS(off,i)
      , GTE(off_i,0#)
      , EQ(happyIndexOffAddr happyCheck off_i,i)
      = [(Happy_GHC_Exts.I# (happyIndexOffAddr happyTable off_i))]
      | Happy_Prelude.otherwise
      = []

-- Internal happy errors:

notHappyAtAll :: a
notHappyAtAll = Happy_Prelude.error "Internal Happy parser panic. This is not supposed to happen! Please open a bug report at https://github.com/haskell/happy/issues.\n"

-----------------------------------------------------------------------------
-- Hack to get the typechecker to accept our action functions

happyTcHack :: Happy_Int -> a -> a
happyTcHack x y = y
{-# INLINE happyTcHack #-}

-----------------------------------------------------------------------------
-- Seq-ing.  If the --strict flag is given, then Happy emits
--      happySeq = happyDoSeq
-- otherwise it emits
--      happySeq = happyDontSeq

happyDoSeq, happyDontSeq :: a -> b -> b
happyDoSeq   a b = a `Happy_GHC_Exts.seq` b
happyDontSeq a b = b

-----------------------------------------------------------------------------
-- Don't inline any functions from the template.  GHC has a nasty habit
-- of deciding to inline happyGoto everywhere, which increases the size of
-- the generated parser quite a bit.

{-# NOINLINE happyDoAction #-}
{-# NOINLINE happyTable #-}
{-# NOINLINE happyCheck #-}
{-# NOINLINE happyActOffsets #-}
{-# NOINLINE happyGotoOffsets #-}
{-# NOINLINE happyDefActions #-}

{-# NOINLINE happyShift #-}
{-# NOINLINE happySpecReduce_0 #-}
{-# NOINLINE happySpecReduce_1 #-}
{-# NOINLINE happySpecReduce_2 #-}
{-# NOINLINE happySpecReduce_3 #-}
{-# NOINLINE happyReduce #-}
{-# NOINLINE happyMonadReduce #-}
{-# NOINLINE happyGoto #-}
{-# NOINLINE happyFail #-}

-- end of Happy Template.
