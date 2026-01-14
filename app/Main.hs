-- a module serves the purpose of controlling namespaces and creating datatypes, functions, classes, use imports
-- Convention: module names capitalized, function names lowercased
module Main (main) where

import Lib

-- what you want ur program to do (entry point of the whole application)
main :: IO ()
main = someFunc
