{
module Parse where
import Common
import Data.Maybe
import Data.Char

}

-- generar el .hs (desde el directorio root del proyecto) happy src/Parse.y -o src/Parse.hs

%name parseEmpty
%tokentype { () }
%error { parseError }

%%

-- aca van las reglas de la gramatica
-- regla que no hace nada
Dummy : { () }

{
parseError :: [()] -> a
parseError _ = error "Parse error"
}