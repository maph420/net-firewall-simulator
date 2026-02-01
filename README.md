# net-firewall-simulator

## Introduccion

El proyecto consiste en un **DSL** cuyo objetivo es simular el comportamiento de un firewall de red. Dado un escenario predefinido (red de dispositivos y paquetes que atraviesan el firewall), el lenguaje permite replicar su funcionamiento. Está inspirado en *iptables* de UNIX, y las reglas que permite definir el firewall se asemejan a las de la tabla **filter** de este.
  
## Archivos del simulador

Un archivo del simulador (extensión `.fws`) se divide en cuatro secciones. A continuación se detalla cada una de ellas junto con su sintaxis:

### Sección subnets

Define las subredes que conformarán la red que protegerá el firewall. Así se definen **N** subredes:

```
subnets {
    subnet subnet-1 {
	range = ???.???.???.???/??;
	interface = "???";	
	}

    subnet subnet-2 {
        range = ???.???.???.???/??;
        interface = "???";
    }
    .
    .
    .
    subnet subnet-N {
        range = ???.???.???.???/??;
        interface = "???";
    }
}
```
Donde ```range``` es la dirección IPv4 de la subred correspondiente e ```interface``` es el nombre de la interfaz de red que vincula a la subred con el firewall. Por ejemplo, si la subred es creada mediante un switch, la interfaz será la que una este con el firewall. Ahora bien, nos abstraemos de la existencia de este switch. 

Así se vería el esquema de red una vez definida las subredes:

<a>
  <img src="https://i.postimg.cc/GhnQrpFx/REFF.jpg" alt="REFF.jpg" width="500" height="275" caption="sdfsdf">
</a>


### Sección devices

Define los dispositivos de la red que serán protegidos por el firewall. Asi se definirían N dispositivos en la red, además del firewall:

```
devices {

  device device-name-1 {
  mac = "???";
  ip = ???.???.???.???;
  subnet = ???;
  }
  
  device device-name-2 {
      mac = "???";
      ip = ???.???.???.???;     
      subnet = ???;
  }
  .
  .
  .
  device device-name-N {
      mac = "???";
      ip = ???.???.???.???;     
      subnet = ???;
  }
  
  device firewall {
      fwmac = "???";
      fwip = ???.???.???.???;
  }

}
```
Cada dispositivo definido se describe con:

**``mac:``** debe ir encerrada entre `""`, se trata de una cadena de caracteres identificatoria a una dirección **MAC** válida.

**``ip:``** una dirección **IPv4** válida, debe ser consistente con el rango de direcciones IPv4 de la subred a la cual pertenece.

**``subnet:``** identificador de la subred a la cual pertenece. Por ejemplo si existe una subred llamada ``LAN`` definida en la seccion de subredes, entonces este es un valor válido.


> [!IMPORTANT]
> Para que el programa funcione correctamente, se DEBE definir un dispositivo asociado al firewall, de nombre ``firewall``. Observar que este tiene sus propios campos ``fwmac`` y ``fwip`` análogos al resto de dispositivos. Además no requiere definir interfaces, ya que convenimos que el firewall estará usando todas las interfaces de las subredes definidas, sumado a la interfaz que lo conecta al enrutador para acceder a internet, que asumimos que es **eth3**.


### Sección packets

Define los envíos que se llevarán a cabo durante la simulación, es decir, ¿qué máquina le mando qué petición a qué otra máquina?[^1]. Así se definen **N** paquetes:
```

packets {
packet-1 : ???.???.???.??? -> ???.???.???.??? : ??? ?? -> ?? : from "???" to "???";
packet-2 : ???.???.???.??? -> ???.???.???.??? : ??? ?? -> ?? : from "???" to "???";
.
.
.
packet-N : ???.???.???.??? -> ???.???.???.??? : ??? ?? -> ?? : from "???" to "???";
}

```
Donde los campos corresponden a: 

- La ip de origen
- La ip de destino
- El protocolo a utilizar. Los protocolos pueden ser: tcp, udp o any (los dos anteriores)
- El numero de puerto de origen del paquete. Un natural en el rango `[0, 65535]`. Sirve cuando un nodo pide multiples servicios a otro nodo.
- El numero de puerto de destino del paquete. Un natural en el rango `[0, 65535]`. Sirve para identificar el servicio que el remitente está solicitando. Suele estar relacionado con el protocolo seleccionado.
- Entre `""`, la interfaz por la cual el paquete **llega** al firewall. Si el paquete sale del firewall, se puede ignorar el campo dejandolo vacío (`""`).
- Entre `""`, la interfaz por la cual el paquete **sale** del firewall. Si el paquete es destinado al firewall, se puede ignorar el campo dejandolo vacío (`""`).

> [!NOTE]
> Por fines didácticos del firewall, si un paquete proviene del internet (fuera de la red que protege el firewall), se usará como **interfaz de entrada** la que vincula el firewall con el enrutador, que convenimos que es **eth3**.  La que se suministre en la sintaxis del paquete se ignorará. Lo mismo ocurrirá con paquetes que vayan por fuera de la red: la **interfaz de salida** del firewall se forzará a ser **eth3**.

### Sección rules

Acá es cuando entra en juego el firewall. Definimos en esta sección las cadenas de reglas a seguir por el firewall, discriminando si los paquetes: salen del firewall (**OUTPUT**), son enviadas al firewall (**INPUT**) o bien pasan por el firewall hacia otro destino (**FORWARD**)[^2]. Así se define la sección de reglas:

```
rules {
    chain INPUT {
        // Reglas correspondientes a la cadena INPUT
    }
    chain FORWARD {
        // Reglas correspondientes a la cadena FORWARD
    }
    chain OUTPUT {
        // Reglas correspondientes a la cadena OUTPUT
    }
}
```

El órden de definición de las cadenas es arbitrario, no debe ser necesariamente el mismo que el exhibido. En cuanto a las reglas, cada regla se separa por un semicolon (`;`) y consiste en una sucesión de condiciones separadas por espacios (de la forma `-condicion ...`) terminadas por un `-do ACCION`, que especifica la acción a tomar sobre el paquete. Las acciones tomables sobre un paquete son:

- Aceptarlo (**ACCEPT**)
- Rechazarlo, avisando al remitente (**REJECT**)
- Rechazarlo, descartándolo "silenciosamente" (**DROP**)

> [!NOTE]
> La diferencia entre **DROP** y **REJECT** es simbolica en este simulador (realmente, un **REJECT** le avisa al remitente que hubo un problema, pero acá no se cubre ese comportamiento)

Las condiciones que se pueden imponer para cada regla son:

- `-srcip ???.???.???.???, ...`

- `-dstip ???.???.???.???, ...`

- `-srcsubnet ???.???.???.???/??, ...`

- `-dstsubnet ???.???.???.???/??, ...`

- `-prot` `???`. Donde el protocolo puede ser: ``tcp``, ``udp``, o ``any`` (los dos anteriores).

- `-srcp ??, ...` Especifica el/los puertos del nodo origen que emitió el paquete. Basta con que coincida con al menos un puerto para matchear. Los valores son números naturales en el rango `[0, 65535]`.

- `-dstp ??, ...` Especifica el/los puertos a los cuales el emisor del paquete quiere acceder. Basta con que coincida con al menos un puerto para matchear. Los valores son números naturales en el rango `[0, 65535]`.

- `-inif "???", ..."` Especifica la/las interfaces por las cuales el paquete entrará al firewall. Basta con que coincida al menos una interfaz para matchear. Sólo es compatible con las cadenas: `INPUT` y `FORWARD`. Los valores son cadenas de caracteres (las interfaces deben ir encerradas entre `""`).

- `-outif "???", ..."` Especifica la/las interfaces por las cuales el paquete sale, desde el nodo remitente. Basta con que coincida al menos una interfaz para matchear. Sólo es compatible con las cadenas: `OUTPUT` y `FORWARD`. Los valores son cadenas de caracteres (las interfaces deben ir encerradas entre `""`).

Adicionalmente, se agrega a la semántica la posibilidad de especificar una política por defecto (**default policy**). Esto es, ¿qué acción tomar si el paquete que pasa no coincide con ninguna de las reglas definidas?

Al final de cada definición de una `chain`, opcionalmente se puede terminar con:

`-default ACCION;`

> [!NOTE]
> Al igual que en **iptables**, el órden de definición de las reglas es importante.
> Se evaluarán en el mismo orden en el que fueron definidas, según la chain a la que pertenezcan (`INPUT`, `OUTPUT` o `FORWARD`).

### Comentarios

Se pueden realizar **comentarios de línea** usando doble barra (`//`).

```
// Esto es un comentario, no se interpretará como código.
```


### Ejemplo

Para aclarar todo lo antes mencionado, mostramos un ejemplo de archivo en `test.fws`:

```
// test.fws

subnets {
	
	subnet LAN {
		range = 192.168.1.0/24;
		interface = "wlan1";	
	}

    subnet DMZ {
        range = 181.16.1.16/28;
        interface = "ppp0";
    }

}

devices {

	device pc-A {
		mac = "AA:BB:CC:DD:EE:FF";
        ip = 192.168.1.10;
		subnet = LAN;
	}

    device pc-B {
		mac = "AA:BB:CC:DA:DA:FF";
        ip = 192.168.1.15;
		subnet = LAN;
	}

	device servidor-web {
		mac = "AA:BB:CC:DD:CA:fe";
        ip = 181.16.1.19;
		subnet = DMZ;
	}

    device web-backup {
		mac = "AA:BB:CC:DD:CA:EE";
        ip = 181.16.1.20;
		subnet = DMZ;
	}

	device firewall {
        fwmac = "00:22:CA:FE:CA:FE";
        fwip = 200.1.0.0;         
    }
	
}

packets {
    p1 : 192.168.1.10 -> 200.1.0.0 : tcp 57890 -> 22: from "wlan1" to "";           // ssh request lan->firewall
    p2 : 192.168.1.10 -> 181.16.1.19 : tcp 12121 -> 80 : from "wlan1" to "ppp0";    // http request lan->dmz
    p3 : 200.1.0.0 -> 8.8.8.8 : udp 22222 -> 53 : from "" to "eth1";                // dns request firewall->internet (google)
    p4 : 181.16.1.19 -> 192.168.1.15 : udp 6800 -> 22 : from "ppp0" to "wlan1";    // ssh request DMZ->LAN
}

rules {
    chain INPUT {
        -srcip 192.168.1.10 -do ACCEPT;
        -dstip 10.0.0.1 -dstp 80 -do DROP;
        -srcsubnet 181.16.1.16/28 -do REJECT;
    }
    chain FORWARD {
        -prot tcp -dstp 80,443 -do ACCEPT;
        -prot udp -dstp 53 -do ACCEPT;
        -default DROP;
    }
    chain OUTPUT {
        -dstip 8.8.8.8 -do REJECT;
        -default ACCEPT;
    }
}

```
> [!TIP]
> Lo unico que debería ser tratado como una cadena de caracteres (es decir, encerrado entre `""`) son las direcciones MAC y las interfaces de red.

El esquema de red definido en el ejemplo se vería así:

<a>
  <img src="https://i.postimg.cc/2SwT0fBh/esquema-test2.png" alt="REFF.jpg" width="500" height="275" >
</a>

## Instalación

El proyecto corre sobre **stack**, una herramienta que permite gestionar proyectos en **Haskell**.

Para conseguirla en debian/ubuntu:

> sudo apt-get install stack

También se puede optar por instalarla manualmente mediante un script:

> curl -sSL https://get.haskellstack.org/ | sh

Una vez instalado, navegar hasta el directorio del proyecto (`net-firewall-simulator`) y ejecutar el comando:

> stack setup

Que se encargará de descargar e instalar la versión correcta de GHC. Este se debería tener que ejecutar una única vez.

Para compilar el proyecto, basta con y correr:

> stack build

El cual además empezará a instalar todas las dependencias que fueran necesarias (puede tardar un rato)

Luego, para correr el programa:

> stack run

[^1]: Lo interesante será cuando dos nodos de subredes distintas se comuniquen. Convenimos que el firewall acepta automáticamente los paquetes de tráfico local (un firewall no simulado, directamente ni vería los paquetes porque no pasan por él) y también acepta tráfico remoto (tampoco pasa por él).

[^2]: Para más información, consultar el man page de iptables (`man iptables`) o [iptables-tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#INPUTCHAIN)
