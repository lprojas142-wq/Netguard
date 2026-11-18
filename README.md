# NetGuard

Lenguaje de dominio específico para detectar comportamientos sospechosos en registros de red.
Proyecto Integrador · Lenguajes y Autómatas II · Instituto Tecnológico de Oaxaca.

Compilador-intérprete en Python 3 con PLY (LALR(1)): léxico → sintáctico → semántico →
cuádruplas → optimizador → máquina virtual.

## Uso rápido

```
python pruebas.py                                   # 41 pruebas contra el documento
python netguard.py ejemplos/reglas.ng               # compila, optimiza y ejecuta
python netguard.py ejemplos/reglas.ng --todo        # muestra todas las fases
python netguard.py ejemplos/reglas.ng --presentacion
```

No hace falta instalar nada además de Python 3.8+: PLY 3.11 viene en `ply/`.
Instrucciones completas en **GUIA_PASO_A_PASO.txt**.

## Ejemplo de programa

```
LIMIT maxAttempts : int = 5
LIMIT trafficLimit : float = 500.0
LOAD EVENTS FROM "red_laboratorio.log" AS traffic
FOR EACH event IN traffic
    IF event.failedAttempts >= maxAttempts OR event.trafficMB > trafficLimit
        ALERT "Evento sospechoso" FROM event.sourceIP
    ELSE
        MARK event AS "normal"
    END
END
```

PLY (c) David M. Beazley, licencia BSD (ver encabezado de ply/lex.py).
