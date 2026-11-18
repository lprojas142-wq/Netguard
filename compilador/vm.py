# -*- coding: utf-8 -*-
"""
vm.py - Máquina virtual (intérprete) de NetGuard (documento, sección 14).

Ejecuta la lista de cuádruplas sobre el archivo de registro (.log).
La memoria se organiza por direcciones virtuales (sección 11.1):
  1000 globales · 2000 locales · 3000 temporales · 4000 constantes · 5000 colecciones

Formato del .log (sección 14.3): un evento por línea con 6 campos separados
por comas, en este orden:
  sourceIP,eventType,port,failedAttempts,trafficMB,status
Las líneas vacías, las que empiezan con # y el encabezado se ignoran.
"""
import ipaddress
import os

from .errors import ErrorNetGuard
from .symtable import CAMPOS_EVENT

ORDEN_CAMPOS = sorted(CAMPOS_EVENT, key=lambda c: CAMPOS_EVENT[c][0])
LIMITE_PASOS = 10_000_000


def evaluar(op, a, b=None):
    """Semántica de los operadores (también la usa el optimizador)."""
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op == '/':
        if b == 0:
            raise ErrorNetGuard('R03', None, 'división entre cero')
        return a / b
    if op == 'NEG':
        return -a
    if op == '<':
        return a < b
    if op == '<=':
        return a <= b
    if op == '>':
        return a > b
    if op == '>=':
        return a >= b
    if op == '==':
        return a == b
    if op == '!=':
        return a != b
    if op == 'AND':
        return bool(a and b)
    if op == 'OR':
        return bool(a or b)
    if op == 'NOT':
        return not a
    raise ValueError(f'operador desconocido {op}')


def leer_registro(ruta, manejador):
    """Lee el archivo .log y devuelve la lista de eventos (diccionarios)."""
    eventos = []
    with open(ruta, encoding='utf-8-sig') as f:
        for num, linea in enumerate(f, 1):
            texto = linea.strip()
            if not texto or texto.startswith('#'):
                continue
            partes = [x.strip() for x in texto.split(',')]
            if partes[0] == 'sourceIP':
                continue                       # encabezado
            if len(partes) != 6:
                manejador.advertencia('R02', num, f'{os.path.basename(ruta)}: se esperaban 6 campos y hay '
                                                  f'{len(partes)}; se ignora la línea')
                continue
            ip, tipo, puerto, intentos, trafico, estado = partes
            problema = None
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                problema = f"sourceIP '{ip}' no es una IPv4 válida"
            for campo, texto, conv in (('port', puerto, int), ('failedAttempts', intentos, int),
                                       ('trafficMB', trafico, float)):
                if problema is None:
                    try:
                        conv(texto)
                    except ValueError:
                        problema = f"{campo} '{texto}' no es {'entero' if conv is int else 'número'}"
            if problema:
                manejador.advertencia('R02', num, f'{os.path.basename(ruta)}: {problema}; se ignora la línea')
                continue
            ev = {'sourceIP': ip, 'eventType': tipo, 'port': int(puerto),
                  'failedAttempts': int(intentos), 'trafficMB': float(trafico), 'status': estado}
            ev['_linea'] = num
            eventos.append(ev)
    return eventos


class MaquinaVirtual:
    def __init__(self, cuadruplos, manejador, base_dir='.', registro=None, salida=print):
        self.q = cuadruplos
        self.err = manejador
        self.base_dir = base_dir
        self.registro = registro        # si se indica, sustituye al archivo de los LOAD
        self.salida = salida
        self.mem = {}
        self.indices = {}
        self.lineas = []                # lo que va al reporte
        self.alertas = 0
        self.marcados = 0
        self.eventos = 0
        self.ejecutados = 0
        self.archivos = []

    # ---------------- memoria ----------------
    def valor(self, o):
        if o.clase == 'const':
            return o.valor
        if o.clase == 'campo':
            return self.mem[o.simbolo.dir][o.campo]
        return self.mem[o.dir]

    def guardar(self, o, v):
        if o.tipo == 'float' and isinstance(v, int) and not isinstance(v, bool):
            v = float(v)                 # promoción int -> float
        self.mem[o.dir] = v

    def emitir(self, texto):
        self.lineas.append(texto)
        self.salida(texto)

    def ruta_registro(self, nombre, linea):
        if self.registro:
            candidatos = [self.registro]
        elif os.path.isabs(nombre):
            candidatos = [nombre]
        else:
            candidatos = [os.path.join(self.base_dir, nombre), nombre]
        for c in candidatos:
            if os.path.isfile(c):
                return c
        raise ErrorNetGuard('R01', linea, f'no se encontró el archivo de registro "{candidatos[0]}"')

    # ---------------- ciclo de ejecución ----------------
    def ejecutar(self):
        pc = 1
        while 1 <= pc <= len(self.q):
            c = self.q[pc - 1]
            self.ejecutados += 1
            if self.ejecutados > LIMITE_PASOS:
                raise ErrorNetGuard('R03', c.linea, 'se excedió el límite de pasos de ejecución')
            op = c.op
            sig = pc + 1
            try:
                if op == 'END':
                    break
                elif op == '=':
                    self.guardar(c.res, self.valor(c.a1))
                elif op in ('NEG', 'NOT'):
                    self.guardar(c.res, evaluar(op, self.valor(c.a1)))
                elif op in ('+', '-', '*', '/', '<', '<=', '>', '>=', '==', '!=', 'AND', 'OR'):
                    self.guardar(c.res, evaluar(op, self.valor(c.a1), self.valor(c.a2)))
                elif op == 'GOTO':
                    sig = c.res
                elif op == 'GOTOF':
                    if not self.valor(c.a1):
                        sig = c.res
                elif op == 'LOAD':
                    ruta = self.ruta_registro(c.a1.valor, c.linea)
                    evs = leer_registro(ruta, self.err)
                    self.mem[c.res.dir] = evs
                    self.eventos += len(evs)
                    self.archivos.append(ruta)
                elif op == 'FE_INIT':
                    self.indices[c.a1.dir] = 0
                elif op == 'FE_NEXT':
                    lista = self.mem[c.a1.dir]
                    i = self.indices.get(c.a1.dir, 0)
                    if i < len(lista):
                        self.mem[c.a2.dir] = lista[i]
                        self.indices[c.a1.dir] = i + 1
                        self.mem[c.res.dir] = True
                    else:
                        self.mem[c.res.dir] = False
                elif op == 'ALERT':
                    self.alertas += 1
                    self.emitir(f'[ALERTA]  {self.valor(c.a1)} - origen {self.valor(c.a2)}')
                elif op == 'MARK':
                    ev = self.valor(c.a1)
                    ev['status'] = self.valor(c.a2)
                    self.marcados += 1
                    self.emitir(f"[MARCADO] {ev['sourceIP']} -> {ev['status']}")
                else:
                    raise ValueError(f'operador desconocido {op}')
            except ErrorNetGuard as e:
                if e.linea is None:
                    e.linea = c.linea
                raise
            pc = sig
        resumen = f'Eventos analizados: {self.eventos} | Alertas: {self.alertas} | Marcados: {self.marcados}'
        self.emitir(resumen)
        return self.lineas
