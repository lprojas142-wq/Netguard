# -*- coding: utf-8 -*-
"""
codegen.py - Generador de código intermedio (documento, sección 12).

Produce CUÁDRUPLAS (operador, arg1, arg2, resultado) numeradas desde 1.
En GOTO y GOTOF el campo resultado es el número de cuádruplo destino; mientras
no se conoce se guarda como None ("?") y se rellena después (backpatching)
con ayuda de la pila de saltos.

También convierte la lista de cuádruplas a TRIPLETAS para compararlas
(sección 12.4).
"""

SALTOS = ('GOTO', 'GOTOF')


class Cuadruplo:
    def __init__(self, op, a1=None, a2=None, res=None, linea=None):
        self.op = op
        self.a1 = a1
        self.a2 = a2
        self.res = res          # Operando, número de destino (saltos) o None
        self.linea = linea

    def es_salto(self):
        return self.op in SALTOS

    def args(self):
        return [a for a in (self.a1, self.a2) if a is not None and not isinstance(a, int)]

    def textos(self, direcciones=False):
        def t(x):
            if x is None:
                return '—'
            if isinstance(x, int):
                return str(x)
            if direcciones and getattr(x, 'dir', None) is not None and x.clase != 'campo':
                return f'{x.nombre}@{x.dir}'
            if direcciones and x.clase == 'campo':
                return f'{x.nombre}@{x.simbolo.dir}+{x.desplazamiento}'
            return str(x)
        res = self.res
        if self.es_salto():
            res = '?' if res is None else str(res)
            return [self.op, t(self.a1), t(self.a2), res]
        return [self.op, t(self.a1), t(self.a2), t(res)]

    def __str__(self):
        return '(' + ', '.join(self.textos()) + ')'


class GeneradorCodigo:
    def __init__(self):
        self.cuadruplos = []

    def siguiente(self):
        """Número que tendrá el próximo cuádruplo."""
        return len(self.cuadruplos) + 1

    def generar(self, op, a1=None, a2=None, res=None, linea=None):
        q = Cuadruplo(op, a1, a2, res, linea)
        self.cuadruplos.append(q)
        return len(self.cuadruplos)          # número del cuádruplo generado

    def rellenar(self, numero, destino):
        """Backpatching: pone el destino de un salto pendiente."""
        self.cuadruplos[numero - 1].res = destino

    def get(self, numero):
        return self.cuadruplos[numero - 1]


def a_tripletas(cuadruplos):
    """Convierte cuádruplas a tripletas (operador, arg1, arg2).

    - Un temporal se reemplaza por (n), el número de la tripleta que lo calculó.
    - La asignación queda (=, destino, valor) y LOAD (LOAD, colección, archivo).
    - Los destinos de salto se escriben entre paréntesis.
    """
    definido_en = {}
    for i, q in enumerate(cuadruplos, 1):
        if q.res is not None and not isinstance(q.res, int) and q.res.clase == 'temp':
            definido_en[q.res.dir] = i

    def ref(x):
        if x is None:
            return '—'
        if x.clase == 'temp' and x.dir in definido_en:
            return f'({definido_en[x.dir]})'
        return str(x)

    trip = []
    for q in cuadruplos:
        if q.op == '=':
            trip.append(['=', str(q.res), ref(q.a1)])
        elif q.op == 'LOAD':
            trip.append(['LOAD', str(q.res), str(q.a1)])
        elif q.op == 'GOTOF':
            trip.append(['GOTOF', ref(q.a1), f'({q.res})'])
        elif q.op == 'GOTO':
            trip.append(['GOTO', f'({q.res})', '—'])
        else:
            trip.append([q.op, ref(q.a1), ref(q.a2)])
    return trip
