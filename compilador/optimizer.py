# -*- coding: utf-8 -*-
"""
optimizer.py - Optimizador de cuádruplas de NetGuard (documento, sección 13).

Técnicas implementadas:
  Locales  : plegado de constantes, propagación de constantes, simplificación
             algebraica, reducción de fuerza, subexpresiones comunes.
  Globales : eliminación de código muerto.
  Ciclos   : movimiento de código invariante fuera del FOR EACH.
  Mirilla  : salto a salto, salto al siguiente, código inalcanzable.

Las pasadas se repiten hasta que ya no cambia nada. Al final se renumeran
los cuádruplos y se corrigen los destinos de los saltos. Cada cambio se anota
en una bitácora que usa la numeración ORIGINAL para poder compararla con el
listado sin optimizar.
"""
import copy

from .codegen import Cuadruplo
from .symtable import Operando
from .vm import evaluar
from .errors import ErrorNetGuard

PUROS = ('+', '-', '*', '/', 'NEG', '<', '<=', '>', '>=', '==', '!=', 'AND', 'OR', 'NOT')
CONMUTATIVOS = ('+', '*', '==', '!=', 'AND', 'OR')


class Optimizador:
    def __init__(self, cuadruplos, tabla):
        self.tabla = tabla
        self.bitacora = []          # (técnica, descripción)
        self.q = []
        for i, original in enumerate(cuadruplos, 1):
            c = copy.copy(original)
            c.orig = i
            self.q.append(c)
        # Los destinos de salto pasan de número a referencia al cuádruplo
        for c in self.q:
            if c.es_salto():
                c.res = self.q[c.res - 1]

    # ------------------------------------------------------------ utilidades
    def anotar(self, tecnica, texto):
        self.bitacora.append((tecnica, texto))

    @staticmethod
    def txt(c):
        """Texto de un cuádruplo con la numeración original."""
        partes = []
        for x in (c.a1, c.a2, c.res):
            if x is None:
                partes.append('—')
            elif isinstance(x, Cuadruplo):
                partes.append(str(x.orig))
            else:
                partes.append(str(x))
        return f'{c.orig} ({c.op}, ' + ', '.join(partes) + ')'

    def siguiente_de(self, c):
        i = self.q.index(c)
        return self.q[i + 1] if i + 1 < len(self.q) else None

    def quitar(self, c):
        """Elimina un cuádruplo; los saltos que llegaban a él pasan al siguiente."""
        sig = self.siguiente_de(c)
        for x in self.q:
            if x.es_salto() and x.res is c:
                x.res = sig
        self.q.remove(c)

    def reemplazar_usos(self, viejo, nuevo):
        clave = viejo.clave()
        usados = []
        for c in self.q:
            for campo in ('a1', 'a2'):
                v = getattr(c, campo)
                if isinstance(v, Operando) and v.clave() == clave:
                    setattr(c, campo, nuevo)
                    usados.append(c.orig)
        return usados

    def constante(self, valor, tipo):
        base = self.tabla.constante(valor, tipo)
        return Operando('const', base.nombre, base.tipo, base.dir, valor=base.valor)

    # ------------------------------------------------------------ pasadas locales
    def plegado(self):
        cambio = False
        for c in list(self.q):
            if c.op in PUROS and all(a.es_const() for a in c.args()) and c.args():
                if c.op == '/' and c.a2.valor == 0:
                    continue
                v = evaluar(c.op, c.a1.valor, c.a2.valor if c.a2 is not None else None)
                k = self.constante(v, c.res.tipo)
                self.anotar('Plegado de constantes', f'{self.txt(c)} se calcula al compilar: {c.res} = {k}')
                self.reemplazar_usos(c.res, k)
                self.quitar(c)
                cambio = True
            elif c.op == 'GOTOF' and c.a1.es_const():
                if c.a1.valor:
                    self.anotar('Plegado de constantes', f'{self.txt(c)}: la condición siempre es verdadera, se quita el salto')
                    self.quitar(c)
                else:
                    self.anotar('Plegado de constantes', f'{self.txt(c)}: la condición siempre es falsa, se cambia por GOTO')
                    c.op, c.a1 = 'GOTO', None
                cambio = True
        return cambio

    def propagacion(self):
        cambio = False
        asignaciones = {}
        for c in self.q:
            if c.op == '=' and c.res.clase == 'var':
                asignaciones.setdefault(c.res.clave(), []).append(c)
        for lista in asignaciones.values():
            if len(lista) != 1:
                continue
            c = lista[0]
            if not c.a1.es_const():
                continue
            usados = self.reemplazar_usos(c.res, c.a1)
            if usados:
                motivo = ('un LIMIT no se puede reasignar' if c.res.simbolo.categoria == 'Global'
                          else 'la variable solo se asigna una vez')
                self.anotar('Propagación de constantes',
                            f"{c.res} → {c.a1} en el cuádruplo {', '.join(map(str, usados))} ({motivo})")
                cambio = True
        return cambio

    def algebraica(self):
        cambio = False
        definido = {c.res.clave(): c for c in self.q
                    if c.op in PUROS and isinstance(c.res, Operando)}

        def es(x, v):
            return x is not None and x.es_const() and x.tipo in ('int', 'float') and x.valor == v

        for c in list(self.q):
            if c.op not in PUROS:
                continue
            nuevo = None
            if c.op == '+' and es(c.a2, 0):
                nuevo = c.a1
            elif c.op == '+' and es(c.a1, 0):
                nuevo = c.a2
            elif c.op == '-' and es(c.a2, 0):
                nuevo = c.a1
            elif c.op == '*' and es(c.a2, 1):
                nuevo = c.a1
            elif c.op == '*' and es(c.a1, 1):
                nuevo = c.a2
            elif c.op == '*' and (es(c.a1, 0) or es(c.a2, 0)):
                nuevo = self.constante(0, c.res.tipo)
            elif c.op == 'NOT' and c.a1.clase == 'temp':
                d = definido.get(c.a1.clave())
                if d is not None and d.op == 'NOT':
                    nuevo = d.a1
            elif c.op == 'AND' and c.a2 is not None and c.a2.es_const() and c.a2.valor is True:
                nuevo = c.a1
            elif c.op == 'OR' and c.a2 is not None and c.a2.es_const() and c.a2.valor is False:
                nuevo = c.a1
            if nuevo is not None and nuevo.tipo == c.res.tipo:
                self.anotar('Simplificación algebraica', f'{self.txt(c)}: {c.res} se reemplaza por {nuevo}')
                self.reemplazar_usos(c.res, nuevo)
                self.quitar(c)
                cambio = True
        return cambio

    def reduccion_fuerza(self):
        for c in self.q:
            if c.op == '*' and c.a2 is not None and c.a2.es_const() and c.a2.tipo == 'int' and c.a2.valor == 2 \
                    and not c.a1.es_const():
                antes = self.txt(c)
                c.op, c.a2 = '+', c.a1
                self.anotar('Reducción de fuerza', f'{antes} → (+, {c.a1}, {c.a1}, {c.res})')
            elif c.op == '*' and c.a1 is not None and c.a1.es_const() and c.a1.tipo == 'int' and c.a1.valor == 2 \
                    and not c.a2.es_const():
                antes = self.txt(c)
                c.op, c.a1 = '+', c.a2
                self.anotar('Reducción de fuerza', f'{antes} → (+, {c.a2}, {c.a2}, {c.res})')
            elif c.op == '/' and c.a2.es_const() and c.a2.valor not in (0, 0.0) and c.a1.tipo == 'float' \
                    and not c.a1.es_const():
                antes = self.txt(c)
                inverso = self.constante(1 / c.a2.valor, 'float')
                c.op, c.a2 = '*', inverso
                self.anotar('Reducción de fuerza', f'{antes} → (*, {c.a1}, {inverso}, {c.res})')

    # ------------------------------------------------------------ bloques básicos
    def lideres(self):
        lid = set()
        if self.q:
            lid.add(id(self.q[0]))
        for i, c in enumerate(self.q):
            if c.es_salto():
                if c.res is not None:
                    lid.add(id(c.res))
                if i + 1 < len(self.q):
                    lid.add(id(self.q[i + 1]))
        return lid

    def subexpresiones(self):
        cambio = False
        lid = self.lideres()
        disponibles = {}
        for c in list(self.q):
            if id(c) in lid:
                disponibles = {}
            if c.op in PUROS:
                args = [a.clave() for a in c.args()]
                if c.op in CONMUTATIVOS:
                    args = sorted(args, key=repr)
                k = (c.op, tuple(args))
                if k in disponibles:
                    previo = disponibles[k]
                    self.anotar('Subexpresiones comunes',
                                f'{self.txt(c)} repite un cálculo: se usa {previo} y se borra')
                    self.reemplazar_usos(c.res, previo)
                    self.quitar(c)
                    cambio = True
                    continue
                disponibles[k] = c.res
            # Lo que cambia un valor invalida las expresiones que lo usan
            muertos = set()
            if c.op == '=' and isinstance(c.res, Operando):
                muertos.add(c.res.clave())
            if c.op in ('MARK', 'FE_NEXT'):
                ev = c.a1 if c.op == 'MARK' else c.a2
                disponibles = {k: v for k, v in disponibles.items()
                               if not any(a[0] == 'campo' and a[1] == ev.dir for a in k[1])}
            if muertos:
                disponibles = {k: v for k, v in disponibles.items() if not (set(k[1]) & muertos)}
        return cambio

    # ------------------------------------------------------------ globales
    def codigo_muerto(self):
        cambio = False
        while True:
            usados = set()
            for c in self.q:
                for a in c.args():
                    usados.add(a.clave())
            borrar = []
            for c in self.q:
                if c.op == '=' and c.res.clase == 'var' and c.res.simbolo.categoria in ('Global', 'Local') \
                        and c.res.clave() not in usados:
                    borrar.append((c, f'{c.res} se asigna pero nunca se lee'))
                elif c.op in PUROS and c.res.clase == 'temp' and c.res.clave() not in usados:
                    borrar.append((c, f'{c.res} se calcula pero nunca se usa'))
            if not borrar:
                return cambio
            for c, motivo in borrar:
                self.anotar('Eliminación de código muerto', f'{self.txt(c)}: {motivo}')
                self.quitar(c)
            cambio = True

    # ------------------------------------------------------------ ciclos
    def invariantes(self):
        for ini in [c for c in self.q if c.op == 'FE_INIT']:
            i = self.q.index(ini)
            if i + 2 >= len(self.q):
                continue
            nxt, gotof = self.q[i + 1], self.q[i + 2]
            if nxt.op != 'FE_NEXT' or gotof.op != 'GOTOF':
                continue
            regreso = [c for c in self.q if c.op == 'GOTO' and c.res is nxt]
            if not regreso:
                continue
            fin = max(self.q.index(r) for r in regreso)
            cuerpo = self.q[i + 3:fin]
            asignadas = {c.res.clave() for c in cuerpo if c.op == '=' and isinstance(c.res, Operando)}
            vars_ciclo = {nxt.a2.clave()} | {c.a2.clave() for c in cuerpo if c.op == 'FE_NEXT'}
            invariantes = set()
            mover = []
            for c in cuerpo:
                if c.op not in PUROS:
                    continue

                def inv(a):
                    if a.es_const():
                        return True
                    if a.clase == 'temp':
                        return a.clave() in invariantes
                    if a.clase == 'var':
                        return a.clave() not in asignadas and a.clave() not in vars_ciclo
                    return False
                if not all(inv(a) for a in c.args()):
                    continue
                if c.op == '/' and not (c.a2.es_const() and c.a2.valor != 0):
                    continue
                invariantes.add(c.res.clave())
                mover.append(c)
            pos = self.q.index(ini)
            for c in mover:
                self.anotar('Movimiento de código invariante',
                            f'{self.txt(c)} no cambia dentro del FOR EACH: se mueve antes de FE_INIT')
                self.quitar(c)
                self.q.insert(pos, c)
                pos += 1

    # ------------------------------------------------------------ mirilla
    def saltos(self):
        cambio = False
        for c in list(self.q):
            if not c.es_salto() or c.res is None:
                continue
            destino, vistos = c.res, set()
            while destino is not None and destino.op == 'GOTO' and id(destino) not in vistos and destino is not c:
                vistos.add(id(destino))
                destino = destino.res
            if destino is not c.res:
                self.anotar('Salto a salto', f'{self.txt(c)} llega a otro GOTO: ahora salta directo a {destino.orig}')
                c.res = destino
                cambio = True
            if c.op == 'GOTO' and c.res is self.siguiente_de(c):
                self.anotar('Salto al siguiente', f'{self.txt(c)} salta a la instrucción siguiente: se elimina')
                self.quitar(c)
                cambio = True
        return cambio

    def inalcanzable(self):
        if not self.q:
            return False
        visitados, pendientes = set(), [self.q[0]]
        while pendientes:
            c = pendientes.pop()
            if id(c) in visitados or c is None:
                continue
            visitados.add(id(c))
            if c.op == 'END':
                continue
            if c.op == 'GOTO':
                pendientes.append(c.res)
                continue
            if c.op == 'GOTOF':
                pendientes.append(c.res)
            sig = self.siguiente_de(c)
            if sig is not None:
                pendientes.append(sig)
        muertos = [c for c in self.q if id(c) not in visitados]
        for c in muertos:
            self.anotar('Código inalcanzable', f'{self.txt(c)} nunca se ejecuta: se elimina')
            self.quitar(c)
        return bool(muertos)

    # ------------------------------------------------------------ orden general
    def limpieza(self):
        for _ in range(50):
            cambio = False
            cambio |= self.plegado()
            cambio |= self.propagacion()
            cambio |= self.algebraica()
            cambio |= self.subexpresiones()
            cambio |= self.codigo_muerto()
            cambio |= self.saltos()
            cambio |= self.inalcanzable()
            if not cambio:
                return

    def optimizar(self):
        self.limpieza()
        self.reduccion_fuerza()
        self.invariantes()
        self.limpieza()
        # Renumerar y convertir referencias de salto a números
        resultado = []
        for c in self.q:
            nuevo = Cuadruplo(c.op, c.a1, c.a2, c.res, c.linea)
            nuevo.orig = c.orig
            resultado.append(nuevo)
        for nuevo, c in zip(resultado, self.q):
            if c.es_salto():
                nuevo.res = self.q.index(c.res) + 1
        return resultado


def optimizar(cuadruplos, tabla):
    try:
        opt = Optimizador(cuadruplos, tabla)
        return opt.optimizar(), opt.bitacora
    except ErrorNetGuard:
        raise
