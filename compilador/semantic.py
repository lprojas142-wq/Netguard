# -*- coding: utf-8 -*-
"""
semantic.py - Análisis semántico de NetGuard (documento, secciones 8, 9 y 10).

Contiene:
  * resultado(op, t1, t2) y asignable(destino, valor): la tabla de
    compatibilidad de tipos (sección 8.2).
  * Nodo: nodo de los árboles de expresiones (sección 9).
  * PilaSemantica: las cuatro pilas POper, PTipos, POptr y PSaltos
    (sección 10) con su traza paso a paso.

El analizador sintáctico (parser.py) llama a estos métodos cada vez que
reduce una producción; así los cuádruplos salen en el mismo orden que el
recorrido en postorden del árbol.
"""
from .symtable import Operando

NUMERICOS = ('int', 'float')
ARITMETICOS = ('+', '-', '*', '/')
RELACIONALES = ('<', '<=', '>', '>=')
IGUALDAD = ('==', '!=')
LOGICOS = ('AND', 'OR')

# Prioridad de los operadores (mayor número = se evalúa primero)
PRIORIDAD = {'OR': 1, 'AND': 2, 'NOT': 3, '<': 4, '<=': 4, '>': 4, '>=': 4, '==': 4, '!=': 4,
             '+': 5, '-': 5, '*': 6, '/': 6, 'NEG': 7, '=': 0, '(': -1}


def resultado(op, t1, t2=None):
    """Tipo de una operación o 'error' (tabla 8.2)."""
    if 'error' in (t1, t2):
        return 'error'
    if op in ('+', '-', '*'):
        if t1 == 'int' and t2 == 'int':
            return 'int'
        if t1 in NUMERICOS and t2 in NUMERICOS:
            return 'float'
        return 'error'
    if op == '/':
        return 'float' if t1 in NUMERICOS and t2 in NUMERICOS else 'error'
    if op == 'NEG':
        return t1 if t1 in NUMERICOS else 'error'
    if op in RELACIONALES:
        return 'boolean' if t1 in NUMERICOS and t2 in NUMERICOS else 'error'
    if op in IGUALDAD:
        if t1 in NUMERICOS and t2 in NUMERICOS:
            return 'boolean'
        if t1 == t2 and t1 in ('string', 'boolean', 'ip'):
            return 'boolean'
        return 'error'
    if op in LOGICOS:
        return 'boolean' if t1 == 'boolean' and t2 == 'boolean' else 'error'
    if op == 'NOT':
        return 'boolean' if t1 == 'boolean' else 'error'
    return 'error'


def asignable(destino, valor):
    """Destino y valor del mismo tipo, o destino float con valor int."""
    if 'error' in (destino, valor):
        return True          # el error ya se reportó antes; evita cascadas
    return destino == valor or (destino == 'float' and valor == 'int')


# ----------------------------------------------------------------------------
# Árboles de expresiones (sección 9)
# ----------------------------------------------------------------------------
class Nodo:
    def __init__(self, etiqueta, clase, tipo, lugar, izq=None, der=None, linea=None):
        self.etiqueta = etiqueta
        self.clase = clase
        self.tipo = tipo
        self.lugar = lugar
        self.izq = izq
        self.der = der
        self.linea = linea

    def hijos(self):
        return [h for h in (self.izq, self.der) if h is not None]

    def postorden(self):
        r = []
        for h in self.hijos():
            r += h.postorden()
        return r + [self.etiqueta]


def hoja(op, linea):
    clases = {'var': 'variable', 'temp': 'temporal', 'const': 'constante', 'campo': 'campo'}
    return Nodo(op.nombre, clases.get(op.clase, op.clase), op.tipo, op.nombre, linea=linea)


def dibujar_arbol(nodo):
    """Árbol en texto, con tipo y lugar de cada nodo."""
    lineas = []

    def etiqueta(n):
        if n.hijos():
            extra = f'{n.tipo} · {n.lugar}' if n.lugar and n.lugar != n.etiqueta else n.tipo
        else:
            extra = n.tipo
        return f'{n.etiqueta}  [{extra}]'

    def rec(n, prefijo, ultimo, raiz):
        if raiz:
            lineas.append(etiqueta(n))
            nuevo = ''
        else:
            lineas.append(prefijo + ('└── ' if ultimo else '├── ') + etiqueta(n))
            nuevo = prefijo + ('    ' if ultimo else '│   ')
        hs = n.hijos()
        for i, h in enumerate(hs):
            rec(h, nuevo, i == len(hs) - 1, False)

    rec(nodo, '', True, True)
    return lineas


# ----------------------------------------------------------------------------
# Pila semántica (sección 10)
# ----------------------------------------------------------------------------
class PilaSemantica:
    def __init__(self, tabla, gen, errores):
        self.tabla = tabla
        self.gen = gen
        self.errores = errores
        self.POper = []      # operandos
        self.PTipos = []     # tipos (en paralelo a POper)
        self.POptr = []      # operadores: (operador, línea)
        self.PSaltos = []    # cuádruplos pendientes de rellenar / de regreso
        self.traza = []      # filas de la traza (listas) y separadores (texto)
        self.pasos = 0
        self.arboles = []    # (descripción, línea, nodo raíz)
        self.lector = None   # función que devuelve el último token leído

    def simbolo_actual(self):
        """Símbolo de entrada que provocó la reducción (lookahead) o 'fin'."""
        return self.lector() if self.lector else 'fin'

    # ---------- traza ----------
    def _registrar(self, simbolo, accion, cuad=None):
        self.pasos += 1
        self.traza.append([
            str(self.pasos), simbolo, accion,
            ', '.join(o.nombre for o in self.POper) or '—',
            ', '.join(self.PTipos) or '—',
            ', '.join(o for o, _ in self.POptr) or '—',
            str(cuad) if cuad is not None else '—',
        ])

    def marcar_sentencia(self, texto):
        """Separador en la traza para saber a qué sentencia pertenece cada paso."""
        self.traza.append(f'── {texto}')

    # ---------- operandos y operadores ----------
    def apilar_operando(self, op, linea, simbolo=None, accion=None):
        op.nodo = op.nodo or hoja(op, linea)
        op.linea = linea
        self.POper.append(op)
        self.PTipos.append(op.tipo)
        if accion is None:
            accion = 'Apilar constante' if op.clase == 'const' else 'Apilar operando'
        self._registrar(simbolo or op.nombre, accion)

    def sacar_operando(self):
        self.PTipos.pop()
        return self.POper.pop()

    def apilar_operador(self, op, linea):
        self.POptr.append((op, linea))
        self._registrar(op if op != 'NEG' else '-', 'Apilar operador' if op != '(' else 'Apilar fondo falso (')

    def cerrar_parentesis(self):
        if self.POptr and self.POptr[-1][0] == '(':
            self.POptr.pop()
        self._registrar(')', 'Sacar fondo falso (')

    def operacion_binaria(self):
        op, linea = self.POptr.pop()
        der = self.sacar_operando()
        izq = self.sacar_operando()
        tipo = resultado(op, izq.tipo, der.tipo)
        if tipo == 'error' and 'error' not in (izq.tipo, der.tipo):
            self.errores.error('S04', linea,
                               f"no se puede aplicar '{op}' a {izq.tipo} y {der.tipo} ({izq} {op} {der})")
        t = self.tabla.nuevo_temporal(tipo, linea)
        n = self.gen.generar(op, izq, der, t, linea)
        t.nodo = Nodo(op, 'operador binario', tipo, t.nombre, izq.nodo, der.nodo, linea)
        self.POper.append(t)
        self.PTipos.append(tipo)
        self._registrar(self.simbolo_actual(), f'Sacar {op}: {izq.tipo} {op} {der.tipo} = {tipo}',
                        self.gen.get(n))
        return t

    def operacion_unaria(self):
        op, linea = self.POptr.pop()
        val = self.sacar_operando()
        tipo = resultado(op, val.tipo)
        if tipo == 'error' and val.tipo != 'error':
            simb = 'NOT' if op == 'NOT' else '-'
            self.errores.error('S04', linea, f"no se puede aplicar '{simb}' a {val.tipo} ({val})")
        t = self.tabla.nuevo_temporal(tipo, linea)
        n = self.gen.generar(op, val, None, t, linea)
        etiqueta = 'NOT' if op == 'NOT' else '-'
        t.nodo = Nodo(etiqueta, 'operador unario', tipo, t.nombre, val.nodo, None, linea)
        self.POper.append(t)
        self.PTipos.append(tipo)
        self._registrar(self.simbolo_actual(), f'Sacar {etiqueta}: {etiqueta} {val.tipo} = {tipo}', self.gen.get(n))
        return t

    def asignacion(self):
        """Sentencia ID = expr: saca '=', el valor y el destino."""
        _, linea = self.POptr.pop()
        val = self.sacar_operando()
        dest = self.sacar_operando()
        ok = asignable(dest.tipo, val.tipo)
        if not ok:
            self.errores.error('S03', linea,
                               f"no se puede asignar un valor {val.tipo} a '{dest}' de tipo {dest.tipo}")
        n = self.gen.generar('=', val, None, dest, linea)
        self._registrar(self.simbolo_actual(), f"Sacar =: asignable({dest.tipo}, {val.tipo}) es "
                               f"{'verdadero' if ok else 'falso'}", self.gen.get(n))
        self.registrar_arbol(f'Asignación a {dest}', linea,
                             Nodo('=', 'asignación', 'asignación', None, dest.nodo, val.nodo, linea))

    def registrar_arbol(self, descripcion, linea, nodo):
        if nodo is not None:
            self.arboles.append((descripcion, linea, nodo))

    def vacia(self):
        return not (self.POper or self.POptr or self.PSaltos)
