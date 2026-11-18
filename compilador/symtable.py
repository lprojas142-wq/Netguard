# -*- coding: utf-8 -*-
"""
symtable.py - Tabla de símbolos de NetGuard (documento, sección 11).

Es una PILA DE TABLAS HASH, una por ámbito. El fondo es el ámbito global y
cada FOR EACH, IF o ELSE apila una tabla nueva que se retira en su END.
Buscar un nombre recorre la pila del tope al fondo.

Direcciones virtuales por rangos (sección 11.1):
  globales 1000-1999, locales 2000-2999, temporales 3000-3999,
  constantes 4000-4999, colecciones desde 5000.
"""

# Campos fijos del tipo event: nombre -> (desplazamiento, tipo)   (sección 11.3)
CAMPOS_EVENT = {
    'sourceIP': (0, 'ip'),
    'eventType': (1, 'string'),
    'port': (2, 'int'),
    'failedAttempts': (3, 'int'),
    'trafficMB': (4, 'float'),
    'status': (5, 'string'),
}

BASE = {'Global': 1000, 'Local': 2000, 'Variable de ciclo': 2000,
        'Temporal': 3000, 'Constante': 4000, 'Colección': 5000}


class Operando:
    """Lo que viaja por la pila de operandos y aparece en las cuádruplas."""

    def __init__(self, clase, nombre, tipo, dir=None, valor=None, simbolo=None, campo=None):
        self.clase = clase      # 'var', 'temp', 'const', 'campo'
        self.nombre = nombre    # texto que se muestra
        self.tipo = tipo
        self.dir = dir          # dirección virtual
        self.valor = valor      # solo constantes
        self.simbolo = simbolo  # entrada de la tabla (var / campo)
        self.campo = campo      # nombre del campo (campo)
        self.nodo = None        # nodo del árbol de expresión (sección 9)

    def __str__(self):
        return self.nombre

    def es_const(self):
        return self.clase == 'const'

    def clave(self):
        """Identidad del operando, para comparar en el optimizador."""
        if self.clase == 'const':
            return ('const', self.tipo, self.valor)
        if self.clase == 'campo':
            return ('campo', self.simbolo.dir, self.campo)
        return (self.clase, self.dir)


def texto_constante(valor, tipo):
    if tipo == 'boolean':
        return 'true' if valor else 'false'
    if tipo == 'string':
        return f'"{valor}"'
    if tipo == 'float':
        return repr(float(valor))
    return str(valor)


class Simbolo:
    def __init__(self, nombre, categoria, tipo, ambito, nivel, dir, modificable, valor_inicial, linea):
        self.nombre = nombre
        self.categoria = categoria
        self.tipo = tipo
        self.ambito = ambito
        self.nivel = nivel
        self.dir = dir
        self.modificable = modificable
        self.valor_inicial = valor_inicial
        self.linea = linea

    def operando(self):
        return Operando('var', self.nombre, self.tipo, self.dir, simbolo=self)


class TablaSimbolos:
    def __init__(self):
        self.pila = [('global', {})]       # [(nombre_ambito, {nombre: Simbolo})]
        self.todos = []                    # historial completo (para imprimir)
        self.temporales = []
        self.constantes = {}               # (tipo, valor) -> Operando
        self.contadores = {'Global': 0, 'Local': 0, 'Temporal': 0, 'Constante': 0, 'Colección': 0}
        self.ambitos_creados = {}

    # ---------------- ámbitos ----------------
    def nivel(self):
        return len(self.pila) - 1

    def ambito_actual(self):
        return self.pila[-1][0]

    def abrir_ambito(self, tipo):
        n = self.ambitos_creados.get(tipo, 0) + 1
        self.ambitos_creados[tipo] = n
        nombre = f'{tipo}#{n}'
        self.pila.append((nombre, {}))
        return nombre

    def cerrar_ambito(self):
        if len(self.pila) > 1:
            self.pila.pop()

    # ---------------- símbolos ----------------
    def buscar(self, nombre):
        for _, tabla in reversed(self.pila):
            if nombre in tabla:
                return tabla[nombre]
        return None

    def buscar_en_actual(self, nombre):
        return self.pila[-1][1].get(nombre)

    def _direccion(self, categoria):
        clave = 'Local' if categoria == 'Variable de ciclo' else categoria
        d = BASE[categoria] + self.contadores[clave]
        self.contadores[clave] += 1
        return d

    def insertar(self, nombre, categoria, tipo, linea, valor_inicial='—'):
        modificable = categoria == 'Local'
        s = Simbolo(nombre, categoria, tipo, self.ambito_actual(), self.nivel(),
                    self._direccion(categoria), modificable, valor_inicial, linea)
        self.pila[-1][1][nombre] = s
        self.todos.append(s)
        return s

    def nuevo_temporal(self, tipo, linea):
        n = len(self.temporales) + 1
        op = Operando('temp', f't{n}', tipo, self._direccion('Temporal'))
        op.linea = linea
        self.temporales.append(op)
        return op

    def constante(self, valor, tipo):
        if tipo == 'float':
            valor = float(valor)
        clave = (tipo, valor if tipo != 'boolean' else bool(valor))
        if clave not in self.constantes:
            op = Operando('const', texto_constante(valor, tipo), tipo,
                          self._direccion('Constante'), valor=valor)
            self.constantes[clave] = op
        return self.constantes[clave]

    # ---------------- impresión ----------------
    def filas_simbolos(self):
        filas = []
        for s in self.todos:
            filas.append([s.nombre, s.categoria, s.tipo, s.ambito, str(s.nivel), str(s.dir),
                          'Sí' if s.modificable else 'No', str(s.valor_inicial), str(s.linea)])
        for t in self.temporales:
            filas.append([t.nombre, 'Temporal', t.tipo, '—', '—', str(t.dir), '—', '—', str(t.linea)])
        return filas

    def filas_constantes(self):
        return [[c.nombre, c.tipo, str(c.dir)] for c in self.constantes.values()]
