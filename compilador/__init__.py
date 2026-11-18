# -*- coding: utf-8 -*-
"""
Paquete del compilador NetGuard.

compilar(texto) ejecuta el front-end (léxico, sintáctico y semántico) y el
generador de código intermedio. El optimizador y la máquina virtual se
llaman por separado desde netguard.py.

  Programa .ng → lexer → parser + semantic + symtable → codegen
              → optimizer → vm → reporte
"""
from .errors import ManejadorErrores, ErrorNetGuard
from .lexer import construir as construir_lexer, tokenizar
from .symtable import TablaSimbolos
from .codegen import GeneradorCodigo
from .semantic import PilaSemantica
from . import parser as _parser
from .optimizer import optimizar
from .vm import MaquinaVirtual


class Resultado:
    def __init__(self):
        self.tokens = []
        self.errores = None
        self.tabla = None
        self.cuadruplos = []
        self.pila = None


def compilar(texto):
    r = Resultado()
    r.errores = ManejadorErrores()
    # Lista de tokens (para mostrarla); los errores léxicos se reportan una sola vez
    r.tokens = tokenizar(texto, ManejadorErrores())
    r.tabla = TablaSimbolos()
    gen = GeneradorCodigo()
    r.pila = PilaSemantica(r.tabla, gen, r.errores)
    ctx = _parser.Contexto(r.tabla, gen, r.pila, r.errores)
    lexer = construir_lexer(r.errores)
    try:
        _parser.analizar(texto, ctx, lexer)
    except ErrorNetGuard as e:
        r.errores.error(e.codigo, e.linea, e.mensaje)
    r.cuadruplos = gen.cuadruplos
    return r


__all__ = ['compilar', 'optimizar', 'MaquinaVirtual', 'ManejadorErrores', 'ErrorNetGuard']
