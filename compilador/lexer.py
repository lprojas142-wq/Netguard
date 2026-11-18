# -*- coding: utf-8 -*-
"""
lexer.py - Analizador léxico de NetGuard (documento, sección 7.2).

Convierte el texto del programa .ng en una secuencia de tokens usando
ply.lex. Las palabras reservadas van en MAYÚSCULAS, los tipos en minúsculas
y los comentarios empiezan con # y terminan al final de la línea.
"""
from ply import lex

# Palabras reservadas (lexema -> token)
RESERVADAS = {
    'LIMIT': 'LIMIT', 'LET': 'LET', 'LOAD': 'LOAD', 'EVENTS': 'EVENTS',
    'FROM': 'FROM', 'AS': 'AS', 'FOR': 'FOR', 'EACH': 'EACH', 'IN': 'IN',
    'IF': 'IF', 'ELSE': 'ELSE', 'END': 'END', 'ALERT': 'ALERT', 'MARK': 'MARK',
    'AND': 'AND', 'OR': 'OR', 'NOT': 'NOT',
    # Tipos
    'int': 'INT', 'float': 'FLOAT', 'string': 'STRING', 'boolean': 'BOOLEAN', 'ip': 'IP',
    # Literales booleanos
    'true': 'TRUE', 'false': 'FALSE',
}

tokens = [
    'ID', 'IP_LIT', 'FLOAT_LIT', 'INT_LIT', 'STRING_LIT',
    'LE', 'GE', 'EQ', 'NE', 'LT', 'GT',
] + sorted(set(RESERVADAS.values()))

# Símbolos de un carácter que el parser usa directamente
literals = ['+', '-', '*', '/', '=', ':', '.', '(', ')']

# Operadores relacionales (PLY ordena las cadenas de mayor a menor longitud,
# así '<=' se reconoce antes que '<')
t_LE = r'<='
t_GE = r'>='
t_EQ = r'=='
t_NE = r'!='
t_LT = r'<'
t_GT = r'>'

t_ignore = ' \t\r'

# Nombres "bonitos" para mostrar en la tabla de tokens y en los errores
NOMBRE_SIMBOLO = {
    'LE': '<=', 'GE': '>=', 'EQ': '==', 'NE': '!=', 'LT': '<', 'GT': '>',
}


def t_COMENTARIO(t):
    r'\#[^\n]*'
    pass  # se descarta


# El orden de las funciones importa: IP_LIT antes que FLOAT_LIT, y éste antes
# que INT_LIT (sección 7.2: "se revisa antes que FLOAT_LIT").
def t_IP_LIT(t):
    r'[0-9]{1,3}(\.[0-9]{1,3}){3}'
    return t


def t_FLOAT_LIT(t):
    r'[0-9]+\.[0-9]+'
    t.value = float(t.value)
    return t


def t_INT_LIT(t):
    r'[0-9]+'
    t.value = int(t.value)
    return t


def t_STRING_LIT(t):
    r'"[^"\n]*"'
    t.value = t.value[1:-1]
    return t


def t_CADENA_SIN_CERRAR(t):
    r'"[^"\n]*'
    t.lexer.manejador.error('L02', t.lineno, 'cadena sin cerrar: falta la comilla final')
    # se descarta para seguir analizando


def t_ID(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = RESERVADAS.get(t.value, 'ID')
    return t


def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)


def t_error(t):
    t.lexer.manejador.error('L01', t.lineno, f"carácter no válido '{t.value[0]}'")
    t.lexer.skip(1)


def construir(manejador):
    """Crea un analizador léxico nuevo ligado a un manejador de errores."""
    lx = lex.lex()
    lx.manejador = manejador
    lx.lineno = 1
    return lx


def tokenizar(texto, manejador):
    """Devuelve la lista completa de tokens (para la opción --tokens)."""
    lx = construir(manejador)
    lx.input(texto)
    lista = []
    while True:
        tok = lx.token()
        if not tok:
            break
        lista.append(tok)
    return lista


def categoria(tok):
    """Categoría del token según la tabla 7.2 del documento."""
    t = tok.type
    if t in ('AND', 'OR', 'NOT'):
        return 'Operador lógico'
    if t in ('INT', 'FLOAT', 'STRING', 'BOOLEAN', 'IP'):
        return 'Tipo'
    if t in ('TRUE', 'FALSE'):
        return 'Literal booleano'
    if t in RESERVADAS.values():
        return 'Palabra reservada'
    if t == 'ID':
        return 'Identificador'
    if t == 'IP_LIT':
        return 'Literal IP'
    if t == 'FLOAT_LIT':
        return 'Literal real'
    if t == 'INT_LIT':
        return 'Literal entero'
    if t == 'STRING_LIT':
        return 'Cadena'
    if t in NOMBRE_SIMBOLO:
        return 'Relacional'
    if t in ('+', '-', '*', '/'):
        return 'Aritmético'
    return 'Asignación y puntuación'


def lexema(tok):
    if tok.type == 'STRING_LIT':
        return f'"{tok.value}"'
    return str(tok.value)
