# -*- coding: utf-8 -*-
"""
parser.py - Analizador sintáctico LALR(1) de NetGuard (documento, secciones 7.3 y 8).

Cada función p_... es una producción de la gramática libre de contexto; su
cuerpo es la REGLA SEMÁNTICA de esa producción (traducción dirigida por la
sintaxis). Las reglas usan la pila semántica (semantic.py), la tabla de
símbolos (symtable.py) y el generador de cuádruplas (codegen.py).

Respecto a la gramática del documento solo se agregan no terminales
"marcadores" para ejecutar las acciones en el momento correcto:
  - op_or, op_and, op_not, op_rel, op_suma, op_mult, op_neg, op_asig, abre_par:
    apilan el operador en POptr apenas se lee (sección 10).
  - encabezado_if  (#1), encabezado_else (#2), cierre de <si> (#3),
    encabezado_for (#4) y cierre de <para_cada> (#5) (sección 8.3).
El lenguaje que se acepta es exactamente el mismo.
"""
from ply import yacc

from .lexer import tokens, NOMBRE_SIMBOLO  # noqa: F401  (yacc necesita 'tokens')
from .symtable import Operando, CAMPOS_EVENT
from .semantic import Nodo, asignable
from .errors import ErrorNetGuard

start = 'programa'

# Contexto de la compilación en curso (lo prepara compilar())
ctx = None


class Contexto:
    def __init__(self, tabla, gen, pila, errores):
        self.tabla = tabla
        self.gen = gen
        self.ps = pila
        self.err = errores
        self.ultimo = None
        self.ultima_linea = 1


def operando_error(nombre, linea):
    op = Operando('var', nombre, 'error')
    op.linea = linea
    return op


# ============================================================================
# Programa y declaraciones globales
# ============================================================================
def p_programa(p):
    'programa : globales cargas sentencias'
    ctx.gen.generar('END')


def p_globales(p):
    '''globales : globales decl_limit
                | vacio'''


def p_decl_limit(p):
    "decl_limit : LIMIT ID ':' tipo '=' expr"
    nombre, linea, tipo = p[2], p.lineno(2), p[4]
    val = ctx.ps.sacar_operando()
    if ctx.tabla.buscar_en_actual(nombre):
        ctx.err.error('S02', linea, f"'{nombre}' ya está declarada en el ámbito global")
        return
    if not asignable(tipo, val.tipo):
        ctx.err.error('S03', linea, f"no se puede asignar un valor {val.tipo} a '{nombre}' de tipo {tipo}")
    inicial = val.nombre if val.es_const() else '(expresión)'
    s = ctx.tabla.insertar(nombre, 'Global', tipo, linea, inicial)
    ctx.gen.generar('=', val, None, s.operando(), linea)
    ctx.ps.registrar_arbol(f'LIMIT {nombre}', linea,
                           Nodo('=', 'asignación', 'asignación', None,
                                Nodo(nombre, 'variable', tipo, nombre, linea=linea), val.nodo, linea))
    ctx.ps.marcar_sentencia(f'fin de LIMIT {nombre} (línea {linea})')


def p_tipo(p):
    '''tipo : INT
            | FLOAT
            | STRING
            | BOOLEAN
            | IP'''
    p[0] = p[1]


# ============================================================================
# Carga de eventos
# ============================================================================
def p_cargas(p):
    '''cargas : cargas carga
              | carga'''


def p_carga(p):
    'carga : LOAD EVENTS FROM STRING_LIT AS ID'
    nombre, linea = p[6], p.lineno(6)
    archivo = ctx.tabla.constante(p[4], 'string')
    if ctx.tabla.buscar(nombre):
        ctx.err.error('S02', linea, f"'{nombre}' ya está declarada")
        return
    s = ctx.tabla.insertar(nombre, 'Colección', 'event[]', linea, f'"{p[4]}"')
    s.modificable = False
    ctx.gen.generar('LOAD', archivo, None, s.operando(), linea)


# ============================================================================
# Sentencias
# ============================================================================
def p_sentencias(p):
    '''sentencias : sentencias sentencia
                  | sentencia'''


def p_sentencia(p):
    '''sentencia : decl_local
                 | asignacion
                 | si
                 | para_cada
                 | alerta
                 | marca'''


def p_decl_local(p):
    "decl_local : LET ID ':' tipo '=' expr"
    nombre, linea, tipo = p[2], p.lineno(2), p[4]
    val = ctx.ps.sacar_operando()
    if ctx.tabla.buscar(nombre):
        ctx.err.error('S02', linea, f"'{nombre}' ya está declarada en un ámbito visible")
        return
    if not asignable(tipo, val.tipo):
        ctx.err.error('S03', linea, f"no se puede asignar un valor {val.tipo} a '{nombre}' de tipo {tipo}")
    inicial = val.nombre if val.es_const() else '(expresión)'
    s = ctx.tabla.insertar(nombre, 'Local', tipo, linea, inicial)
    ctx.gen.generar('=', val, None, s.operando(), linea)
    ctx.ps.registrar_arbol(f'LET {nombre}', linea,
                           Nodo('=', 'asignación', 'asignación', None,
                                Nodo(nombre, 'variable', tipo, nombre, linea=linea), val.nodo, linea))
    ctx.ps.marcar_sentencia(f'fin de LET {nombre} (línea {linea})')


def p_asignacion(p):
    'asignacion : destino op_asig expr'
    ctx.ps.asignacion()
    ctx.ps.marcar_sentencia('fin de la asignación')


def p_destino(p):
    'destino : ID'
    nombre, linea = p[1], p.lineno(1)
    s = ctx.tabla.buscar(nombre)
    if s is None:
        ctx.err.error('S01', linea, f"la variable '{nombre}' no está declarada")
        op = operando_error(nombre, linea)
    else:
        if not s.modificable:
            ctx.err.error('S06', linea, f"'{nombre}' es de solo lectura ({s.categoria.lower()})")
        op = s.operando()
    ctx.ps.apilar_operando(op, linea)


def p_op_asig(p):
    "op_asig : '='"
    ctx.ps.apilar_operador('=', p.lineno(1))


# ---------------------------------------------------------------- IF / ELSE
def p_si(p):
    'si : encabezado_if bloque sino END'
    # Acción #3: cerrar ámbito y rellenar el salto pendiente
    pendiente = ctx.ps.PSaltos.pop()
    ctx.gen.rellenar(pendiente, ctx.gen.siguiente())
    ctx.tabla.cerrar_ambito()


def p_encabezado_if(p):
    'encabezado_if : IF expr'
    # Acción #1: la condición debe ser boolean; abrir ámbito; GOTOF pendiente
    linea = p.lineno(1)
    cond = ctx.ps.sacar_operando()
    if cond.tipo not in ('boolean', 'error'):
        ctx.err.error('S05', linea, f'la condición del IF es {cond.tipo}, debe ser boolean')
    ctx.ps.registrar_arbol('Condición del IF', linea, cond.nodo)
    ctx.tabla.abrir_ambito('IF')
    n = ctx.gen.generar('GOTOF', cond, None, None, linea)
    ctx.ps.PSaltos.append(n)
    ctx.ps.marcar_sentencia(f'IF (línea {linea}): GOTOF {n} pendiente, PSaltos = {ctx.ps.PSaltos}')


def p_sino(p):
    '''sino : encabezado_else bloque
            | vacio'''


def p_encabezado_else(p):
    'encabezado_else : ELSE'
    # Acción #2: GOTO pendiente; rellenar el GOTOF con el inicio del ELSE
    linea = p.lineno(1)
    n = ctx.gen.generar('GOTO', None, None, None, linea)
    pendiente = ctx.ps.PSaltos.pop()
    ctx.gen.rellenar(pendiente, ctx.gen.siguiente())
    ctx.ps.PSaltos.append(n)
    ctx.tabla.cerrar_ambito()
    ctx.tabla.abrir_ambito('ELSE')
    ctx.ps.marcar_sentencia(f'ELSE (línea {linea}): {pendiente} → {ctx.gen.siguiente()}, '
                            f'GOTO {n} pendiente, PSaltos = {ctx.ps.PSaltos}')


def p_bloque(p):
    '''bloque : sentencias
              | vacio'''


# ---------------------------------------------------------------- FOR EACH
def p_para_cada(p):
    'para_cada : encabezado_for bloque END'
    # Acción #5: regresar a FE_NEXT, rellenar el GOTOF y cerrar ámbito
    pendiente = ctx.ps.PSaltos.pop()
    inicio = ctx.ps.PSaltos.pop()
    ctx.gen.generar('GOTO', None, None, inicio)
    ctx.gen.rellenar(pendiente, ctx.gen.siguiente())
    ctx.tabla.cerrar_ambito()
    ctx.ps.marcar_sentencia(f'END del FOR EACH: GOTO {inicio}, {pendiente} → {ctx.gen.siguiente()}')


def p_encabezado_for(p):
    'encabezado_for : FOR EACH ID IN ID'
    # Acción #4
    var, coleccion, linea = p[3], p[5], p.lineno(1)
    c = ctx.tabla.buscar(coleccion)
    if c is None:
        ctx.err.error('S01', linea, f"la colección '{coleccion}' no está declarada")
        col_op = operando_error(coleccion, linea)
    else:
        if c.categoria != 'Colección':
            ctx.err.error('S09', linea, f"'{coleccion}' es {c.tipo}, no una colección de eventos")
        col_op = c.operando()
    ctx.tabla.abrir_ambito('FOR')
    if ctx.tabla.buscar(var):
        ctx.err.error('S02', linea, f"'{var}' ya está declarada en un ámbito visible")
        var_op = operando_error(var, linea)
    else:
        s = ctx.tabla.insertar(var, 'Variable de ciclo', 'event', linea)
        var_op = s.operando()
    ctx.gen.generar('FE_INIT', col_op, None, None, linea)
    t = ctx.tabla.nuevo_temporal('boolean', linea)
    inicio = ctx.gen.generar('FE_NEXT', col_op, var_op, t, linea)
    n = ctx.gen.generar('GOTOF', t, None, None, linea)
    ctx.ps.PSaltos.append(inicio)
    ctx.ps.PSaltos.append(n)
    ctx.ps.marcar_sentencia(f'FOR EACH (línea {linea}): regreso {inicio}, GOTOF {n} pendiente, '
                            f'PSaltos = {ctx.ps.PSaltos}')


# ---------------------------------------------------------------- acciones
def p_alerta(p):
    'alerta : ALERT expr FROM expr'
    linea = p.lineno(1)
    ip = ctx.ps.sacar_operando()
    msg = ctx.ps.sacar_operando()
    if msg.tipo not in ('string', 'error'):
        ctx.err.error('S04', linea, f'el mensaje de ALERT debe ser string, no {msg.tipo}')
    if ip.tipo not in ('ip', 'error'):
        ctx.err.error('S04', linea, f'el origen de ALERT debe ser ip, no {ip.tipo}')
    ctx.gen.generar('ALERT', msg, ip, None, linea)
    ctx.ps.marcar_sentencia(f'fin de ALERT (línea {linea})')


def p_marca(p):
    'marca : MARK ID AS expr'
    nombre, linea = p[2], p.lineno(2)
    val = ctx.ps.sacar_operando()
    s = ctx.tabla.buscar(nombre)
    if s is None:
        ctx.err.error('S01', linea, f"la variable '{nombre}' no está declarada")
        ev = operando_error(nombre, linea)
    else:
        if s.tipo != 'event':
            ctx.err.error('S04', linea, f"MARK necesita un event y '{nombre}' es {s.tipo}")
        ev = s.operando()
    if val.tipo not in ('string', 'error'):
        ctx.err.error('S04', linea, f'el estado de MARK debe ser string, no {val.tipo}')
    ctx.gen.generar('MARK', ev, val, None, linea)
    ctx.ps.marcar_sentencia(f'fin de MARK (línea {linea})')


# ============================================================================
# Expresiones (precedencia por niveles: OR < AND < NOT < relacionales < + - < * / < unario)
# ============================================================================
def p_expr(p):
    '''expr : expr op_or expr_and
            | expr_and'''
    if len(p) == 4:
        ctx.ps.operacion_binaria()


def p_op_or(p):
    'op_or : OR'
    ctx.ps.apilar_operador('OR', p.lineno(1))


def p_expr_and(p):
    '''expr_and : expr_and op_and expr_not
                | expr_not'''
    if len(p) == 4:
        ctx.ps.operacion_binaria()


def p_op_and(p):
    'op_and : AND'
    ctx.ps.apilar_operador('AND', p.lineno(1))


def p_expr_not(p):
    '''expr_not : op_not expr_not
                | expr_rel'''
    if len(p) == 3:
        ctx.ps.operacion_unaria()


def p_op_not(p):
    'op_not : NOT'
    ctx.ps.apilar_operador('NOT', p.lineno(1))


def p_expr_rel(p):
    '''expr_rel : expr_arit op_rel expr_arit
                | expr_arit'''
    if len(p) == 4:
        ctx.ps.operacion_binaria()


def p_op_rel(p):
    '''op_rel : LT
              | LE
              | GT
              | GE
              | EQ
              | NE'''
    ctx.ps.apilar_operador(p[1], p.lineno(1))


def p_expr_arit(p):
    '''expr_arit : expr_arit op_suma termino
                 | termino'''
    if len(p) == 4:
        ctx.ps.operacion_binaria()


def p_op_suma(p):
    '''op_suma : '+'
               | '-' '''
    ctx.ps.apilar_operador(p[1], p.lineno(1))


def p_termino(p):
    '''termino : termino op_mult factor
               | factor'''
    if len(p) == 4:
        ctx.ps.operacion_binaria()


def p_op_mult(p):
    '''op_mult : '*'
               | '/' '''
    ctx.ps.apilar_operador(p[1], p.lineno(1))


def p_factor_neg(p):
    'factor : op_neg factor'
    ctx.ps.operacion_unaria()


def p_op_neg(p):
    "op_neg : '-'"
    ctx.ps.apilar_operador('NEG', p.lineno(1))


def p_factor_par(p):
    "factor : abre_par expr ')'"
    ctx.ps.cerrar_parentesis()


def p_abre_par(p):
    "abre_par : '('"
    ctx.ps.apilar_operador('(', p.lineno(1))


def p_factor(p):
    '''factor : acceso
              | literal'''


def p_acceso_id(p):
    'acceso : ID'
    nombre, linea = p[1], p.lineno(1)
    s = ctx.tabla.buscar(nombre)
    if s is None:
        ctx.err.error('S01', linea, f"la variable '{nombre}' no está declarada")
        ctx.ps.apilar_operando(operando_error(nombre, linea), linea)
    else:
        ctx.ps.apilar_operando(s.operando(), linea)


def p_acceso_campo(p):
    "acceso : ID '.' ID"
    base, campo, linea = p[1], p[3], p.lineno(1)
    nombre = f'{base}.{campo}'
    s = ctx.tabla.buscar(base)
    if s is None:
        ctx.err.error('S01', linea, f"la variable '{base}' no está declarada")
        op = operando_error(nombre, linea)
    elif s.tipo != 'event':
        ctx.err.error('S07', linea, f"'{base}' es {s.tipo}, no tiene el campo '{campo}'")
        op = operando_error(nombre, linea)
    elif campo not in CAMPOS_EVENT:
        ctx.err.error('S07', linea, f"event no tiene el campo '{campo}' "
                                    f"(campos: {', '.join(CAMPOS_EVENT)})")
        op = operando_error(nombre, linea)
    else:
        desp, tipo = CAMPOS_EVENT[campo]
        op = Operando('campo', nombre, tipo, None, simbolo=s, campo=campo)
        op.desplazamiento = desp
    ctx.ps.apilar_operando(op, linea)


def p_literal(p):
    '''literal : INT_LIT
               | FLOAT_LIT
               | STRING_LIT
               | IP_LIT
               | TRUE
               | FALSE'''
    tok = p.slice[1].type
    linea = p.lineno(1)
    if tok == 'INT_LIT':
        op = ctx.tabla.constante(p[1], 'int')
    elif tok == 'FLOAT_LIT':
        op = ctx.tabla.constante(p[1], 'float')
    elif tok == 'STRING_LIT':
        op = ctx.tabla.constante(p[1], 'string')
    elif tok == 'IP_LIT':
        octetos = [int(x) for x in p[1].split('.')]
        if any(o > 255 for o in octetos):
            ctx.err.error('S08', linea, f'la IP {p[1]} tiene un octeto fuera del rango 0-255')
        op = ctx.tabla.constante(p[1], 'ip')
    else:
        op = ctx.tabla.constante(tok == 'TRUE', 'boolean')
    # Copia para no compartir el nodo del árbol entre usos de la misma constante
    copia = Operando('const', op.nombre, op.tipo, op.dir, valor=op.valor)
    ctx.ps.apilar_operando(copia, linea)


def p_vacio(p):
    'vacio :'


def p_error(t):
    if t is None:
        raise ErrorNetGuard('P02', ctx.ultima_linea,
                            'fin de archivo inesperado (¿falta un END o una sentencia?)')
    valor = NOMBRE_SIMBOLO.get(t.type, t.value)
    if t.type == 'STRING_LIT':
        valor = f'"{t.value}"'
    raise ErrorNetGuard('P01', t.lineno, f"token inesperado '{valor}'")


_parser = None


def construir_parser(debug=False):
    global _parser
    if _parser is None or debug:
        if debug:
            _parser = yacc.yacc(write_tables=False, debug=True, debugfile='parser.out')
        else:
            _parser = yacc.yacc(write_tables=False, debug=False, errorlog=yacc.NullLogger())
    return _parser


def analizar(texto, contexto, lexer):
    """Ejecuta el análisis sintáctico con las acciones semánticas."""
    global ctx
    ctx = contexto
    parser = construir_parser()

    def siguiente_token():
        tok = lexer.token()
        if tok is not None:
            ctx.ultimo = tok
            ctx.ultima_linea = tok.lineno
        else:
            ctx.ultimo = None
        return tok

    def lector():
        t = ctx.ultimo
        if t is None:
            return 'fin'
        if t.type == 'STRING_LIT':
            return f'"{t.value}"'
        return str(NOMBRE_SIMBOLO.get(t.type, t.value))

    ctx.ps.lector = lector
    lexer.input(texto)
    parser.parse(texto, lexer=lexer, tokenfunc=siguiente_token)
