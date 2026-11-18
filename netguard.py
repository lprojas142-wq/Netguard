# -*- coding: utf-8 -*-
"""
netguard.py - Programa principal de NetGuard.

Une todas las fases del compilador-intérprete (documento, sección 14):

  python netguard.py PROGRAMA.ng [REGISTRO.log] [opciones]

Opciones para mostrar cada fase:
  --tokens        Fase léxica: tabla de tokens (sección 7.2)
  --arbol         Árboles de expresiones (sección 9)
  --traza         Traza de la pila semántica (sección 10)
  --tabla         Tabla de símbolos y de constantes (sección 11)
  --cuadruplos    Código intermedio en cuádruplas (sección 12.3)
  --tripletas     El mismo código en tripletas (sección 12.4)
  --optimizado    Cuádruplas optimizadas y bitácora de cambios (sección 13)
  --direcciones   Muestra las direcciones virtuales en las cuádruplas
  --todo          Todas las anteriores
  --comparar      Ejecuta con y sin optimizar y compara cuántos cuádruplos se ejecutan
  --presentacion  Muestra las fases una por una, con pausa entre ellas
  --sin-optimizar Ejecuta el código sin optimizar
  --no-ejecutar   Solo compila
  --reporte RUTA  Archivo del reporte (por omisión: reporte.txt)
"""
import argparse
import datetime
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)          # para encontrar ply/ y compilador/

from compilador import compilar, optimizar, MaquinaVirtual, ManejadorErrores, ErrorNetGuard  # noqa: E402
from compilador.codegen import a_tripletas  # noqa: E402
from compilador.semantic import dibujar_arbol  # noqa: E402
from compilador import lexer as lx  # noqa: E402

VERSION = '1.0'


# ----------------------------------------------------------------------------
# Utilidades de impresión
# ----------------------------------------------------------------------------
def configurar_consola():
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass
    if os.name == 'nt':
        os.system('')               # activa los colores/códigos ANSI en Windows 10+


def tabla_texto(encabezados, filas):
    anchos = [len(h) for h in encabezados]
    for f in filas:
        if isinstance(f, str):
            continue
        for i, celda in enumerate(f):
            anchos[i] = max(anchos[i], len(str(celda)))
    sep = '+' + '+'.join('-' * (a + 2) for a in anchos) + '+'
    total = len(sep) - 4

    def fila(celdas):
        if isinstance(celdas, str):          # fila separadora que ocupa todo el ancho
            return '| ' + celdas[:total].ljust(total) + ' |'
        return '| ' + ' | '.join(str(c).ljust(a) for c, a in zip(celdas, anchos)) + ' |'
    lineas = [sep, fila(encabezados), sep.replace('-', '=')]
    lineas += [fila(f) for f in filas]
    lineas.append(sep)
    return '\n'.join(lineas)


def titulo(texto):
    print()
    print('=' * 78)
    print(f'  {texto}')
    print('=' * 78)


def pausa(activa):
    if activa and sys.stdin.isatty():
        try:
            input('\n   [Enter] para continuar...')
        except EOFError:
            pass


# ----------------------------------------------------------------------------
# Secciones que se pueden mostrar
# ----------------------------------------------------------------------------
def mostrar_programa(ruta, texto):
    titulo(f'PROGRAMA FUENTE: {ruta}')
    for i, linea in enumerate(texto.splitlines(), 1):
        print(f'{i:>3}  {linea}')


def mostrar_tokens(r):
    titulo('FASE 1 · ANÁLISIS LÉXICO: tokens (sección 7.2)')
    filas = [[str(t.lineno), lx.NOMBRE_SIMBOLO.get(t.type, t.type), lx.lexema(t), lx.categoria(t)]
             for t in r.tokens]
    print(tabla_texto(['Línea', 'Token', 'Lexema', 'Categoría'], filas))
    print(f'Total: {len(r.tokens)} tokens')


def mostrar_arboles(r):
    titulo('ÁRBOLES DE EXPRESIONES (sección 9)')
    for desc, linea, nodo in r.pila.arboles:
        print(f'\n• {desc} (línea {linea})')
        for l in dibujar_arbol(nodo):
            print('    ' + l)
        print('    Postfija: ' + ' '.join(nodo.postorden()))


def mostrar_traza(r):
    titulo('PILA SEMÁNTICA: traza paso a paso (sección 10)')
    print('El tope de cada pila es el elemento de la derecha. "Símbolo" es el token que se')
    print('estaba leyendo cuando ocurrió la acción.')
    filas = r.pila.traza
    print(tabla_texto(['#', 'Símbolo', 'Acción', 'POper', 'PTipos', 'POptr', 'Cuádruplo generado'], filas))
    estado = 'vacías' if r.pila.vacia() else 'NO vacías (falta un END)'
    print(f'Al terminar, las cuatro pilas quedaron {estado}.')


def mostrar_tabla(r):
    titulo('TABLA DE SÍMBOLOS (sección 11)')
    print(tabla_texto(['Nombre', 'Categoría', 'Tipo', 'Ámbito', 'Nivel', 'Dirección', 'Modificable',
                       'Valor inicial', 'Línea'], r.tabla.filas_simbolos()))
    print('\nTabla de constantes:')
    print(tabla_texto(['Constante', 'Tipo', 'Dirección'], r.tabla.filas_constantes()))
    print('Rangos: globales 1000 · locales 2000 · temporales 3000 · constantes 4000 · colecciones 5000')


def filas_cuadruplos(cuads, direcciones, con_origen=False):
    filas = []
    for i, c in enumerate(cuads, 1):
        fila = [str(i)] + c.textos(direcciones)
        if con_origen:
            fila.append(str(getattr(c, 'orig', '')))
        else:
            fila.append(str(c.linea) if c.linea else '—')
        filas.append(fila)
    return filas


def mostrar_cuadruplos(r, direcciones):
    titulo('CÓDIGO INTERMEDIO: cuádruplas (operador, arg1, arg2, resultado) (sección 12.3)')
    print(tabla_texto(['#', 'Operador', 'arg1', 'arg2', 'Resultado', 'Línea fuente'],
                      filas_cuadruplos(r.cuadruplos, direcciones)))
    print(f'Total: {len(r.cuadruplos)} cuádruplas')


def mostrar_tripletas(r):
    titulo('CÓDIGO INTERMEDIO: tripletas (operador, arg1, arg2) (sección 12.4)')
    filas = [[str(i)] + t for i, t in enumerate(a_tripletas(r.cuadruplos), 1)]
    print(tabla_texto(['#', 'Operador', 'arg1', 'arg2'], filas))


def mostrar_optimizado(r, opt, bitacora, direcciones):
    titulo('OPTIMIZACIÓN (sección 13)')
    if bitacora:
        print('Cambios aplicados (numeración del código original):')
        for tecnica, texto in bitacora:
            print(f'  · {tecnica}: {texto}')
    else:
        print('No se encontró nada que optimizar.')
    print()
    print(tabla_texto(['#', 'Operador', 'arg1', 'arg2', 'Resultado', 'Viene del original'],
                      filas_cuadruplos(opt, direcciones, con_origen=True)))
    print(f'Total: {len(r.cuadruplos)} → {len(opt)} cuádruplas')


def ejecutar(cuads, ruta_ng, registro, salida=print):
    err = ManejadorErrores()
    vm = MaquinaVirtual(cuads, err, base_dir=os.path.dirname(os.path.abspath(ruta_ng)),
                        registro=registro, salida=salida)
    vm.ejecutar()
    return vm, err


def escribir_reporte(ruta, ruta_ng, vm, err, optimizado):
    with open(ruta, 'w', encoding='utf-8') as f:
        f.write('REPORTE NETGUARD\n')
        f.write(f'Fecha:     {datetime.datetime.now():%Y-%m-%d %H:%M}\n')
        f.write(f'Programa:  {ruta_ng}\n')
        f.write(f'Registro:  {", ".join(vm.archivos)}\n')
        f.write(f'Código:    {"optimizado" if optimizado else "sin optimizar"}\n')
        f.write('-' * 60 + '\n')
        for l in vm.lineas:
            f.write(l + '\n')
        for c, l, m in err.advertencias:
            f.write(f'Advertencia [{c}] línea {l} del registro: {m}\n')


# ----------------------------------------------------------------------------
def main(argv=None):
    configurar_consola()
    ap = argparse.ArgumentParser(
        prog='netguard',
        description='NetGuard: lenguaje para detección de comportamientos sospechosos en redes.')
    ap.add_argument('programa', help='archivo .ng con las reglas')
    ap.add_argument('registro', nargs='?', help='archivo .log (si se omite se usa el del LOAD)')
    ayudas = {
        'tokens': 'muestra la tabla de tokens (análisis léxico)',
        'arbol': 'muestra los árboles de expresiones',
        'traza': 'muestra la traza de la pila semántica',
        'tabla': 'muestra la tabla de símbolos y de constantes',
        'cuadruplos': 'muestra el código intermedio en cuádruplas',
        'tripletas': 'muestra el código intermedio en tripletas',
        'optimizado': 'muestra las cuádruplas optimizadas y los cambios aplicados',
        'direcciones': 'agrega las direcciones virtuales a las cuádruplas',
        'todo': 'muestra todas las fases',
        'comparar': 'compara la ejecución con y sin optimizar',
        'presentacion': 'muestra todas las fases una por una, con pausa (para exponer)',
    }
    for op, ayuda in ayudas.items():
        ap.add_argument(f'--{op}', action='store_true', help=ayuda)
    ap.add_argument('--sin-optimizar', action='store_true', help='ejecuta el código sin optimizar')
    ap.add_argument('--no-ejecutar', action='store_true', help='solo compila, no ejecuta')
    ap.add_argument('--reporte', default='reporte.txt', help='archivo del reporte (por omisión reporte.txt)')
    ap.add_argument('--version', action='version', version=f'NetGuard {VERSION}')
    a = ap.parse_args(argv)

    if a.todo or a.presentacion:
        a.tokens = a.arbol = a.traza = a.tabla = a.cuadruplos = a.tripletas = a.optimizado = True
        a.comparar = True
    p = a.presentacion

    try:
        with open(a.programa, encoding='utf-8-sig') as f:
            texto = f.read()
    except OSError as e:
        print(f'No se pudo abrir el programa: {e}')
        return 2

    if p:
        mostrar_programa(a.programa, texto)
        pausa(p)

    r = compilar(texto)

    if a.tokens:
        mostrar_tokens(r)
        pausa(p)

    if r.errores.hay_errores():
        titulo('ERRORES DE COMPILACIÓN')
        r.errores.imprimir()
        n = len(r.errores.errores)
        print(f'\nSe encontraron {n} error(es). El programa no se ejecuta.')
        return 1

    if a.arbol:
        mostrar_arboles(r)
        pausa(p)
    if a.traza:
        mostrar_traza(r)
        pausa(p)
    if a.tabla:
        mostrar_tabla(r)
        pausa(p)
    if a.cuadruplos:
        mostrar_cuadruplos(r, a.direcciones)
        pausa(p)
    if a.tripletas:
        mostrar_tripletas(r)
        pausa(p)

    opt, bitacora = optimizar(r.cuadruplos, r.tabla)
    if a.optimizado:
        mostrar_optimizado(r, opt, bitacora, a.direcciones)
        pausa(p)

    if a.no_ejecutar:
        print('\nCompilación correcta (sin errores).')
        return 0

    codigo = r.cuadruplos if a.sin_optimizar else opt
    titulo('EJECUCIÓN (intérprete NetGuard)' + (' · código sin optimizar' if a.sin_optimizar else ''))
    try:
        vm, err = ejecutar(codigo, a.programa, a.registro)
    except ErrorNetGuard as e:
        print(e)
        print('La ejecución se detuvo.')
        return 1
    for c, l, m in err.advertencias:
        print(f'Advertencia [{c}] línea {l} del registro: {m}')
    escribir_reporte(a.reporte, a.programa, vm, err, not a.sin_optimizar)
    print(f'\nReporte guardado en {a.reporte}')

    if a.comparar:
        pausa(p)
        titulo('COMPARACIÓN: código original vs optimizado')
        vm_o, _ = ejecutar(r.cuadruplos, a.programa, a.registro, salida=lambda s: None)
        vm_p, _ = ejecutar(opt, a.programa, a.registro, salida=lambda s: None)
        iguales = vm_o.lineas == vm_p.lineas
        print(tabla_texto(['Versión', 'Cuádruplas', 'Cuádruplos ejecutados'], [
            ['Sin optimizar', str(len(r.cuadruplos)), str(vm_o.ejecutados)],
            ['Optimizado', str(len(opt)), str(vm_p.ejecutados)],
        ]))
        ahorro = vm_o.ejecutados - vm_p.ejecutados
        if vm_o.ejecutados:
            print(f'Se ejecutan {ahorro} cuádruplos menos '
                  f'({100 * ahorro / vm_o.ejecutados:.1f} % menos trabajo).')
        print('Los dos reportes son ' + ('IGUALES: la optimización no cambió el resultado.' if iguales
                                          else 'DIFERENTES (revisar).'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
