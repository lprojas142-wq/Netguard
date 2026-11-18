# -*- coding: utf-8 -*-
"""
pruebas.py - Pruebas automáticas de NetGuard.

Comprueba que el compilador produce exactamente lo que dice el documento
(cuádruplas, tripletas, tabla de símbolos, optimización y reporte) y que cada
archivo de ejemplos/errores provoca el error que indica su nombre.

  python pruebas.py
"""
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

from compilador import compilar, optimizar, MaquinaVirtual, ManejadorErrores, ErrorNetGuard  # noqa: E402
from compilador.codegen import a_tripletas  # noqa: E402

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):
    pass

EJ = os.path.join(AQUI, 'ejemplos')
resultados = []


def prueba(nombre, condicion, detalle=''):
    resultados.append(condicion)
    print(f"  [{'OK' if condicion else 'FALLO'}] {nombre}" + (f'  -> {detalle}' if not condicion and detalle else ''))


def leer(ruta):
    with open(ruta, encoding='utf-8') as f:
        return f.read()


def ejecutar(cuads, ruta_ng, registro=None):
    err = ManejadorErrores()
    vm = MaquinaVirtual(cuads, err, base_dir=os.path.dirname(ruta_ng), registro=registro,
                        salida=lambda s: None)
    vm.ejecutar()
    return vm, err


def texto(cuads):
    return [str(c) for c in cuads]


# ---------------------------------------------------------------------------
print('\n1. Programa de la Fase 1 (secciones 11, 12 y 13 del documento)')
ruta = os.path.join(EJ, 'reglas.ng')
r = compilar(leer(ruta))
prueba('compila sin errores', not r.errores.hay_errores(), r.errores.errores)

esperadas = [
    '(=, 5, —, maxAttempts)', '(=, 500.0, —, trafficLimit)',
    '(LOAD, "red_laboratorio.log", —, traffic)', '(FE_INIT, traffic, —, —)',
    '(FE_NEXT, traffic, event, t1)', '(GOTOF, t1, —, 17)', '(=, false, —, suspicious)',
    '(>=, event.failedAttempts, maxAttempts, t2)', '(>, event.trafficMB, trafficLimit, t3)',
    '(OR, t2, t3, t4)', '(GOTOF, t4, —, 15)', '(=, true, —, suspicious)',
    '(ALERT, "Evento sospechoso", event.sourceIP, —)', '(GOTO, —, —, 16)',
    '(MARK, event, "normal", —)', '(GOTO, —, —, 5)', '(END, —, —, —)']
prueba('17 cuádruplas iguales a la tabla 12.3', texto(r.cuadruplos) == esperadas, texto(r.cuadruplos))

trip = [' '.join(t) for t in a_tripletas(r.cuadruplos)]
prueba('tripletas iguales a la tabla 12.4',
       trip[5] == 'GOTOF (5) (17)' and trip[9] == 'OR (8) (9)' and trip[13] == 'GOTO (16) —', trip)

simbolos = {f[0]: (f[1], f[2], f[5]) for f in r.tabla.filas_simbolos()}
prueba('tabla de símbolos igual a la 11.3',
       simbolos.get('maxAttempts') == ('Global', 'int', '1000')
       and simbolos.get('traffic') == ('Colección', 'event[]', '5000')
       and simbolos.get('event') == ('Variable de ciclo', 'event', '2000')
       and simbolos.get('suspicious') == ('Local', 'boolean', '2001')
       and simbolos.get('t4') == ('Temporal', 'boolean', '3003'), simbolos)
constantes = [f[0] for f in r.tabla.filas_constantes()]
prueba('tabla de constantes 4000-4006',
       constantes == ['5', '500.0', '"red_laboratorio.log"', 'false', 'true', '"Evento sospechoso"', '"normal"'],
       constantes)
prueba('las cuatro pilas terminan vacías', r.pila.vacia())

opt, bitacora = optimizar(r.cuadruplos, r.tabla)
esperadas_opt = [
    '(LOAD, "red_laboratorio.log", —, traffic)', '(FE_INIT, traffic, —, —)',
    '(FE_NEXT, traffic, event, t1)', '(GOTOF, t1, —, 13)', '(>=, event.failedAttempts, 5, t2)',
    '(>, event.trafficMB, 500.0, t3)', '(OR, t2, t3, t4)', '(GOTOF, t4, —, 11)',
    '(ALERT, "Evento sospechoso", event.sourceIP, —)', '(GOTO, —, —, 3)',
    '(MARK, event, "normal", —)', '(GOTO, —, —, 3)', '(END, —, —, —)']
prueba('optimización 17 → 13 igual a la tabla 13.2', texto(opt) == esperadas_opt, texto(opt))

vm_o, _ = ejecutar(r.cuadruplos, ruta)
vm_p, _ = ejecutar(opt, ruta)
reporte = ['[ALERTA]  Evento sospechoso - origen 192.168.1.10',
           '[ALERTA]  Evento sospechoso - origen 192.168.1.25',
           '[MARCADO] 10.0.0.4 -> normal',
           'Eventos analizados: 3 | Alertas: 2 | Marcados: 1']
prueba('reporte igual al de la sección 14.3', vm_p.lineas == reporte, vm_p.lineas)
prueba('mismo reporte con y sin optimizar', vm_o.lineas == vm_p.lineas)
prueba('cuádruplos ejecutados 38 → 29 (11/9 → 8 por evento)',
       (vm_o.ejecutados, vm_p.ejecutados) == (38, 29), (vm_o.ejecutados, vm_p.ejecutados))

# ---------------------------------------------------------------------------
print('\n2. Expresión aritmética de la sección 10.1')
r = compilar(leer(os.path.join(EJ, 'riesgo.ng')))
cuads = texto(r.cuadruplos)
prueba('genera *, / y + en el orden de la pila semántica',
       '(*, event.failedAttempts, 2, t2)' in cuads and '(/, event.trafficMB, 100, t3)' in cuads
       and '(+, t2, t3, t4)' in cuads and '(=, t4, —, riesgo)' in cuads, cuads)
tipos = {t.nombre: t.tipo for t in r.tabla.temporales}
prueba('tipos: * int, / float, + float (promoción)',
       (tipos['t2'], tipos['t3'], tipos['t4']) == ('int', 'float', 'float'), tipos)

# ---------------------------------------------------------------------------
print('\n3. Todas las técnicas de optimización')
ruta = os.path.join(EJ, 'optimizacion.ng')
r = compilar(leer(ruta))
opt, bitacora = optimizar(r.cuadruplos, r.tabla)
tecnicas = {t for t, _ in bitacora}
for t in ('Plegado de constantes', 'Propagación de constantes', 'Simplificación algebraica',
          'Reducción de fuerza', 'Subexpresiones comunes', 'Eliminación de código muerto',
          'Movimiento de código invariante', 'Salto a salto'):
    prueba(t, t in tecnicas)
vm_o, _ = ejecutar(r.cuadruplos, ruta)
vm_p, _ = ejecutar(opt, ruta)
prueba('el resultado no cambia al optimizar', vm_o.lineas == vm_p.lineas)
prueba('se ejecutan menos cuádruplos', vm_p.ejecutados < vm_o.ejecutados, (vm_o.ejecutados, vm_p.ejecutados))

# ---------------------------------------------------------------------------
print('\n4. IF anidado (puertos.ng)')
ruta = os.path.join(EJ, 'puertos.ng')
r = compilar(leer(ruta))
opt, _ = optimizar(r.cuadruplos, r.tabla)
vm, _ = ejecutar(opt, ruta)
prueba('4 alertas y 3 eventos marcados', vm.lineas[-1] == 'Eventos analizados: 9 | Alertas: 4 | Marcados: 3',
       vm.lineas[-1])

# ---------------------------------------------------------------------------
print('\n5. Archivo de registro con líneas inválidas')
ruta = os.path.join(EJ, 'reglas.ng')
r = compilar(leer(ruta))
opt, _ = optimizar(r.cuadruplos, r.tabla)
vm, err = ejecutar(opt, ruta, os.path.join(EJ, 'registro_con_errores.log'))
prueba('3 líneas ignoradas con advertencia R02', [a[0] for a in err.advertencias] == ['R02'] * 3,
       err.advertencias)
prueba('se procesan las 2 líneas válidas', vm.eventos == 2, vm.eventos)

# ---------------------------------------------------------------------------
print('\n6. Errores (un archivo por código en ejemplos/errores)')
carpeta = os.path.join(EJ, 'errores')
for nombre in sorted(os.listdir(carpeta)):
    if not nombre.endswith('.ng') or nombre.startswith('varios'):
        continue
    codigo = nombre[:3]
    ruta = os.path.join(carpeta, nombre)
    r = compilar(leer(ruta))
    if codigo.startswith('R'):
        obtenido = None
        if not r.errores.hay_errores():
            opt, _ = optimizar(r.cuadruplos, r.tabla)
            try:
                ejecutar(opt, ruta)
            except ErrorNetGuard as e:
                obtenido = e.codigo
        prueba(f'{nombre} → {codigo}', obtenido == codigo, obtenido)
    else:
        codigos = r.errores.codigos()
        prueba(f'{nombre} → {codigo}', codigos[:1] == [codigo], codigos)

r = compilar(leer(os.path.join(carpeta, 'varios_errores.ng')))
prueba('varios_errores.ng reporta los 5 errores', r.errores.codigos() == ['S03', 'S06', 'S05', 'S04', 'S04'],
       r.errores.codigos())

# ---------------------------------------------------------------------------
total, bien = len(resultados), sum(resultados)
print(f'\nResultado: {bien} de {total} pruebas correctas.')
sys.exit(0 if bien == total else 1)
