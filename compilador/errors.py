# -*- coding: utf-8 -*-
"""
errors.py - Manejador de errores de NetGuard (documento, secciones 8.4 y 14).

Todas las fases (léxico, sintáctico, semántico e intérprete) reportan aquí sus
errores con un código y el número de línea. Si al terminar la compilación hay
errores, el programa NO se ejecuta.

Códigos:
  L01  Carácter no válido                      (léxico)
  L02  Cadena sin cerrar                       (léxico)
  P01  Error de sintaxis: token inesperado     (sintáctico)
  P02  Fin de archivo inesperado               (sintáctico)
  S01..S09  Errores semánticos (tabla 8.4 del documento)
  R01  Archivo de registro no encontrado       (ejecución)
  R02  Línea inválida en el archivo de registro (advertencia de ejecución)
  R03  División entre cero                     (ejecución)
"""

DESCRIPCIONES = {
    'L01': 'Carácter no válido',
    'L02': 'Cadena sin cerrar',
    'P01': 'Error de sintaxis',
    'P02': 'Fin de archivo inesperado',
    'S01': 'Variable no declarada',
    'S02': 'Redeclaración en un ámbito visible',
    'S03': 'Tipos incompatibles en asignación',
    'S04': 'Tipos incompatibles en operación',
    'S05': 'Condición no booleana',
    'S06': 'Asignación a solo lectura',
    'S07': 'Campo inexistente',
    'S08': 'IP fuera de rango',
    'S09': 'FOR EACH sobre algo que no es colección',
    'R01': 'Archivo de registro no encontrado',
    'R02': 'Línea inválida en el archivo de registro',
    'R03': 'División entre cero',
}


class ErrorNetGuard(Exception):
    """Error que detiene una fase (sintaxis o ejecución)."""

    def __init__(self, codigo, linea, mensaje):
        super().__init__(mensaje)
        self.codigo = codigo
        self.linea = linea
        self.mensaje = mensaje

    def __str__(self):
        return formato(self.codigo, self.linea, self.mensaje)


def formato(codigo, linea, mensaje):
    lugar = f'Línea {linea}' if linea else 'General'
    return f'[{codigo}] {lugar}: {mensaje}'


class ManejadorErrores:
    """Acumula errores y advertencias de todas las fases."""

    def __init__(self):
        self.errores = []        # (codigo, linea, mensaje)
        self.advertencias = []

    def error(self, codigo, linea, mensaje):
        self.errores.append((codigo, linea, mensaje))

    def advertencia(self, codigo, linea, mensaje):
        self.advertencias.append((codigo, linea, mensaje))

    def hay_errores(self):
        return bool(self.errores)

    def codigos(self):
        return [e[0] for e in self.errores]

    def imprimir(self, salida=print):
        for c, l, m in sorted(self.errores, key=lambda e: (e[1] or 0)):
            salida(formato(c, l, m))
        for c, l, m in self.advertencias:
            salida('Advertencia ' + formato(c, l, m))
