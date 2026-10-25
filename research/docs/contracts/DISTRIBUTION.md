# Normalización de distribuciones enteras

Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Entrada VA `0x004BE780`, RVA `0x000BE780`, base preferida `0x00400000`.
El nombre operativo «normalización» es **inferred** de los efectos comprobados.

## Layout y efectos observados

**confirmed en 525 casos completos:** recibe un descriptor por el primer argumento
de pila. Lee el comienzo del vector en `descriptor+8` y el final en `descriptor+0x0C`;
la diferencia se divide por ocho. La casilla 0 se conserva y se excluye de la suma.
Si no hay casillas posteriores, no escribe el vector ni llama a los helpers.

La rutina suma las casillas posteriores en dos acumuladores de 64 bits, combina sus
resultados y, cuando su condición de entrada permite continuar, transforma cada casilla.
Para cada valor bruto `x` y suma bruta `S`, el modelo operativo del resultado usa:

```text
p = (x * 0x320000) módulo 2^64
resultado = división_con_signo_truncada_hacia_cero(signed64(p), signed64(S))
```

El código realiza un desplazamiento aritmético de 15 bits tras multiplicar y vuelve
a desplazar a la izquierda antes de dividir. El producto por `0x320000` tiene sus 15
bits inferiores a cero, de modo que ese par de desplazamientos recupera su patrón
de bits. Entre ambos pasos escribe el valor intermedio en el vector.

Se comprobaron las cuatro escrituras de 32 bits de cada casilla: mitad alta y baja
del intermedio, y después mitad baja y alta del resultado final. Estas escrituras
intermedias no se deben ignorar al razonar sobre observadores concurrentes.

## Caso habitual y contraejemplos

**inferred dentro del modelo y sin overflow:** `0x320000 = 100 * 32768`; con pesos
no negativos, suma representable y numeradores que no desborden el entero con signo,
la fórmula corresponde a porcentajes con 15 bits fraccionales. Las divisiones pueden
dejar un resto de redondeo; no se obliga al total final a ser exactamente 100.
Ejemplo original comprobado: `[999, 1, 2, 3]` produce
`[999, 546133, 1092266, 1638400]`, cuyo total posterior a la casilla 0 es 3276799.

**confirmed, caso sintético extremo:** no es correcto sustituir sin condiciones el
guard por `signed64(S)>0`. Para
`[999, INT64_MIN, 0, INT64_MIN + 2^32]`, la suma modular es `2^32`, pero el `ADC`
final tiene overflow y la secuencia `JS/JG/comparación baja` deja el vector intacto.
También hay vectores positivos grandes cuyos productos se desbordan y terminan a cero.
No se ha observado que estos estados extremos aparezcan en una partida real.

## Pruebas y llamadores

`scripts/verify_distribution.py` ejecuta la rutina completa, incluidas las llamadas
originales a `0x00AC9F20` y `0x00AC02A0`. Compara el resultado contra
`scripts/distribution_model.py`, la casilla 0, descriptor, canarios, registros no volátiles,
orden de llamadas y escrituras. 525 fixtures: casos extremos y dos series deterministas
de tamaños 0 a 64; 238 entran en el camino de normalización; cero discrepancias.

Reverify contrasta 39 instrucciones: cálculo y guard, helpers, 18 sitios CALL
identificados y ocho instrucciones de preparación de argumentos. Los contextos de
las 18 llamadas están en `evidence/generated/distribution/callers_be780.txt`.
Los sitios de `0x00958DF0` pasan direcciones relativas a EDI `+0x74`, `+0x9C`,
`+0xC4` y `+0xEC`. Esto confirma las instrucciones, no el tipo de EDI en todas las rutas.
Las etiquetas externas «ideologías» e «issues» de algunas regiones siguen siendo pistas
para contrastar con serialización y ejecución.

Recibos: `evidence/generated/distribution/{claims.json,reverify.json,emulation.json}`.
Reproducción desde la raíz: cargar `research/env.sh`, después
`python research/scripts/verify_distribution.py`.
No se prueban punteros inválidos, alias, modificaciones concurrentes ni todo el engine.
