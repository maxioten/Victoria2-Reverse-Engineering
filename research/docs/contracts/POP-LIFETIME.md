# Ciclo de vida de POPs: rutina candidata a destructor

Perfil: `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferida base `0x00400000`; entrada VA `0x00955AE0`, RVA `0x00555AE0`.
El papel «destructor de POP» se interpreta por las llamadas y las secuencias de limpieza.
El nombre compilado `CPop` quedó vinculado a su vtable mediante [RTTI](RTTI.md);
los efectos de la función siguen limitados a las rutas comprobadas.

## Contrato observado

**confirmed para nueve fixtures:** recibe el objeto por el primer argumento de pila,
retorna mediante `RET 4`, preserva EBX, ESI, EDI y EBP y restaura el valor previo de FS:0.
Durante la ejecución escribe VA `0x00E36428` en el primer dword del objeto y después
VA `0x00E3A544`. La primera tabla está vinculada a `CPop`; la segunda aún no tiene
una atribución de clase confirmada por el mismo procedimiento.

Las pruebas ejecutan la rutina entera y las dos llamadas que alcanza esa ruta:
VA `0x00967F50` y `0x009C1650`. No sustituyen estas llamadas por stubs.
Ambas tablas globales en VA `0x01258A94` y `0x01258A98` se fijan a cero como condición
de entrada. La resolución del bloque `objeto+0x220` escribe cero en su primer dword.
Los dos campos siguientes se conservan en los casos probados.

## Estructuras candidatas y limpieza

Lectura estática y escrituras observadas sobre el objeto:

| Región | Efecto |
| --- | --- |
| `+0x14`, `+0x24`, `+0x28` | Primer byte a cero, longitud a cero y capacidad a 15 |
| `+0x22C`, `+0x23C`, `+0x240` | Primer byte a cero, longitud a cero y capacidad a 15 |
| Triples en `+0x104`, `+0xF4`, `+0xDC`, `+0xCC`, `+0xB4`, `+0xA4`, `+0x8C`, `+0x7C`, `+0x3C` | Compara primer dword con cero; si no es cero llama al wrapper de liberación; después escribe cero en los tres dwords |
| `+0x1D4` | Si es distinto de cero llama a `0x00955D40`; ruta excluida de la prueba |
| `+0x220` | Caché o puntero resuelto: termina a cero con las tablas globales ausentes |

**inferred:** las dos regiones con capacidad 15 son compatibles con cadenas con buffer
interno. Los triples son compatibles con buffers o vectores. No se dan por demostrados
los tipos STL originales, sus elementos ni sus invariantes completos.

Los casos usan longitudes de cadena 0, 1 y 15, combinadas con identificadores de la
región `+0x224` iguales a 0, `0x1268` y `0x1269`. Se comparan los 768 bytes del objeto
tras cada ejecución, incluidos los bytes de texto que el código no borra. El primer
byte se pone a cero; no se afirma que se borre todo el buffer.

## Entrada virtual sin liberación

**confirmed para 36 fixtures adicionales:** se ejecuta completo el wrapper de VA
`0x004A8230`, primer método de la tabla vinculada a `CPop`. Recibe `this` en ECX
y un argumento de pila. Con flags `0`, `2`, `0x100` y `0xFFFFFFFE`, cuyo bit inferior
es cero, llama al destructor, devuelve el puntero original en EAX y termina mediante
`RET 4`. Conserva EBX, ESI, EDI y EBP y restaura FS:0. Cada flag se cruza con las
nueve combinaciones anteriores y se compara el objeto completo de 768 bytes.
No se alcanza ninguna llamada al wrapper de liberación. Las instrucciones del test
del bit, las llamadas y el retorno se contrastan además en el inventario RTTI.

El caso con bit inferior uno sigue excluido: una ejecución de esta ruta necesita
un heap válido y comprobar la liberación real. Esta prueba no demuestra que el
objeto siga siendo utilizable después de destruirlo.

## Reproducción y límites

Desde la raíz, cargar `research/env.sh` y ejecutar
`python research/scripts/verify_pop_destructor.py`.
Reverify comprueba ocho instrucciones. Unicorn conserva trazas de escrituras al objeto,
verifica llamadas alcanzadas y restaura la cadena de excepciones sintética.
Recibos: `evidence/generated/pop-destructor/{claims.json,reverify.json,emulation.json}`.

El harness utiliza FS:0 sintético y contenedores vacíos, cadenas internas de capacidad
15, puntero opcional nulo y tablas de resolución ausentes. Las rutas de liberación,
elementos contenidos, tablas vivas y desenrollado de excepciones se excluyen.
No prueba un destructor ejecutado sobre un POP real ni todo su grafo de efectos.

Una [prueba nativa PE32 independiente](NATIVE-POP.md) amplía la evidencia a 134 casos
sintéticos de la lista, con buffers no vacíos, referencias a regimientos y un heap real:
632 liberaciones exitosas y 192 comparaciones previas a liberar. Declara por separado las relocaciones
de carga, la instrumentación de HeapFree y los límites de esa ejecución.

## Relación con la lista

La rutina VA `0x004BE8D0` desconecta enlaces antes de llamar a esta entrada y después
llama al wrapper de liberación VA `0x00AAE91B`. Su ruta diferida marca el nodo sin
desconectarlo. Ver [selección y recorrido](POP-SCHEDULE.md).
El consumidor de la marca `+0x280` y la eliminación durante iteraciones siguen pendientes.
