# Expansión del vector de POP: capacidad y heap nativo

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Las VA siguientes corresponden a base preferida `0x00400000`; RVA = VA − base.
Continúa el contrato de [append con capacidad libre](POP-APPEND.md).

## Capacidad: comprobación estática y ejecución limitada

Reverify contrasta 16 instrucciones adicionales. Unicorn ejecuta el cuerpo original
de `0x004BEDE0` en 584 fixtures hasta una de tres fronteras: retorno normal,
entrada de reserva `0x004BF200` o entrada del error de longitud `0x00AAD3AD`.
Se detiene antes de ejecutar esos dos callees; no fabrica sus resultados.

Para descriptores alineados de los tamaños positivos comprobados:

```
necesario = tamaño + 1
si necesario <= capacidad: no reserva
si necesita reservar: nueva_capacidad = max(necesario, capacidad + capacidad/2)
```

La división por dos es entera. El código contiene además comprobaciones contra
`0x67B239/0x67B23A` y una alternativa para evitar el crecimiento geométrico cuando
superaría el máximo. Los spans de puntero se restan en 32 bits y la división por
632 usa aritmética con signo. No se interpreta el máximo codificado como prueba
de que exista un vector válido de ese tamaño o una reserva exitosa de casi 4 GiB.

La matriz incluye tamaños 0..3, valores impares, hasta tres millones y el borde
positivo de signed32 dividido por 632; añade 512 descriptores con direcciones
envueltas y doce spans sintéticos alrededor de `0x80000000/0xFFFFFFFF`. Esos
últimos casos contrastan sólo selección de capacidad y frontera de error, no la
validez de un contenedor ni la entrega de una excepción.

## Expansión nativa: 126 casos completos

**confirmed para los fixtures declarados:** PE32 ejecutado por Wine wow64, con
imagen privada en `0x30000000`, delta `0x2FC00000` y 249.412 relocaciones HIGHLOW.
El loader procede del banco de vida de POP y no ejecuta entrada, TLS ni
inicialización del engine. Se protegen las secciones de código RX.

El banco llama al append original `0x004BEB50` con tamaño igual a capacidad,
cruzando tamaños 0, 1, 2, 3, 5, 8 y 16; origen externo o cada posición válida del
vector, y patrones de reserva `0`, `0x5A`, `0xFF`. Para tamaño cero begin/end/capacity
son nulos. Son 126 casos, con:

- 126 llamadas originales a HeapAlloc a través del CRT, con tamaño comprobado;
- 123 llamadas originales a HeapFree, porque los tres vectores iniciales nulos no liberan bloque;
- 123 comparaciones completas del bloque antiguo justo antes de liberarlo;
- comparación de todos los bytes del bloque nuevo, incluida capacidad todavía sin usar;
- comprobación del descriptor, puntero devuelto, dos cachés globales, origen externo y FS:0 nativo.

Los callbacks de IAT llaman realmente a HeapAlloc/HeapFree. Después de una reserva
exitosa se llena el bloque devuelto con el patrón declarado para distinguir los
bytes escritos de los conservados. Eso prepara el almacenamiento sin inicializar;
no sustituye cálculos, constructores, destructores ni resultados del heap.

## La expansión no es memcpy

El camino observado es:

```
4BEDE0 → 4BF200 → 4BF4C0 → CRT/new → HeapAlloc
                   ↓
                 4C0AF0 → 955450 para cada elemento anterior
                   ↓
                 4BE400 → destructor virtual con flag cero
                   ↓
                 CRT/free → HeapFree del array antiguo
                   ↓
                 actualiza begin/end/capacity
```

La copia de cada elemento anterior pasa por el mismo constructor selectivo del
contrato POP-APPEND: reinicia contadores y referencias y toma la identidad de los
globals. El banco compara exactamente esos efectos en el bloque nuevo. El bloque
antiguo se compara después de sus destructores y antes de liberarlo; comprueba
también que en ese momento el descriptor aún apunta al bloque antiguo.

Cuando el origen de append pertenecía al vector, se recalcula desde el índice y
el nuevo begin después de crecer. El elemento añadido se compara con la copia
esperada. No se sigue usando un puntero al bloque ya liberado en esos fixtures.

**inferred:** esta semántica encaja con colecciones temporales especializadas;
el banco no demuestra que sean el almacén principal de todos los POP de una partida.
No se extrapola este layout de contenedor a cualquier lista de POP ni se propone
reemplazarlo por una copia de bytes sin estudiar sus llamadores.

## Ampliación: ocho buffers internos con datos

La segunda fase conserva los 126 casos anteriores y añade **120 casos nativos**
con catálogos todavía vacíos y vectores internos poblados. El recibo combinado
de esa fase contiene 246 casos, **2.946 HeapAlloc**, **2.151 HeapFree** y 2.151
comprobaciones de contenido justo antes de liberar. La primera versión de fuentes,
ejecutable y recibos está conservada en `native-growth/baseline-empty-126/`.

Los casos nuevos cruzan tamaño anterior 0..3, origen externo o cada elemento
anterior, tres patrones de almacenamiento y cuatro perfiles de distribución:

| Perfil | Longitud lógica de los ocho buffers |
| --- | --- |
| 1 | todos uno |
| 2 | todos tres |
| 3 | todos siete |
| 4 | `(0,1,3,7,0,1,3,7)` |

Los descriptores de ocho bytes de elemento están en `+0x7C/+0xA4/+0xCC/+0xF4`;
los de cuatro, en `+0x8C/+0xB4/+0xDC/+0x104`. Cada buffer de origen reserva dos
elementos adicionales con contenido conocido. En el perfil mixto, incluso los
rangos lógicos vacíos tienen begin no nulo y capacidad existente.

**confirmed dentro del dominio:** los copiadores originales reservan buffers de
destino independientes y copian únicamente los elementos lógicos. En los destinos
recién construidos capacity y end quedan iguales. Para longitud cero no reservan
un buffer de destino, aunque el origen tenga capacidad. El modelo comprueba las
ocho ternas de punteros, todo el payload y cada byte lógico de los buffers nuevos.
No basta con que los valores numéricos copiados coincidan: también comprueba que
las reservas nuevas vivas tengan punteros distintos y que no sean los buffers del origen externo.

Los destructores recorren los elementos antiguos en orden ascendente. Dentro de
cada elemento liberan buffers en offsets
`+0x104,+0xF4,+0xDC,+0xCC,+0xB4,+0xA4,+0x8C,+0x7C` antes de liberar el array.
Cada callback contrasta puntero, orden y contenido completo del buffer solicitado,
incluidos sus dos elementos de capacidad sobrante. El snapshot final del array
antiguo contrasta que sus descriptores fueron puestos a cero. El descriptor del
contenedor continúa apuntando al array antiguo en esos callbacks.

Cuando el origen de append era un elemento del mismo vector, el nuevo elemento
recibe otra copia profunda desde el elemento ya reubicado. Las dos copias mantienen
reservas distintas mientras están vivas. El allocator puede reutilizar direcciones
de buffers antiguos que ya liberó; no se interpreta esa reutilización legítima
como un alias entre reservas vivas. Los buffers y el payload del origen externo
permanecen intactos.

Las liberaciones manuales de limpieza del banco se mantienen fuera de los conteos
de llamadas originales. No se prueban aquí destructores finales de los nuevos
elementos: se comprueban sus contenidos y se limpian explícitamente sus reservas.

La [fase posterior con catálogos no vacíos](POP-CATALOG-COPY.md) añade 216 casos:
el recibo de esa fase contiene 462 casos, 6.858 reservas y 4.635 liberaciones.
Los límites de los 126/120 casos anteriores se mantienen como dominios separados.

## Fronteras declaradas

En las dos primeras fases, los POP de prueba no están registrados, el recurso `+0x1D4` es nulo, los registros
globales están ausentes y los catálogos existen pero están vacíos. Los ocho
vectores internos son nulos en los 126 casos iniciales, o tienen los cuatro
perfiles y capacidades de la ampliación. Los elementos tienen vtable original y
condiciones válidas para los destructores de ese dominio.

Los catálogos poblados se contrastan en la fase enlazada, con invariantes declaradas.
El [constructor con tipo con catálogos](POP-CONSTRUCTION.md) tiene después 192
ciclos nativos propios. Faltan referencias externas a elementos
reubicados, identidades registradas, recursos opcionales, fallos de heap, límites
de longitud ejecutando el throw, excepciones y concurrencia. La ejecución nativa
de esta fase valida reservas pequeñas exitosas; los descriptores grandes sólo se
usan en el chequeo de selección de capacidad que se detiene antes de reservar.

## Reproducción

```bash
source research/env.sh
python research/scripts/verify_pop_growth.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Wine debe ejecutarse en el host con el prefijo dedicado ya preparado. Fuentes:
`harnesses/native_pop_growth.c` y `harnesses/native_private_image.h`. Recibos:
`evidence/generated/pop-growth/` y `evidence/generated/native-growth/`. Cada intento
nativo conserva fuentes, salida y resultado. El gate comprueba hashes del código,
loader, ejecutable, builder, runner y stdout/stderr del recibo nativo aprobado;
declara `fresh_execution_this_gate:false`, pues no vuelve a ejecutar Wine.
