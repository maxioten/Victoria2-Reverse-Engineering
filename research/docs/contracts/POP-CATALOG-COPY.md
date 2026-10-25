# Metadatos de catálogo en la copia de POP

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Continúa las pruebas de
[expansión y copia profunda](POP-GROWTH.md).

**confirmed para 216 casos nativos nuevos:** el constructor de copia
`0x00955450` reconstruye prefijos de los vectores de cuatro bytes a partir de dos
catálogos globales, después de copiar las distribuciones. No conserva siempre los
metadatos del origen aunque éste tenga buffers con datos y capacidad suficiente.

| Global y rango del catálogo | Campo de cada entrada | Buffers de destino escritos |
| --- | --- | --- |
| `0x01258A3C`, begin/end `+0x0C/+0x10` | dword `+8` | `+0x8C`, `+0xDC` |
| `0x01258A48`, begin/end `+0x18/+0x1C` | dword `+0x30` | `+0xB4`, `+0x104` |

Las longitudes se obtienen de la diferencia de punteros dividida por cuatro.
Las entradas se recorren en orden del array del catálogo. Las dos cabeceras,
arrays y conjuntos de entradas de los fixtures son distintos; no se presupone
que estos globals sean alias en el engine. No se asignan nombres de gameplay a
los catálogos ni a los dwords de metadatos.

## Matriz y resultados

La matriz cruza longitudes `(A,B)` de `(1,3),(3,1),(7,3),(3,7),(0,3),(3,0)`;
vectores fuente con longitud igual a su catálogo o dos elementos lógicos más;
tamaños anteriores del contenedor 0..2; origen externo o cada posición anterior;
y tres patrones de almacenamiento. Los ocho buffers de cada fuente tienen además
otros dos elementos de capacidad sobrante. Todos los buffers fuente son no nulos,
incluso para longitud lógica cero.

Los metadatos fuente contienen patrones deliberadamente distintos de las entradas
del catálogo. El oráculo comienza con su copia literal y sustituye sólo el prefijo
indicado por el catálogo. Se contrastan **5.712 palabras de metadatos** en los
destinos finales, el resto de sus buffers y el payload completo. Las reservas de
destino tienen la longitud lógica de la fuente, no la longitud del catálogo.

Cuando la fuente contiene dos elementos lógicos adicionales, sus dwords posteriores
al prefijo se conservan por copia. Es distinto de los dos elementos fuera de end,
que sólo son capacidad y no se copian. Si el catálogo está vacío y la fuente tiene
elementos lógicos, todo ese rango lógico se copia sin reconstrucción de metadatos.

El resultado se mantiene cuando el origen de append pertenece al vector: primero
se reubica el elemento y después se copia al nuevo slot. El catálogo y el origen
externo se comparan completos después de la llamada y permanecen intactos. Los
buffers antiguos se contrastan al liberarlos, incluidos los bytes de capacidad.

Al cerrar esta fase, el banco combinado contenía **462 casos**, **6.858 reservas** y **4.635
liberaciones originales**, con snapshot antes de cada liberación. De esos casos,
126 usan vectores nulos y catálogos vacíos; 120 tienen buffers con datos y catálogos
vacíos; los 216 nuevos cubren los catálogos declarados. Las fuentes y recibos de la
fase anterior están en `native-growth/baseline-populated-246/`.

## Qué permanece abierto

Los fixtures mantienen la longitud lógica de cada vector al menos igual a la de
su catálogo. **hypothesis pendiente:** esa relación forma parte de las invariantes
requeridas por estos bucles; no se valida aquí un catálogo más largo que el buffer
ni se concluye cómo el juego lo impediría. Tampoco se confunde un fixture con dos
elementos lógicos sobrantes con una combinación necesariamente alcanzable jugando.

Se ejecutan copia y expansión, no el constructor con tipo `0x00954F40` con estos
catálogos poblados. Sus bucles análogos sólo tienen instrucciones contrastadas en
esta fase. La [fase posterior de construcción](POP-CONSTRUCTION.md) ejecuta 192
ciclos del constructor con tipo y destructor con catálogos poblados y modos de caché.
Quedan pendientes recursos opcionales, registro vivo,
fallo de heap, límites, excepciones, referencias externas y concurrencia.

## Reproducción

```bash
source research/env.sh
python research/scripts/verify_pop_growth.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

El recibo combinado está en `evidence/generated/native-growth/execution.json`.
Los campos por caso incluyen longitudes de ambos catálogos y sobrante lógico.
Reverify añade ocho instrucciones de los bucles de copia/construcción a las 16 de
expansión. Verificar esos bytes no demuestra que se haya ejecutado el constructor
por defecto con catálogo poblado. El gate enlaza por hashes el recibo nativo y sus
fuentes; no vuelve a ejecutar Wine por sí mismo.
