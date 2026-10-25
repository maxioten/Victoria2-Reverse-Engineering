# Factory de nodos CPop: lista, región e identidad

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Imagen privada nativa
`0x30000000`, delta de relocación `0x2FC00000`.

**confirmed para 1.053 ciclos nativos completos:** `0x004B8D30(propietario,tipo)`
retorna con RET 8 y EAX = nodo nuevo. Después se ejecuta el unlink original
`0x004BE8D0` sobre ese nodo, con limpieza y liberación reales. No se parchean
funciones ni se fabrican resultados de callees o métodos virtuales.

## Secuencia de construcción observada

1. `0x004B8C80` selecciona el tipo. En el dominio probado, `tipo+0x3D4` apunta a
   un fixture de `CNullPopType` y su predicado virtual original devuelve cero;
   el selector conserva el tipo solicitado.
2. Construye un CPop temporal con `0x00954A40`, que obtiene su tipo inicial del
   getter `0x0096BB70` y del global `0x01258A2C`, ya no nulo.
3. Selecciona una cabecera de lista de 16 bytes en
   `*(propietario+0x194) + (tipo+0x28)*16`.
4. Reserva `0x288` = 648 bytes mediante el CRT original, copia el temporal con
   `0x00955450` y añade el nodo al final de la lista.
5. Destruye el temporal, prepara una clave explícita y llama al método virtual
   `CPop.vtable+0x18`, que apunta al registro `0x009C1390` original.
6. Establece el tipo con `0x00955D90` y la región con `0x00955F20`.

El nodo final tiene tamaño de población cero, tipo solicitado y `+0x64` igual al
propietario. Se comparan sus 648 bytes completos antes de retirarlo. No se confunde
este resultado con la ejecución del consumidor que después carga datos en el nodo.

## Payload y metadatos de lista

| Región | Efecto contrastado |
| --- | --- |
| `+0..+0x277` | payload CPop de 632 bytes, conforme al constructor de copia y setters del dominio |
| `+0x278` | puntero al anterior tail, o cero |
| `+0x27C` | puntero siguiente cero |
| byte `+0x280` | marca inicial cero |
| `+0x281..+0x287` | conserva el patrón de reserva; no se atribuye significado |

Se cruzan listas anteriores de cero, uno y dos nodos, con tres índices de tipo.
El factory actualiza head si la lista estaba vacía, tail, contador y next del
tail anterior. Se contrastan las tres cabeceras completas y todos los bytes de
los nodos previos. Los demás buckets permanecen intactos.

## Identificador dedicado y registro

La clave nueva es `(0x2E, valor anterior del global 0x00F09568)`. El factory
escribe `contador = valor anterior + 1` con wrap de 32 bits antes de la llamada
virtual de registro. Los fixtures cruzan semillas
0, 1, 0x7FFFFFFF, 0x80000000 y 0xFFFFFFFF; con esta última, la clave conserva
0xFFFFFFFF y el contador termina en cero.

El contador automático genérico `0x01258A9C` no cambia en estos casos. La llamada
virtual introduce un enlace real de ocho bytes y deja el byte de registro activo
en uno. Se comprueban clave completa, selección de tabla B, bucket, contador y
contenido del enlace. Las tablas tienen 1/3/7 buckets y comienzan vacías por fixture;
no se afirma unicidad a través de un wrap con claves antiguas todavía vivas.

Los enlaces vtable/RTTI se contrastan por bytes: el slot de registro de CPop
apunta a `0x009C1390`; `CPopType` usa vtable `0x00E365F8` y `CNullPopType`,
`0x00E36618`. En esta última, el slot `+0x18` llama a `0x0058CFD0`, cuyo cuerpo
original pone AL a cero y retorna. Son fixtures de tipos con vtables originales,
no implementaciones sustitutas del predicado.

## Retirada y liberaciones

El unlink repara los enlaces y después destruye el nodo. El destructor libera
primero sus buffers de distribución, en orden inverso de los ocho offsets
`0x7C,0x8C,0xA4,0xB4,0xCC,0xDC,0xF4,0x104`. Después retira su
registro y libera el enlace de ocho bytes. En ese callback se comprueba
head ya desvinculado y contador de registro todavía uno. Después se libera el
nodo de 648 bytes, con snapshot completo de su payload destruido y metadatos.
El contador de la lista baja después de liberar el nodo.

Las listas y los nodos previos vuelven exactamente al estado inicial. El handle
de clave `(0x2E,semilla)` resuelve el nodo recién creado y devuelve/almacena cero
después de retirarlo. El banco no lee el nodo después de liberarlo.

Con catálogos vacíos, cada caso aporta dos HeapAlloc y dos HeapFree originales.
Con D buffers de distribución activos, aporta `2D+2` de cada uno: D del temporal,
el nodo de 648 bytes, D copias profundas del nodo y el enlace de registro.
El temporal libera sus D buffers en orden inverso antes de registrar el nodo.
Se contrastan los datos cero, los prefijos reconstruidos desde los catálogos y
las capacidades lógicas exactas de las dos copias; cada buffer se compara antes
de liberarse y no se vuelve a leer después. Se comparan además los descriptores
del nodo completo y sus buffers antes de retirarlo. El propietario completo,
los tipos y el bloque de catálogos se comparan antes y después y permanecen intactos;
las cabeceras de lista y registro son almacenamiento externo que sí cambia.
Se conserva FS:0 nativo y se guarda/restaura FX, con CW inicial `0x037F`.

## Dos variantes de constructor

Se corrige una etiqueta anterior: `0x00954F40` recibe el tipo en EDX; se describe
ahora como **constructor con tipo**. El factory usa `0x00954A40`, cuya entrada
recibe sólo destino en stack y obtiene `CNullPopType` desde el getter global.
Estas son convenciones observadas, no declaraciones recuperadas del C++ original.
Las pruebas previas de la variante con tipo conservan su alcance y resultados.

## Dominio, matriz y reproducción

La matriz es índice de tipo 0/1/2 × longitud anterior 0/1/2 × cinco semillas de ID
× buckets 1/3/7 × tres patrones 0/0x5A/0xFF = **405 casos**. Se ejecutan selector,
constructor temporal, copia, métodos virtuales, setters, registro, unlink y destructor
originales, usando HeapAlloc/HeapFree reales con snapshots.

Otros **648 casos** cruzan catálogos A/B `(1,3),(3,1),(7,3),(3,7),(0,3),(3,0)`
× tres índices de tipo × tres longitudes anteriores × semillas 0/0xFFFFFFFF
× buckets 1/7 × tres patrones de reserva. La fase añade 9.936 reservas y
liberaciones originales y 14.688 palabras de metadatos contrastadas entre las
dos copias. Los intentos fallidos se conservan en `native-growth/attempt-*/`:
el primer modelo esperaba liberar el registro antes de las distribuciones;
el callback observó el último buffer de 12 bytes de la copia del nodo primero
(índice de reserva 16 con A=1/B=3). Esa expectativa quedó refutada y se corrigió
el orden, conservando comprobaciones exactas de puntero, contenido y cabecera.

Singletons y tipo nulo ya disponibles, banderas de tipo `+0x40`
y `+0x39C` cero. Las cachés declaradas tienen bits no cero y no se presupone que
representen objetos de una partida. Los nodos anteriores de lista son fixtures no
registrados. Se excluyen la rama de selección alternativa con estadísticas,
recurso opcional, lazy init, fallos, excepciones y concurrencia.
La fase posterior [del consumidor completo](POP-CONSUMER.md) valida su ruta de
nodo nuevo con árboles existentes. Sus demás ramas y un tick real siguen abiertos.

El banco combinado suma al cerrar esta fase **2.991 casos**, **23.964 reservas** y
**21.693 liberaciones** con snapshot; se contrastan 27.072 palabras de catálogos.
La fase anterior de 2.343 casos queda conservada en
`native-growth/baseline-factory-2343/`.

```bash
source research/env.sh
python research/scripts/verify_pop_factory.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Reverify contrasta 43 instrucciones/enlaces/RTTI; la evidencia de ejecución es
independiente en `native-growth/execution.json`, `entry: pop_factory_lifecycle`.
El gate vincula fuentes y recibos por hash y no vuelve a ejecutar Wine al consultar
el recibo. La consulta `queries/query_b8d30.txt` conserva pseudocódigo auxiliar de
Ghidra; no se trata como fuente original ni como prueba de ejecución por sí sola.

La ampliación del [selector interno](FACTORY-INTERNAL-SELECTOR.md) añade otros
960 factories completos con retirada, incluyendo 216 cambios de tipo/bucket.
Es una matriz distinta de los 1.053 ciclos originales de este contrato; no
extiende sus catálogos poblados a esa rama alternativa.
