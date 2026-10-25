# Copia de CPop con recurso opcional de origen

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Continúa la copia aislada
de [CGoodsPool](GOODS-POOL-COPY.md) dentro de la entrada completa de CPop.

**confirmed para 180 secuencias nativas completas:** constructor de copia
`0x00955450(destino,origen)`, RET 8 y EAX = destino, seguido del destructor
`0x00955AE0(destino)`, RET 4. El origen tiene `+0x1D4` no nulo y un recurso con
ambos pools y campos restantes deliberadamente diferentes de los valores iniciales.

## Resultado de la copia

| Parte del destino | Resultado contrastado |
| --- | --- |
| Recurso `+0x1D4` | reserva nueva de 256 bytes, construida por `0x00954910` |
| Primer pool | asignación original `0x0047DBB0` desde el primer pool del origen |
| Segundo pool, offset `+0x58` | conserva los valores iniciales del constructor de destino |
| Campos restantes `+0xB0..+0xFF` | conservan los valores inicializados o bytes de reserva del destino |

No se copian literalmente los 256 bytes del recurso. El segundo pool del origen
tiene longitudes 1/3/7, mapas y valores distintos; el destino conserva longitud
uno, mapa cero y el valor global inicial de ocho bytes. Los campos fuente restantes
tienen patrones diferentes, mientras el destino conserva sus ceros, constantes,
conversión x87 y agujeros del constructor. No se concluye un bug ni se les atribuye
función económica por intuición.

El constructor de copia pone inicialmente su puntero de recurso a cero. Si el del
origen es no nulo, reserva y construye el destino y llama una vez a la asignación
del primer pool. La condición observada de esta ruta es el puntero fuente; no se
extrapola el control del constructor con tipo mediante byte de tipo `+0x39C`
a esta otra entrada.

## Primer pool y reserva intermedia

La longitud del primer pool fuente se cruza con 0/1/2/7/16; el mapa copia
0/1/31/64 bytes. El primer elemento del destino proviene del constructor global,
no del primer elemento fuente. Para longitud cero, end retrocede a begin pero el
buffer inicial de capacidad uno sigue existiendo hasta la destrucción.

Con longitud mayor de uno, la copia reserva un buffer nuevo. Antes de liberar el
buffer inicial de ocho bytes se contrasta su contenido y se verifica que la terna
del recurso sigue apuntando a esa reserva. Después se compara el buffer nuevo
completo: primer elemento global retenido y elementos `1..n-1` procedentes del
origen. Se ejecutan los cuerpos originales y las APIs reales del heap.

La matriz completa es primer pool 0/1/2/7/16 × segundo pool 1/3/7 × mapa
0/1/31/64 × patrones de reserva 0/0x5A/0xFF. Son 180 casos: 72 con tres reservas
de destino y 108 con cuatro por la expansión del primer pool. Cada secuencia
libera las tres reservas finales y, cuando corresponde, la reserva intermedia.

## Comparaciones y límites

Se compara antes de destruir el payload CPop de 632 bytes, el recurso de 256 bytes
y sus buffers. En las liberaciones se comparan los datos de ambos pools y el
recurso después de poner a cero sus descriptores. Al terminar se compara de nuevo
el payload destruido. El origen completo, su recurso y los buffers fuente con
dos elementos de capacidad adicional permanecen intactos. El banco guarda/restaura
FX y comprueba FS:0 nativo alrededor de ambas entradas.

Los cuatro vectores de distribución de CPop están vacíos, los catálogos existen
pero tienen longitud cero en los 180 casos iniciales y los registros globales
están ausentes. Los campos
fuente son fixtures de bits, no un estado de partida demostrado alcanzable.
La ampliación siguiente combina distribuciones/catálogos poblados. Faltan registro
vivo, recursos con invariantes de gameplay reales, fallo de reserva, excepciones y
referencias externas. No se deduce seguridad paralela de objetos sintéticos.

La fase inicial añade 648 reservas y 648 liberaciones originales. El banco combinado
contiene al cerrarla **1.506 casos**, **10.518 reservas** y **8.247 liberaciones**
con snapshot previo. Las 1.326 observaciones anteriores y fuentes están
conservadas en `native-growth/baseline-pool-copy-1326/`.

## Ampliación con distribuciones y catálogos

**confirmed para 216 secuencias nativas combinadas:** la misma entrada de copia
y su destructor se ejecutan con los ocho buffers de distribución fuente no nulos,
catálogos A/B de longitudes `(1,3),(3,1),(7,3),(3,7),(0,3),(3,0)`, y recurso
opcional fuente con datos.

Se cruzan dos longitudes lógicas de distribución, iguales al catálogo o con dos
elementos adicionales; primer pool opcional de longitud 0/2/7, segundo de longitud
tres, mapa de 0/64 bytes y tres patrones de reserva. Los buffers fuente tienen
además dos elementos de capacidad sobrante. Donde catálogo y longitud lógica son
cero, begin sigue siendo no nulo en el origen; la copia no crea un buffer vacío
de destino por conservar esa capacidad.

El modelo comprueba en una misma secuencia las ocho ternas del destino, buffers
profundamente copiados, prefijos reconstruidos desde el catálogo, colas lógicas
conservadas y el bloque opcional completo. Los efectos de primer/segundo pool son
los de la fase inicial. Después comprueba contenido y orden de cada liberación:
segundo buffer opcional, primero opcional, recurso de 256 bytes y buffers de las
distribuciones en orden descendente de offsets. También se comprueba la liberación
intermedia al ampliar el primer pool opcional.

Se compara el payload completo antes y después de destruir. Origen, catálogos,
recurso fuente y todos sus buffers, incluidos los bytes fuera de end, permanecen
intactos. Las reservas de destino usan sus tamaños lógicos y se contrastan antes
de cada HeapFree real; los buffers fuente se limpian manualmente fuera del conteo
de llamadas originales. Los registros globales continúan ausentes.

Esta ampliación aporta **2.376 reservas y 2.376 liberaciones** y contrasta otras
2.448 palabras de metadatos. Al cerrarla, el banco combinado contiene **1.722 casos**,
**12.894 reservas**, **10.623 liberaciones** con snapshot y **12.384 palabras de
metadatos**. Los 1.506 casos anteriores y fuentes están conservados en
`native-growth/baseline-optional-copy-1506/`. Los nuevos casos usan
`entry: cpop_optional_copy_combined` y registran longitudes A/B y sobrante lógico.

Combinar los caminos no demuestra el estado de una partida, registro vivo,
referencias externas a objetos reubicados, errores, excepciones o concurrencia.
Esos límites se mantienen, aunque los efectos de copia y destrucción ya estén
contrastados juntos en los fixtures declarados.

## Reproducción

```bash
source research/env.sh
python research/scripts/verify_pop_optional.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Esta fase añade siete comprobaciones de instrucciones al verificador opcional:
inicialización del puntero, condición fuente, llamada de construcción y copia de
pool. La ejecución está en `native-growth/execution.json`,
`entry: cpop_optional_copy`, con ambos tamaños de pool y tamaño de mapa por caso.
El gate vincula por hash fuentes, ejecutable, runner y salida; no vuelve a ejecutar
Wine cada vez que consulta el recibo.
