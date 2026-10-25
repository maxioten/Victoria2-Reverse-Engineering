# Copia y cambio de longitud de CGoodsPool

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Continúa el contrato de
[construcción del recurso opcional](POP-OPTIONAL.md).

**confirmed para 540 fixtures completos de Unicorn y 480 nativos:** entrada
`0x0047DBB0`, argumentos `(destino,origen)`, RET 8, EAX = destino. Se ejecutan los
copiadores, resize y, en los casos nativos que lo requieren, reservas y liberaciones
originales. No se usan retornos de stubs.

## Regla operacional

La rutina copia desde `origen+8` hacia `destino+8` tantos bytes como indique el
global `0x012587F4`. En estas pruebas está entre cero y 64. Los bytes posteriores
del mapa del destino no se borran ni copian si quedan fuera de ese rango.

Después ajusta el vector en `destino+0x48` a la longitud lógica del origen mediante
`0x0043A880`. **El bucle de copia comienza en el índice uno.** No es una asignación
literal del rango entero del vector:

- Si el destino ya tenía al menos un elemento, su índice cero conserva los bits anteriores.
- Si el destino estaba vacío y el origen no, resize crea ese primer elemento con cero.
- Los índices `1..n-1` toman los ocho bytes de los elementos del origen.
- Si `n=0`, el nuevo end es begin; el contenido fuera del rango lógico se conserva.

No se asigna significado de gameplay al primer elemento. Puede actuar como entrada
especial dentro de invariantes más amplias, pero eso continúa siendo **hypothesis**.

Hay 360 casos emulados con primer elemento final distinto del primer elemento de
origen. Dos contraejemplos concretos al modelo de copia literal completa:

| Longitud origen | Longitud previa destino | Primer elemento origen | Primer elemento final destino |
| --- | --- | --- | --- |
| 2 | 0 | `0x6E0DA84E5469E7F4` | `0x0000000000000000` |
| 2 | 1 | `0xDE76E820BBD32AF1` | `0x5A5A5A5A5A5A5A5A` |

Son patrones sintéticos reproducibles, no valores extraídos de una partida. El
recibo conserva ambos valores por caso; no se deduce un bug del engine de esos
contraejemplos a un modelo de copia demasiado general.

## Comparación emulada completa

Los 540 casos cruzan tamaños de mapa 0/1/2/31/63/64, longitudes de origen
0/1/2/3/7/16, destino previo 0/1/3/9 y tres patrones. Incluyen 108 casos de copia
del objeto sobre sí mismo. Hay capacidad suficiente, siempre con buffers no nulos.

Se comparan los 65.536 bytes de fixtures, incluidos ambos objetos, buffers,
primer elemento, mapa no copiado y capacidad sin usar. También se contrastan el
retorno, registros no volátiles y balance del stack. Los callees reales de resize,
reserva sin crecimiento y relleno cero se ejecutan; las entradas de heap se
rechazan porque están fuera de este dominio.

## Reserva nativa y orden de publicación

Los 480 casos nativos cruzan origen 0/1/2/7/16, destino previo 0/1/3/6, mapas
0/1/31/64, tres patrones y dos capacidades previas: longitud del destino o
`max(longitudes)+2`. Los buffers de origen tienen dos elementos de capacidad
sobrante cuando no están vacíos; con origen vacío begin/end/capacity son nulos.

De estos casos, 132 necesitan HeapAlloc real y 84 liberan un buffer anterior no
nulo. La capacidad nueva de los tamaños contrastados es
`max(n,capacidad_anterior + capacidad_anterior/2)`. En particular, copiar siete
valores a capacidad seis reserva nueve. Se comprueban los dos elementos de
capacidad nueva sin usar: mantienen el patrón de reserva, no datos del origen.

Antes de HeapFree se compara el buffer antiguo completo y se comprueba que el
descriptor todavía apunta a él. Después se compara todo el buffer nuevo, el
objeto de destino completo y el origen completo, incluyendo su capacidad. El
origen permanece intacto y las reservas vivas son distintas. FS:0 nativo retorna
a su valor previo. Las liberaciones manuales de limpieza no cuentan como llamadas
originales de la rutina.

## Alcance y reproducción

Se prueban objetos distintos con buffers separados y, sólo en Unicorn, el mismo
objeto. No se prueban solapamientos parciales, mapa mayor de 64 bytes, fallos de
heap, límites de longitud, excepciones, registro vivo o concurrencia. Los mapas
sintéticos no se validan como índices coherentes para otros métodos del pool.
La copia completa del recurso de 256 bytes desde el constructor CPop sigue
fuera de esta fase: ejecutar un pool aislado no demuestra esa secuencia completa.
La [fase posterior CPop](POP-OPTIONAL-COPY.md) ejecuta 180 secuencias completas y
contrasta qué partes conserva o reconstruye.

```bash
source research/env.sh
python research/scripts/verify_goods_pool_copy.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Reverify añade doce comprobaciones de instrucciones. Recibos emulados:
`evidence/generated/goods-pool-copy/`. Casos nativos: `native-growth/execution.json`,
con `entry: goods_pool_copy`. El banco nativo combinado contiene al cerrar esta
fase 1.326 casos, 9.870 reservas y 7.599 liberaciones con snapshots. Los 846 casos
previos están conservados en `native-growth/baseline-optional-846/`.
