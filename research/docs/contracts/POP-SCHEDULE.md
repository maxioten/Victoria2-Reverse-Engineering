# Selección y recorrido de POPs dentro del tick de país

Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA con base preferida `0x00400000`; RVA = VA − base. Entrada contenedora candidata
VA `0x005091A0`, nombrada `Country_DailyUpdate` por la referencia externa fijada en
`docs/HALLAZGOS.md`. Los nombres de campos y callees son interpretaciones operativas.

## Regla comprobada

**confirmed en el dominio emulado:** el fragmento de preparación de fecha VA
`0x0050921B` a `0x00509341` calcula el día del mes con índice cero y la longitud
mensual. El guard de VA `0x005093C6` selecciona el camino de actualización si:

```text
signed32([objeto+0x58]) > 0
y unsigned32([objeto+0x0C]) % longitud_mes == día_del_mes_con_índice_cero
```

La división de VA `0x005093D9` es **DIV sin signo**, con EDX previamente a cero.
No se debe sustituir por un resto con signo si se busca reproducir el comportamiento
para patrones con el bit superior activo. El campo `+0x58` sí se compara con signo.
Los nombres `id` y `tamaño de POP` para estos campos son **inferred** desde el contexto;
no se ha determinado aquí la unidad numérica del tamaño ni todas sus escrituras.

Prueba reproducible: `source research/env.sh` y
`python research/scripts/verify_pop_schedule.py` desde la raíz. Unicorn ejecuta ambos
fragmentos originales sobre objetos sintéticos. La longitud calculada por el primer
fragmento se suministra al local `[EBP-0x1C]` del guard; se excluye el código intermedio.

- 1.460 fechas: todos los días de 1836 y 1900, horas 0 y 23, calendario de 365 días.
- Ocho patrones de identificador por fecha, incluidos `0x80000000` y `0xFFFFFFFF`.
- Tres valores del campo de tamaño: 0, 1 y `0xFFFFFFFF` (−1 con signo).
- 35.040 decisiones, sin discrepancias con la regla anterior.
- Reverify verifica 17 instrucciones del guard, llamadas y avance del iterador.

Recibos: `evidence/generated/pop-schedule/{claims.json,reverify.json,emulation.json}`.
Esto prueba selección del camino; no ejecuta la actualización de un POP ni demuestra
equivalencia global de simulación, frecuencia mensual en una partida ni pureza.

La investigación posterior tiene un [mapa completo del grafo normal de la rutina
seleccionada](POP-UPDATE.md) y una [prueba de su primitiva de tamaño](POP-SIZE.md).
Ambos mantienen separados el inventario estructural y los dominios de ejecución.

## Recorrido local y puntos de mutación

**confirmed, instrucciones estáticas:** VA `0x005093C0` carga `[EDI+0x27C]` y
VA `0x005093C8` conserva el resultado en `[EBP-0x14]` antes de las llamadas:

| VA de llamada | RVA | Destino VA | Interpretación externa, todavía parcial |
| --- | --- | --- | --- |
| `0x0050945D` | `0x0010945D` | `0x00957EA0` | Actualización mensual de POP |
| `0x0050946B` | `0x0010946B` | `0x004B9250` | Tratamiento o fusión de POP vacío |

Después, VA `0x00509472` recupera ese puntero conservado; VA `0x00509477` vuelve
a `0x005093C0` si no es cero. El siguiente bucket se obtiene sumando 16 al desplazamiento
local en VA `0x0050947D`. No se presupone que todos los bytes de ese bucket sean punteros.

**inferred:** `+0x27C` actúa como enlace siguiente de la cadena recorrida. Guardarlo
antes de las llamadas es compatible con callees que mutan o eliminan el nodo actual.
No demuestra por sí solo qué nodos eliminan, qué memoria liberan o cuándo invalidan
el enlace conservado. Estas cuestiones se deben resolver antes de compactar listas,
reordenar POPs, mantener caches de punteros o ejecutar actualizaciones en paralelo.

## Pendientes para cerrar el contrato

- Trazar las escrituras de `+0x0C`, `+0x58` y `+0x27C`, constructores y destrucción.
- Auditar efectos de ambas llamadas, incluida la relación con RNG y acumuladores.
- Documentar el layout completo de buckets y su selección por tipo.
- Contrastar las rutas con una partida real, incluidas migración y fusión de POPs.
- Conservar orden de recorrido y precisión aritmética en cualquier modelo de reemplazo.

## Desconexión y eliminación diferida

Entrada VA `0x004BE8D0` (RVA `0x000BE8D0`): ESI apunta al bucket y el primer
argumento de pila apunta al nodo. **confirmed en los casos declarados:**

| Campo | Papel operativo comprobado |
| --- | --- |
| bucket `+0x00` | Primer nodo |
| bucket `+0x04` | Último nodo |
| bucket `+0x08` | Conteo: DEC estático después de llamadas excluidas de la emulación |
| bucket `+0x0C`, un byte | Selecciona la ruta diferida cuando es distinto de cero |
| nodo `+0x278` | Enlace al anterior |
| nodo `+0x27C` | Enlace al siguiente |
| nodo `+0x280`, un byte | Se escribe 1 en la ruta diferida |

Con argumento nulo retorna AL=0. Con argumento no nulo y bandera diferida activa,
escribe la marca del nodo y retorna AL=1, sin modificar enlaces ni metadatos del bucket
en los casos probados. Sin bandera, ajusta los vecinos y, si corresponde, cabeza y cola.
El prefijo probado se detiene entonces antes de llamar a VA `0x00955AE0`.

Lectura estática posterior, verificada por reverify: VA `0x004BE927` llama a
`0x00955AE0`; VA `0x004BE92D` llama al wrapper `0x00AAE91B`; luego decrece el campo
de conteo y retorna con `RET 4`. Los efectos internos de ambas llamadas no se
incluyen en esta prueba. «Destructor» y «liberación» son nombres operativos parciales
hasta auditar sus rutas con argumento no nulo.

Ese límite corresponde al primer harness de emulación. Las rutas con argumento no
nulo se contrastaron después en el [banco nativo de vida de nodos](NATIVE-POP.md),
con recursos sintéticos y dominio explícito; no sustituye una traza de la actualización
completa durante una partida.

`scripts/verify_pop_unlink.py` ejecuta doce casos: argumento nulo con buckets vacío
y no vacío, nodo único, cabeza, medio y cola de una lista de tres nodos; cada variante
con bandera apagada y encendida. Se verifican todos los enlaces y metadatos pertinentes.
Las rutas nula y diferida se ejecutan completas; la inmediata sólo hasta el punto
anterior a las llamadas. Doce instrucciones se contrastan mediante reverify.
Recibos: `evidence/generated/pop-unlink/{claims.json,reverify.json,emulation.json}`.

Advertencia de análisis observada: el export anterior `ghidra-corrected/functions.csv`
terminaba el cuerpo candidato en VA `0x004BE931`, justo al final del CALL al wrapper
que se había marcado incorrectamente como no retorno. El ensamblador continúa hasta
el RET en `0x004BE93C`. Es necesario revisar ese límite después del análisis general;
retirar el override de una llamada no prueba que todos los cuerpos ya estén reparados.

## Desconexión sin destrucción

VA `0x004BE0F0` (RVA `0x000BE0F0`) recibe el nodo en EAX y el bucket en ECX.
**confirmed en 88 casos completos:** si el byte `bucket+0x0C` no es cero retorna
sin cambiar la lista ni marcar el nodo. Si es cero, enlaza los vecinos, actualiza
cabeza y cola, decrementa el conteo y pone a cero ambos enlaces del nodo retirado.
No llama a la destrucción ni al heap.

Se probaron todos los nodos de listas de tamaños 1, 3, 8 y 32, con bandera cero y uno.
El harness mantiene pila y nodos en regiones separadas y compara todos los bytes de
la región de datos. Los cinco nuevos checks de reverify y los casos de emulación
están incluidos en `scripts/verify_pop_unlink.py` y sus mismos recibos.

**inferred:** esta operación permite retirar o mover un objeto conservando su memoria.
Es diferente de `0x004BE8D0`: cuando la bandera está activa, aquella marca el nodo;
esta no modifica nada. No se deben unificar ambas operaciones en una reconstrucción.

La búsqueda estructural del desplazamiento `0x280` halló 170 instrucciones candidatas
en la base actual de Ghidra (`evidence/generated/field-accesses/field_280.csv`).
Coincidir en desplazamiento no atribuye un campo al mismo tipo. No se identificó aún
el consumidor de la marca: puede usar un puntero al subobjeto o una ruta todavía no
recuperada, por lo que este resultado no demuestra que la marca no se utilice.
