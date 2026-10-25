# Elección de tipo después de no encontrar un destino

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Imagen nativa privada
`0x30000000`, con relocaciones declaradas y sin inicializar el engine.

**confirmed en el dominio declarado:** 1.536 llamadas nativas completas al
consumidor `0x004BA780` llegan sin destino al bloque `0x004BAA33`, eligen un tipo,
ejecutan el factory original, inicializan tamaño/saldo, registran el movimiento,
limpian el slot y retornan. Después se retira el nodo con el unlink original,
incluida la baja de identidad y dos liberaciones reales con snapshots.

## Último elegible, comparado siempre contra la fuente

La elección comienza con el tipo de la fuente. Si su byte `+0x3D8` es cero o el
catálogo no tiene entradas, se conserva ese tipo. En caso contrario se recorren
las entradas en orden y se conserva cada entrada que cumpla:

1. Su método virtual `vtable+0x18` devuelve AL distinto de cero.
2. Su byte `+0x3D9` es cero.
3. Su dword con signo `+0x3C` es menor que el del tipo **original de la fuente**.

Cada coincidencia sustituye la elección; el umbral sigue siendo el tipo de la
fuente, no la entrada elegida anteriormente. Por tanto gana la **última entrada
elegible**, no la primera ni la de menor campo. Con fuente diez y entradas
`[5,1,7]` elegibles, se elige siete. Los fixtures nativos contienen 50
contraejemplos a sustituirlo por una minimización.

Este bloque no consulta el límite `tipo+0x30`, la cultura o la religión. No se
confunde con la [búsqueda de nodos existentes](POP-SELECTION.md): aquella aplica
otros filtros y conserva el primer nodo válido dentro de la pasada pertinente.
Tampoco se da significado de gameplay al campo `+0x3C` sólo por su comparación.

## Métodos virtuales y segundo selector dentro del factory

Se usan vtables originales, respaldadas por los enlaces RTTI ya estudiados:

| Fixture de tipo | Vtable preferida | Slot `+0x18` original | Resultado |
| --- | --- | --- | --- |
| CPopType | `0x00E365F8` | `0x00A31490` | MOV AL,1; RET |
| CNullPopType | `0x00E36618` | `0x0058CFD0` | XOR AL,AL; RET |

No se interceptan esas llamadas ni se fabrican sus retornos. El verificador
emulado comprueba el orden y la dirección real de cada predicado ejecutado.
Si `+0x3D8=0`, no se llama a ninguno, aunque existan entradas elegibles.

Hay otro selector: el factory `0x004B8D30` llama a `0x004B8C80`. En los ensayos,
el tipo elegido tiene `+0x3D4` apuntando al fixture CNullPopType ya existente;
su predicado original es falso y este segundo selector conserva la elección.
La fase posterior [del selector interno](FACTORY-INTERNAL-SELECTOR.md) ejecuta
sus dos ramas de forma aislada. Otra ampliación del mismo contrato integra 960 factories directos con cambio
de tipo. La combinación completa con la elección previa del consumidor sigue
sin ejecutarse.

## Resultado completo y matriz nativa

El tipo fuente tiene índice cero; las tres entradas candidatas tienen índices
`+0x28` cero/uno/dos. El nodo se enlaza en el bucket de la elección final y su
campo `+0x68` conserva esa elección. Se comparan los 648 bytes, las tres cabeceras,
tipos/catálogos completos, slot, mundo, árboles de movimientos, tablas de identidad,
handle y estado previo a liberar. Se conserva FS:0 y se guarda/restaura FX.
La fuente mantiene su puntero de tipo durante la limpieza del slot.

Se cruzan seis permutaciones × cuatro familias de campos con signo × ocho modos
de predicados/flags × longitudes de catálogo 0/1/2/3 × byte fuente 0/1 = **1.536**.
Las familias incluyen INT32_MIN, -1, cero, diez e INT32_MAX, igualdad y desigualdad.
Los ocho modos usan máscaras de predicados `7,7,7,7,0,1,3,5` y de flags
`0,1,2,4,0,0,0,2`; no son el producto cartesiano de todas las máscaras.
La posición del slot, diferencia de índice de región y patrón de reserva se
distribuyen por índices de la matriz, sin multiplicar ese total.

En 1.160 casos se conserva el tipo fuente y en 376 se elige una entrada del
catálogo. Cada ciclo reserva/libera nodo y enlace de registro: dos HeapAlloc y
dos HeapFree originales. La clave es `(0x2E,0xFFFFFFFF)`, con contador dedicado
que pasa a cero. Tamaño fuente 65.536, saldo 32.768.000, árboles de movimiento
preexistentes con la misma clave numérica de provincia y tipos `+0x40/+0x39C=0`.

## Fragmento independiente y reproducción

Otros **18.432 fragmentos originales `0x004BAA33..0x004BAAEB`** se ejecutan en
Unicorn: seis permutaciones × cuatro familias × todas las máscaras 0..7 de
predicados × todas las máscaras 0..7 de flags × cuatro longitudes × byte fuente
0/1/255. Se contrastan EAX elegido, orden/destinos virtuales, ESP/EBX y el arena
de 16 KiB intacto. Hay 150 contraejemplos a minimizar el campo. Son fragmentos;
no se les atribuye retorno completo del consumidor o restauración de FS:0.

```bash
source research/env.sh
python research/scripts/verify_pop_factory_selection.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Recibos de fragmentos: `pop-factory-selection/{claims,reverify,emulation}.json`.
Reverify contrasta 24 instrucciones/enlaces de vtable. Los ciclos completos están
en `native-growth/execution.json`, `entry: pop_consumer_type_selection`; el runner
recalcula la elección con `scripts/pop_factory_selection_model.py`, independiente
del modelo C. El gate vincula ambos modelos y los recibos por hash.

El banco nativo suma **6.759 casos, 29.196 reservas y 28.077 liberaciones** con
snapshot; la fase anterior está en `baseline-consumer-merge-5223/`. No se suman
los fragmentos emulados a esos totales. Catálogos de distribuciones vacíos,
singletons ya disponibles y sin estadísticas/recursos opcionales. No se prueban
catálogos malformados, selector interno alternativo, inserción/rotación de
movimientos, retiro interno de nodos vacíos, errores, concurrencia o un tick real.
