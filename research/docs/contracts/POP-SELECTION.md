# Selección de destinos existentes: prioridad y orden de lista

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

**confirmed en los fixtures declarados:** el consumidor `0x004BA780` busca en
pasadas ordenadas sobre el bucket de `tipo_fuente+0x28`. Se ejecutan **305 llamadas
completas en Unicorn**, con uno a seis nodos candidatos, fusión y registro de
movimientos originales. Otros **447 casos** recorren la búsqueda sin encontrar
destino y se detienen en `0x004BAA33`, antes de ejecutar la selección del factory.
Estos últimos son prefijos, no consumidores completos ni pruebas del factory.

## Búsqueda ordinaria

Si el byte `tipo_fuente+0x3D8` es cero, o los índices de región `+0x12C` coinciden,
las pasadas son las siguientes. Cada una vuelve a empezar por el head original.

| Pasada | Condiciones adicionales del primer candidato aceptado | CALL de fusión |
| --- | --- | --- |
| Exacta | mismo puntero de tipo, cultura y religión | `0x004BA932` |
| Campo de tipo | byte `tipo_destino+0x3D9=0`, mismo dword de tipo `+0x3C` y misma cultura; no compara religión | `0x004BA99B` |
| Campo de cultura | byte `tipo_destino+0x3D9=0`, mismo puntero de tipo y mismo dword `cultura+0x50`; no exige misma cultura ni religión | `0x004BAA08` |

Todas exigen que el límite con signo `tipo_destino+0x30` sea -1 o que el tamaño
actual del candidato sea estrictamente menor. La primera pasada **no consulta
`+0x3D9`**: se contrastan 56 consumidores completos que aceptan una coincidencia
exacta con ese flag no cero. No se le atribuye semántica de prohibición global.

La prioridad es de pasadas, después de posición en la lista. Hay 45 fixtures que
contradicen una alternativa que examinara cada nodo una sola vez y aceptara
cualquiera de las tres condiciones: una coincidencia exacta posterior puede
ganar frente a un candidato anterior válido sólo para una pasada más débil.

No se asigna significado de gameplay a `tipo+0x3C` o `cultura+0x50`; aquí se
documentan sus comparaciones y rutas. La clasificación de estos campos continúa
abierta fuera de la evidencia local.

## Búsqueda alternativa de campo inferior

Cuando `tipo_fuente+0x3D8!=0` y difieren los índices de región, sólo se ejecuta la
pasada alternativa: además del límite anterior, requiere `tipo_destino+0x3D9=0`,
campo con signo `tipo_destino+0x3C < tipo_fuente+0x3C`, misma cultura y misma
religión. La fusión se llama desde `0x004BA8C8`.

Acepta el **primer** candidato que cumple esas condiciones. No minimiza `+0x3C`:
seis fixtures refutan esa sustitución. Por ejemplo, un candidato de campo cinco
puede ganar frente a otro posterior de campo menos uno, con fuente de campo diez.
Si esta pasada no encuentra nada, pasa a `0x004BAA33`; no intenta las tres pasadas
ordinarias. Una fase posterior [de elección de tipo](POP-FACTORY-SELECTION.md) ejecuta ese
cuerpo y el factory, con evidencia nativa independiente.

## Evidencia dinámica y matriz

`scripts/pop_selection_model.py` genera la elección esperada y la traza exacta
de pares `(pasada, índice_de_nodo)`. El verificador observa las entradas de cada
iteración en `0x004BA87E/0x004BA8FB/0x004BA95D/0x004BA9C6` y compara toda la traza.
También contrasta el EDI real al entrar en `0x00964370` con el destino seleccionado.

Las 752 entradas se componen de cinco familias de tres candidatos × seis
permutaciones × ocho combinaciones de flags/índices, más 512 listas reproducibles
de uno a seis candidatos. Se alterna el límite del tipo fuente entre -1 y 17;
un tipo adicional tiene límite 17. Se cruzan tamaños de candidato 1/17,
tipos con campos `+0x3C` diez/cinco/veinte/menos uno, flags `+0x3D9`, dos religiones
y tres culturas con campos `+0x50` siete/siete/nueve. Son fixtures sintéticos;
no prueban que todos esos grafos o tipos alternativos coexistan en un bucket real.

| Resultado | Casos |
| --- | ---: |
| Consumidor completo, pasada exacta | 113 |
| Consumidor completo, mismo campo `tipo+0x3C` | 143 |
| Consumidor completo, mismo campo `cultura+0x50` | 23 |
| Consumidor completo, campo de tipo inferior | 26 |
| Prefijo sin coincidencia, detenido antes de factory | 447 |

En los retornos completos se ejecutan helpers originales de fusión, tamaño,
saldo y registro con árboles de clave cero preexistentes. Se comparan todos los
131.072 bytes del arena, incluidos los candidatos descartados, lista, slot fuente,
mundo, árboles, tipos y culturas. Se conservan registros ABI y FS:0. El modelo
aritmético usa el [contrato de fusión](POP-MERGE.md).

Los prefijos sin coincidencia conservan el arena íntegro y no alcanzan callees.
Se detienen dentro del frame del consumidor: no se afirma restauración de ABI/FS:0
para esos casos. No se sustituyen instrucciones ni retornos de funciones.

## Reproducción y fronteras

```bash
source research/env.sh
python research/scripts/verify_pop_selection.py
python research/scripts/verify_grounding.py
```

Recibos: `pop-selection/{claims,reverify,emulation}.json`. Reverify contrasta 24
instrucciones; la semántica y el orden provienen de la ejecución separada. El gate
vincula ambos modelos y los recibos por hash. Estas pruebas son de emulación;
el banco nativo previo permanece en 5.223 casos y no se le suman estos 752.

Tipo `+0x40=0`, tamaños de candidatos positivos, recursos opcionales nulos,
árboles de movimientos ya poblados y misma clave numérica de provincia. Fuente
y candidatos son objetos distintos. La elección posterior del tipo para el factory tiene evidencia nativa en el
contrato enlazado. Permanecen abiertos el selector interno alternativo,
inserción/rotación de movimientos, retiro interno de nodos vacíos,
estadísticas no vacías de otros flags, errores, concurrencia, partida y tick completo.
