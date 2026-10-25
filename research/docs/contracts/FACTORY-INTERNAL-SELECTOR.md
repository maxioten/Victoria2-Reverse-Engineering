# Selector interno del factory: primer tipo presente en las filas

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Imagen privada nativa
`0x30000000`, con relocaciones y sin ejecutar la inicialización del engine.

**confirmed en el dominio declarado:** 2.178 llamadas nativas completas a
`0x004B8C80(tipo_solicitado,propietario)`, convención observada cdecl, retorno EAX.
Se ejecutan los predicados virtuales originales y no se sustituyen sus resultados.
Un puente ASM fija y comprueba EBX/ESI/EDI/EBP; caller limpia los ocho bytes de
argumentos. Se contrasta también FS:0 y todos los bytes de los fixtures.

## Decisión observada

El tipo solicitado tiene un puntero alternativo en `+0x3D4`. Se llama al slot
virtual `alternativo.vtable+0x18`:

- Si AL es cero, retorna el solicitado directamente.
- Si AL no es cero, busca en las filas del contexto del propietario.

La ruta no nula usa el global `0x01258728` ya inicializado y esta cadena:

```text
base_array = *global_01258728
contexto = *(base_array + propietario[0x58] * 0xB0 + 8)
begin = contexto[0x108]
end = contexto[0x10C]
filas = (end - begin) >> 5
tipo_de_fila_i = *(begin + i*32 + 8)
```

Dentro de cada fila se compara primero con el alternativo, después con el
solicitado. Retorna el primero de esos dos punteros que aparece en el recorrido;
si no aparece ninguno, o la lista está vacía, retorna el solicitado.

| Filas, con predicado verdadero | Resultado |
| --- | --- |
| solicitado, alternativo | solicitado |
| alternativo, solicitado | alternativo |
| otro, alternativo, solicitado | alternativo |
| otros o ninguna fila | solicitado |

No se lee una cantidad o ponderación para decidir: en este cuerpo la selección
depende de la identidad de esos punteros y de su orden. Los restantes bytes de
fila se alternan entre patrones y se comparan intactos. Esto documenta las
lecturas de este selector; no asigna significado completo a la estructura de filas.
El nombre de estadísticas para el contexto es **inferred** por los helpers
relacionados, no por una declaración C++ recuperada.

Es diferente de la [elección previa del consumidor](POP-FACTORY-SELECTION.md),
que conserva la última entrada elegible del catálogo, y de la
[búsqueda de destinos](POP-SELECTION.md), que tiene prioridades entre pasadas.

## Matriz nativa y estado conservado

Se enumeran todas las secuencias de longitud 0/1/2/3/4 con tres clases de fila:
otro, solicitado, alternativo. Hay `1+3+9+27+81=121` secuencias; se cruzan con
índices de propietario 0/1/3 × predicado falso/verdadero × patrones 0/0x5A/0xFF:
**2.178 llamadas**. Con cero filas y patrón cero se prueba también begin/end nulos.

El predicado verdadero usa vtable CPopType `0x00E365F8`, slot `+0x18` hacia
`0x00A31490` (AL=1). El falso usa CNullPopType `0x00E36618`, slot hacia
`0x0058CFD0` (AL=0). Ambos son cuerpos originales. Los tres objetos de tipo son
distintos y el alternativo no hace alias del solicitado en esta matriz.

Se preparan cuatro entradas del array de contextos, cuatro headers y cuatro
vectores de filas; sólo uno contiene la secuencia elegida. Los otros contienen
tipos diferentes. Se comparan completos tipos, propietario, singleton, array,
headers y filas. El global mantiene su puntero durante la llamada y se limpia
después por el harness. No se observan reservas/liberaciones originales ni
mutaciones de los fixtures. Los retornos son solicitado en 1.656 casos y
alternativo en 522.

Los objetos son fixtures parciales con campos necesarios declarados. No prueban
invariantes completas de una partida. Estas 2.178 llamadas validan la entrada aislada. La ampliación siguiente integra
la selección dentro del factory completo. Las primeras pruebas del factory
ejercitaban la rama de predicado falso.

## Integración en el factory completo

**confirmed para otros 960 ciclos nativos:** se llama directamente a
`0x004B8D30(propietario,tipo_solicitado)` y después al unlink `0x004BE8D0`.
Los cuerpos originales del selector, constructor temporal, copia, registro,
setters, destructores y liberadores se ejecutan sin sustituir retornos.

La matriz enumera las 40 secuencias ternarias de longitud 0..3 × índices del
propietario 0/3 × predicado falso/verdadero × tres patrones × índice del tipo
alternativo 1/2. El solicitado tiene índice cero. Hay **216 elecciones del
alternativo y 744 del solicitado**. La elección determina tanto `nodo+0x68`
como el bucket `propietario+0x194 + tipo_elegido[0x28]*16`.

Se comparan completos los 648 bytes del nodo, las tres cabeceras, propietario,
tipos, contexto y filas. La clave `(0x2E,0xFFFFFFFF)` se registra en la tabla B;
el contador dedicado termina en cero y el contador genérico no cambia. El handle
resuelve el nodo antes de retirarlo y cero después. Se comprueban snapshots,
orden y estado del registro/lista en cada liberación original. El contexto del
selector permanece intacto durante creación y retirada.

Cada ciclo añade dos reservas y dos liberaciones: nodo de 648 bytes y enlace de
ocho bytes. El tipo alternativo tiene `+0x40/+0x39C=0`; el temporal parte del
CNullPopType global ya disponible. Catálogos de distribución vacíos, sin recursos
opcionales, fallos ni inicialización perezosa. Esto valida el factory directo;
no ejecuta aún el consumidor combinando su elección de catálogo con un cambio
posterior del selector interno. Los otros cinco llamadores directos tampoco se
ejecutan en esta ampliación.

## Llamadores, reproducción y límites

El snapshot Ghidra conserva seis referencias directas en
`0x004B8D5C/0x004B8F90/0x004B919A/0x004B96D7/0x0095B4BC/0x0095BBF0`.
Sus instrucciones CALL se contrastan por separado; no se afirma cobertura de
llamadas indirectas ni la semántica completa de esos seis llamadores.

```bash
source research/env.sh
python research/scripts/verify_factory_internal_selector.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Reverify contrasta 34 instrucciones/referencias. Recibos estáticos en
`factory-internal-selector/{claims,reverify,call-reference-snapshot}.json`;
la ejecución completa está en `native-growth/execution.json`,
`entry: factory_internal_selector` y `factory_internal_integration`. El runner
recalcula el primer tipo presente
desde la secuencia base tres y el predicado; el gate vincula fuentes y salida.

Al cerrar la fase aislada, el banco sumaba 8.937 casos; esa versión se conserva
en `baseline-internal-selector-8937/`. Con la integración suma **9.897 casos,
31.116 reservas y 29.997 liberaciones** con snapshot. La rama que crea el singleton,
listas malformadas, alias de tipos, los otros llamadores, recursos/estadísticas
de otros flags, fallos, concurrencia, partida y tick completo permanecen abiertos.
