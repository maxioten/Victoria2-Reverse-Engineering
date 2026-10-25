# Consumidor completo de la cola: creación de nodos y registro de movimientos

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. El banco PE32 ejecuta
la imagen privada en `0x30000000`, con relocaciones y sin inicializar el engine.

**confirmed en el dominio declarado:** 1.080 llamadas completas a
`0x004BA780(propietario)`, desde su entrada hasta RET 4, con FS:0 restaurado.
No se sustituyen resultados de callees. Las reservas y liberaciones pasan por
el CRT y HeapAlloc/HeapFree reales. Después de cada llamada se retira el nodo
nuevo con `0x004BE8D0` y se contrasta su payload completo antes de liberar.

## Camino ejecutado

El propietario contiene tres slots contiguos de 632 bytes en `+0x30C/+0x310`.
Uno tiene tamaño positivo y los otros, tamaño cero o negativo. El cuerpo recorre
los tres, deja intactos los no positivos y busca un destino en la lista del tipo.
Los buckets comienzan vacíos: ejecuta el factory `0x004B8D30`, la inicialización
desde fuente `0x00955A00` y el setter de tamaño `0x00955FD0` originales.

El nodo nuevo conserva la región del propietario asignada por el factory. Copia
los campos declarados de la fuente, aplica el tamaño limitado a dos millones y
deja `+0x58/+0x5C/+0x60` iguales a ese tamaño. El evento en
`+0x158+4*(1 o 2)` recibe el tamaño solicitado completo, incluido 2.000.001;
la selección compara los índices `+0x12C` de ambas regiones. El saldo de fuente
se copia si su representación con signo no es negativa; si lo es, se escribe cero.

El registro de movimientos recibe el tamaño solicitado, limitado por arriba a
65.535, y lo suma a una celda de 16 bits con wrap. En estos fixtures, los IDs
numéricos de provincia `+0x58` son ambos cero: sólo se ejecuta la ruta de la misma
clave en `0x00444DA0`. Los índices de región `+0x12C` pueden diferir; no se
confunden esos índices con los IDs numéricos usados como claves del registro.

El cuerpo después limpia el slot positivo: `+0x5C` toma el tamaño solicitado
anterior; `+0x58`, `+0x60` y el saldo se ponen a cero. Sus restantes bytes y los
slots no positivos se comparan completos. La pasada final examina tres buckets
de tipos, encuentra el nodo nuevo positivo y lo conserva. No se ejecuta aquí la
retirada interna de nodos con tamaño no positivo.

## Registro de movimientos controlado

El global `0x012588E8` apunta a un fixture de mundo. Su `+0xC10` referencia un
descriptor con una fila de 28 bytes y el índice actual cero. Su marca anterior
coincide con el sentinel original `0x0125A35C`, evitando la rotación de fila.
La llamada escribe la fecha declarada `0x12345678` en el descriptor y en
`propietario+0x354` a través de la tabla `mundo+0xACC`.

La fila contiene un árbol exterior con clave cero y un árbol interior con clave
cero. Se ejecutan búsquedas originales `0x00445260` y `0x004453B0` sobre esas
entradas preexistentes: no se interceptan ni se fabrican sus retornos. La celda
interior parte de `0xFFF0`; su palabra alta y todos los bytes restantes permanecen
intactos. Se comparan completos descriptor, fila, mapas, sentinels, nodos de árbol,
tabla de provincias, mundo, regiones, tipos, catálogos, listas y tablas de registro,
según las escrituras esperadas de cada uno.

## Matriz y límites

Tres índices de tipo × tres posiciones positivas × tamaños
1/65.535/65.536/2.000.000/2.000.001 × cuatro saldos
0/32.768.000/0xFFFFFFFFFFFFFFFF/0x7FFFFFFFFFFFFFFF × índices de región iguales
o distintos × patrones de reserva 0/0x5A/0xFF = **1.080 casos**.
Cada caso hace dos reservas y dos liberaciones originales. La semilla dedicada
de ID es 0xFFFFFFFF, con clave conservada e incremento a cero contrastados.

Los catálogos de distribuciones están vacíos y las listas de destinos comienzan
vacías. Singletons y cachés ya disponibles; tipo `+0x40/+0x39C/+0x3D8` cero.
Una fase posterior valida la [fusión con un nodo existente](POP-MERGE.md) en
1.152 llamadas nativas completas. No se validan todavía búsqueda alternativa de tipo,
movimientos entre claves distintas, inserción/rotación de árboles, retiro interno
de nodos vacíos, recursos opcionales, fallos, excepciones, concurrencia o una partida.
**inferred:** la interpretación de cola intermedia sigue limitada a los llamadores
y rutas contrastados. Ejecutar este cuerpo completo no prueba un tick completo.

El primer modelo esperado puso `nodo+0x5C=0`; el original produjo uno para tamaño
uno. Se corrigió el modelo para reflejar el setter ya estudiado y se conservaron
los intentos fallidos, con fuentes y salida, en `native-growth/attempt-*/`.

## Evidencia y reproducción

```bash
source research/env.sh
python research/scripts/verify_pop_consumer.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Los 34 checks estáticos de reverify respaldan instrucciones concretas y límites
de llamadas; no prueban por sí solos la semántica completa. La evidencia nativa
está en `native-growth/execution.json`, `entry: pop_consumer_new_node`.
El banco combinado suma **4.071 casos, 26.124 reservas y 23.853 liberaciones** con
snapshot. La fase anterior se conserva en `baseline-populated-factory-2991/`.
El gate vincula fuentes, ejecutable y salida por hashes; no vuelve a ejecutar Wine.
Las consultas Ghidra de consumidor y árboles son material auxiliar, no fuente C++.
