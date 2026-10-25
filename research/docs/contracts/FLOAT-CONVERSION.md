# Conversión numérica x87: ejecución nativa y anchura del resultado

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida `0x00400000`. Se investigan las VA `0x00B31C00`, `0x00B31C1C` y
`0x00B31C36`; la primera y la tercera aparecen en la actualización de POPs.
La entrada intermedia se prueba como parte del bloque compartido, sin afirmar que
tenga un llamador del juego identificado ni forzar un límite nuevo de función en Ghidra.

## Bloque y carga aislada

El banco copia exactamente 171 bytes desde RVA `0x00731C00`, terminando en el RET de
VA `0x00B31CAA`. Reserva el espacio de una imagen privada, pero sólo compromete dos
páginas: código y selector global. Aplica las dos relocaciones HIGHLOW originales,
en offsets `+2` y `+0x1E`; ambas referencias apuntaban a VA preferida `0x013F3BE0`.
La página de código queda RX y el selector se fija a cero o uno en la página de datos.
No se inicializa el motor ni se resuelven imports del juego.

La base real es la devuelta por VirtualAlloc y figura en cada recibo. En la ejecución
conservada fue `0x008F0000`: entradas reales `0x01021C00`, `0x01021C1C` y `0x01021C36`,
selector `0x018E3BE0`. Es un resultado de esa ejecución, no una dirección fija futura.

## Rutas comprobadas

**confirmed para 3.360 observaciones nativas acotadas:**

| Entrada | Condición probada | Resultado observado |
| --- | --- | --- |
| `0x00B31C00` | Selector distinto de cero | FSTP a binary64 y CVTTSD2SI: resultado de 32 bits en EAX; EDX conserva el centinela de entrada |
| `0x00B31C00` | Selector cero | Salta al cuerpo de conversión de 64 bits |
| `0x00B31C1C` | Selector uno, máscaras x87 del banco activas | Entra en la ruta de 32 bits tras comprobar parte del control word |
| `0x00B31C1C` | Selector cero | Salta al cuerpo de conversión de 64 bits |
| `0x00B31C36` | Ambos valores del selector | Resultado de 64 bits en EDX:EAX; consume el valor ST(0) |

La matriz inicial de 56 entradas binary64 coincidió con truncar hacia cero cuando el
resultado cabía en la anchura correspondiente. La ampliación a 84 entradas extended80
refutó esa descripción como contrato general: la cuantización intermedia y un atajo
en el límite de signed64 introducen diferencias descritas más abajo. Las combinaciones
con NaN, infinitos o resultados intermedios fuera de rango producen `0x80000000` en la
ruta de 32 bits y `0x8000000000000000` en la de 64 bits, con excepciones enmascaradas. Esto
describe patrones observados; no convierte un cast fuera de rango en C en una operación
portable ni modela excepciones sin enmascarar.

**Contraejemplo a intercambiar las rutas:** para entrada binary64 `2^32`, bits
`0x41F0000000000000`, la ruta alternativa devuelve EDX:EAX `0x0000000100000000` y EAX
inferior cero; la rápida devuelve EAX `0x80000000`. La primera matriz conservó 23
entradas con diferencia en los 32 bits inferiores. La ampliación conserva 71 al
comparar la entrada B31C00 con selector cero/uno y modo cercano, incluyendo casos con
truncamiento matemático dentro de signed32. La anchura no es la única diferencia.

## Precisión extendida: contraejemplos nuevos

**confirmed con carga FLDT de diez bytes:** el valor exacto `1 − 2^-64`, patrón
extended80 `0x3FFEFFFFFFFFFFFFFFFF`, produce:

| Modo x87 | Ruta rápida EAX | Ruta alternativa EDX:EAX |
| --- | --- | --- |
| Cercano | 1 | 0 |
| Abajo | 0 | 0 |
| Arriba | 1 | 0 |
| Hacia cero | 0 | 0 |

La ruta rápida primero almacena ST(0) como binary64 mediante FSTP. En los modos
cercano y arriba, ese paso convierte el valor en uno antes de CVTTSD2SI. La alternativa
conserva la información necesaria para devolver cero. El recibo contiene 26 patrones
con diferencias de esta clase dentro del rango matemático de signed32 y 26 patrones
cuyo resultado rápido cambia con el modo de redondeo. Los controles x87 y MXCSR se
varían emparejados; no se afirma haber probado todas sus combinaciones independientes.

Hay además dos mecanismos distintos cerca de los límites de signed64:

| Entrada exacta | Modos | Resultado alternativo | Truncamiento matemático |
| --- | --- | --- | --- |
| `2^63 − 0.5`, bits `0x403DFFFFFFFFFFFFFFFF` | Cercano, arriba | `0x8000000000000000` | `0x7FFFFFFFFFFFFFFF` |
| `−2^63 + 0.5`, bits `0xC03DFFFFFFFFFFFFFFFF` | Cercano, abajo | `0x8000000000000000` | `0x8000000000000001` |

En el primer caso, FISTP redondea inicialmente fuera del rango de signed64. En el
segundo, FISTP devuelve un entero representable, INT64_MIN, pero el bloque que detecta
palabra baja cero y palabra alta con sólo el signo omite la corrección posterior.
Por eso no basta con preguntar si el truncamiento matemático final cabe en signed64.

El primer modelo ampliado omitió ese atajo y discrepó en ocho observaciones del
segundo caso. Se conserva como **modelo refutado**, con su fuente, recibo y resultados,
en `native-float/extended-truncation-refutation/`. Se corrigió a partir de las
instrucciones `0x00B31C55..0x00B31CA5`, sin cambiar el bloque original ejecutado.
El análisis de las observaciones actuales agrupa cuatro pares distintos de entrada/modo
en `extended-counterexamples.json`; no representa otra ejecución nativa.

## Controles y estado flotante

El puente de ensamblador propio guarda el estado FPU del host con FXSAVE, inicializa
x87, carga un patrón binary64 en ST(0), establece los controles y llama al cuerpo
original. Captura EDX:EAX, control word, status word, tags y MXCSR antes de restaurar
el estado del host con FXRSTOR. Las entradas binary64 usan FLDL; las extended80, FLDT.
El resultado esperado se calcula con fracciones y enteros exactos de Python;
el C del harness no hace una conversión flotante a entero para crear el oráculo.

Se prueban cuatro modos emparejados x87/MXCSR: cercano, abajo, arriba y hacia cero.
La precisión x87 se fija a 64 bits de significando, con todas las excepciones
enmascaradas. Los tags muestran stack x87 vacío al terminar; el control word permanece
idéntico. Los bits de control de MXCSR también se conservan, mientras los flags de
excepción se registran sin exigir que sean cero.

Las primeras 56 entradas incluyen ceros con signo, fracciones y vecinos binary64 de `2^24`,
`2^31`, `2^32`, `2^53` y `2^63`, subnormales y los patrones NaN/infinitos declarados.
Se añaden 84 patrones extended80 normalizados cercanos a enteros y fronteras. Se verifica
la cobertura exacta de las 140 × 3 × 2 × 4 combinaciones. El modelo racional distingue
la cuantización binary64, el redondeo inicial de FISTP, su rango y el atajo INT64_MIN.
Clasifica 2.832 casos con intermedio dentro de rango y 528 no finitos o fuera de rango.
Ese segundo contador no es un conteo de todos los flags de excepción de hardware ni
de todos los resultados cuyos bits coinciden con INT64_MIN.

## Relación con el llamador

**confirmed, instrucciones:** después del CALL de `0x0095823F`, el código de POP
compara y usa EAX. En cambio, después de los CALL a `0x00B31C36` en `0x00958563` y
`0x00958571`, guarda y usa tanto EAX como EDX. Las dos anchuras tienen por tanto usos
distintos en el mismo llamador. No se deben reemplazar ambas por un cast genérico sin
contrastar las rutas y los rangos válidos de entrada de cada sitio.

Estos sitios no son llamadas al RNG identificado. Los demás callees del POP pueden
consumir azar; no se concluye que la actualización completa carezca de RNG.

## Reproducción y límites

Desde la raíz, con `research/env.sh` cargado:

```bash
python research/scripts/verify_float_conversion.py
python research/scripts/build_native_float_probe.py
python research/scripts/run_native_float_probe.py
python research/scripts/analyze_extended_float.py
```

Reverify aporta 22 comprobaciones de despacho, corrección y atajo a las instrucciones de
conversión ya contrastadas en el mapa de POPs. Los recibos estáticos están en
`evidence/generated/float-conversion/`. Los nativos y sus intentos están en
`evidence/generated/native-float/`: construcción, fixtures, resultados por caso,
contraejemplos, hashes del código/fuentes/modelo y SHA-256 del stdout y stderr.
La línea base binary64 permanece en `native-float/baseline-binary64-1344/`.
El proceso PE32 se ejecutó bajo Wine 11.19, fuera del filtro del sandbox, en el prefijo
aislado ya preparado. La puerta general valida los hashes del recibo nativo existente;
no vuelve a lanzar Wine en cada ejecución.

Se prueban valores extended80 concretos, sin cubrir todos sus patrones ni encodings.
No se prueban otros controles de precisión, máscaras de excepción desactivadas, todas las combinaciones
independientes de redondeo x87/MXCSR ni la actualización entera del POP. El resultado
no prueba una sustitución universal por SSE, C o código recompilado.
