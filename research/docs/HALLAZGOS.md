# Hallazgos contrastados — 21 de octubre de 2026

Perfil único: `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Todas las VA de esta nota usan la base preferida `0x00400000`; RVA = VA − base.
Las direcciones de ejecución con ASLR requieren la base real.

Referencia externa contrastada: `maxioten/Victoria2-Reverse-Engineering`, revisión
`e299a0214d32274239402e8ee22039e1d02e101f`, archivo `Engine/daily-tick.md`.
Los nombres de funciones de esa referencia siguen siendo candidatos semánticos.

## Calendario

**confirmed:** el fragmento original VA `0x00682F39` a `0x00682F9F` produce los índices
de año y mes esperados para 5.840 entradas: todos los días de los años
0, 1, 1836, 1900, 1948, 2000, 2030 y 9999, a las horas 0 y 23.
La instrucción VA `0x00682FA5` suma 24 a `[ESI+0xB0C]`.
Reverify comprueba esa instrucción, la resta del sesgo, la constante 365.0 y la tabla
de doce longitudes mensuales. Unicorn ejecuta los fragmentos originales.

**confirmed, modelo acotado:** para enteros `raw` entre 43.800.000 e INT32_MAX,
Z3 demuestra `((raw − 43800000) / 24) / 365 = raw / 8760 − 5000`, usando división
entera hacia abajo. Esto prueba la identidad del modelo, no todas las operaciones
del calendario del juego ni el fragmento para cada valor de ese intervalo.

La fórmula de la referencia resta 5000 después de haber quitado el sesgo. Para
`raw=59883360`, el fragmento original produce 1836; aquella fórmula produce −3164.
Esta es una refutación concreta de esa fórmula. La interpretación histórica completa,
fechas anteriores al sesgo y otras APIs del calendario permanecen abiertas.

Evidencia: `evidence/generated/calendar/{claims.json,reverify.json,emulation.json,model-proof.smt2}`.
Reproducción desde la raíz: `source research/env.sh` y
`python research/scripts/verify_calendar.py`.

## Marca de no retorno incorrecta en Ghidra

**confirmed:** la ruta con primer argumento de pila cero en VA `0x00AAE91B`
retorna al llamador. Unicorn ejecuta doce instrucciones del PE original, mantiene
EBP y deja ESP cuatro bytes por encima de su valor de entrada. La ruta no llama a
APIs de heap. Es un contraejemplo suficiente a la propiedad incondicional `noreturn`;
no caracteriza la ruta con argumento no nulo ni demuestra el nombre de la función.

El proyecto parcial de Ghidra tenía `noreturn=true` y 32.354 referencias CALL con
override `CALL_RETURN` hacia esa entrada. El script `CorrectNullRelease.java`
cambió la propiedad a false y retiró esos overrides, sin cambiar el binario.
Esto corrige metadatos de análisis; no implica que se hayan reconstruido correctamente
32.354 funciones ni que el análisis global esté completo.

Evidencia: `evidence/generated/crt-null-release.json` y
`evidence/generated/analysis-corrections/{correction.txt,null-release-callers.csv}`.
La exportación anterior se conserva en `evidence/generated/ghidra/`; la posterior,
en `evidence/generated/ghidra-corrected/`. Persisten advertencias sobre pila y tipos.
Reproducción del contraejemplo: `python research/scripts/emulate_null_release.py`.
La corrección del proyecto es una mutación separada que no ejecuta el gate cotidiano.

## Orden parcial de llamadas del tick

**confirmed, grafo estático acotado:** en VA `0x00685EAD` a `0x00685F83`, con
llamadas opacas que retornan a la siguiente instrucción, se recuperan 57 instrucciones
alcanzables. Reverify comprueba ocho llamadas (bytes y operandos) y nueve saltos:
25 afirmaciones. El grafo conserva ambas ramas de cada salto, sin resolver condiciones.

La llamada VA `0x00685ED1` apunta a `0x005091A0` y pertenece al bucle cuyo salto
de repetición está en `0x00685EEF`. Al salir se recorren otros bloques y se llega
a VA `0x00685F7E`, que llama a `0x00489990`. La condición en `0x00685EB0` permite
omitir el primer bucle. No hay un camino de vuelta desde la continuación de la
llamada económica al primer bucle dentro de esta región.

**inferred:** si los nombres externos `Country_DailyUpdate` y `Economy_Update`
describen correctamente esas entradas, el diagrama externo presenta esas dos fases
en orden inverso. No se infiere pureza, ausencia de reentrada, seguridad entre hilos
ni comportamiento de los callees a partir de este orden local.

Evidencia: `evidence/generated/tick-path/{claims.json,reverify.json,cfg.json}`.
Reproducción: `python research/scripts/verify_tick_path.py`.

## Reanálisis general y corrección persistente

La pasada de `ghidra-resumed-20261021T033646Z-KpuojY` terminó sin agotar el límite:
443 segundos de análisis principal y 32 segundos adicionales tras los scripts.
Exportó 63.855 funciones candidatas y 246.830 referencias de llamada antes del guardado
final. Esos valores son recuperación automática; no miden semántica comprendida.

**confirmed, metadatos:** la heurística `Non-Returning Functions - Discovered` volvió
a marcar el wrapper como no retorno. Tras corregirlo, el propio headless lanzó otro
análisis por los cambios de los post-scripts y reintrodujo la marca antes de guardar.
Por eso aquel export previo al guardado no representa necesariamente el estado final.

Se leyó la implementación instalada de Ghidra 12.1.4, `FindNoReturnFunctionsAnalyzer`
en `Ghidra/Features/Base/lib/Base-src.zip`: la heurística asigna `setNoReturn(true)`
sin tratar una corrección manual a false como una exclusión. Se desactivó esa heurística
en este proyecto, manteniendo el analizador de funciones no retornables conocidas.
Se retiraron 33.509 overrides del wrapper y se recuperó el cuerpo local de la rutina
VA `0x004BE8D0` hasta su RET, último byte `0x004BE93E`.

Reapertura de sólo lectura comprobada mediante `AuditReturningWrapper.java`:
heurística apagada, wrapper retornable, cero overrides `CALL_RETURN` hacia él y RET
de la desconexión dentro de su cuerpo. Recibos en
`evidence/generated/analysis-stable/{stabilization.txt,saved-project-audit.json}`.
La nueva exportación de sólo lectura se guarda en `evidence/generated/ghidra-stable-saved/`.
Los cuerpos de las demás funciones aún requieren auditoría.

La exportación del proyecto guardado contiene 63.924 funciones candidatas y 246.832
referencias de llamada. El audit del guardado conserva 33.508 referencias al wrapper,
sin overrides de retorno forzado. No se confunden estos contadores con los del export
anterior al último análisis.

El script de reanálisis se cambió para aplicar la configuración antes del análisis y
exportar tras guardar y reabrir en sólo lectura. Así se evita confundir un export de
post-script con el proyecto que realmente quedó guardado.

## Recuperación de continuaciones tras el wrapper

`RepairReturningCallers.java` se ejecutó con la heurística desactivada y una copia
completa del proyecto previo en `projects/before-return-flow-repair/`.
Parte de las continuaciones habían desaparecido del listado de instrucciones, aunque
otros bloques del mismo cuerpo seguían presentes. Retirar la marca y sus overrides
no había desensamblado de nuevo esas continuaciones.

**confirmed, metadatos del pase:** de 33.508 sitios de llamada examinados, había
32.963 continuaciones sin instrucción en la dirección siguiente; se pudo volver a
desensamblar esa dirección en todos ellos. Son sitios de continuación recuperados,
no un recuento de todas las instrucciones nuevas. Se recalcularon los cuerpos
candidatos de 9.719 funciones y cambiaron 9.716. No se modificaron bytes del juego.

Se excluyeron 533 sitios sin función contenedora, registrados para revisión manual.
No se borraron funciones ajenas para resolver solapamientos. Los nuevos límites siguen
siendo resultados de un analizador: no certifican contratos semánticos ni cobertura total.
Recibos: `evidence/generated/return-flow-repair/{repair-summary.json,fallthroughs.csv,bodies.csv}`.

La exportación reabierta en sólo lectura, `evidence/generated/ghidra-return-flow-repaired/`,
contiene 63.924 funciones candidatas y 247.345 referencias de llamada. El audit encuentra
33.725 referencias al wrapper, todas sin override de retorno forzado. El aumento
incluye referencias recién recuperadas; debe comprobarse si otra pasada cambia el mapa.
La búsqueda directa de desplazamiento `0x280` sigue produciendo 170 candidatos y
no identifica aún el consumidor de la marca de eliminación de POPs.

Pasadas adicionales recuperaron 37, 10 y 8 continuaciones; la pasada siguiente no
cambió cuerpos ni encontró nuevas continuaciones faltantes entre los sitios con dueño.
`scripts/repair_return_flow.py` conserva cada pase y su auditoría. El recibo de
convergencia está indicado en `evidence/generated/latest-return-flow-convergence.txt`.
Quedan 483 sitios sin función contenedora; la convergencia se limita a los llamadores
considerados y no certifica el resto del programa.

La exportación final reabierta en sólo lectura está en
`evidence/generated/ghidra-converged/`: 63.924 candidatos y 247.347 referencias de
llamada, con el audit de metadatos todavía correcto.

## Preguntas abiertas de cobertura

La [prueba nativa de vida de nodos POP](contracts/NATIVE-POP.md) ejecuta la eliminación
inmediata completa y la marca diferida en una copia privada reubicada del PE, bajo
Wine 11.19. Pasaron 134 casos sintéticos: 632 HeapFree reales y 192 snapshots completos
antes de liberar. Incluye buffers de heap, objeto opcional y referencias a regimientos;
conserva fuera del dominio las ramas de país/tipo y ejército, registros presentes,
errores del heap y excepciones. Se corrigió el nombre provisional «observadores»:
el [circuito de referencias](contracts/POP-REGIMENTS.md) enlaza las limpiezas de CPop y CRegiment.
Esto amplía la evidencia de propiedad y limpieza sin validar una partida real.

La fase posterior de [borrado y baja del registro](contracts/OBJECT-REGISTRY.md) añadió
194 casos nativos y 71 enlaces liberados. El retorno AL uno de `0x009C1650` no demuestra
coincidencia: transforma los campos del objeto también si la clave no existe. El banco
combinado suma 328 casos, 703 liberaciones y 263 comprobaciones previas a liberar.

La ampliación de [alta y ciclo registrado](contracts/REGISTRY-INSERTION.md) añadió 80
casos de inserción y cinco secuencias originales de alta, búsqueda y destrucción de POP.
Se alcanzan los helpers CRT y HeapAlloc real; no se sustituyen por resultados ficticios.
En esa fase, el recibo combinado sumaba 413 casos, 45 reservas, 718 liberaciones y 278
comprobaciones previas a liberar. Quedaron entonces pendientes los identificadores
automáticos, el error de clave duplicada y el fallo de reserva.

La [generación automática y el bloqueo local](contracts/AUTOMATIC-IDS.md) añadieron
36 ciclos y tres pruebas del helper de adquisición, dos con contención controlada.
Se comprueba el contador de 32 bits, incluido wrap a cero, y la suma de tipo sin
truncamiento final a 16 bits. El bloqueo se libera antes de insertar: no cubre toda
la mutación de tabla. El recibo actual suma 452 casos, 81 reservas, 790 liberaciones
y 350 comprobaciones previas a liberar. La mutación paralela del registro sigue abierta.

El [mapa de actualización de POP](contracts/POP-UPDATE.md) conserva un grafo normal
de 1.147 instrucciones y 3.912 bytes, con 71 llamadas (seis indirectas). Eso no equivale
a ejecutar la actualización entera. La [primitiva de tamaño](contracts/POP-SIZE.md)
pasó 1.362 fixtures completos: 42 incluyen estadísticas ya pobladas, con cambios en
fila, mapa, agregado y array por tipo. Los callees de esos caminos se ejecutan de verdad
en Unicorn. La conversión x87/entero observada en otros sitios sigue pendiente de un
contrato numérico completo; no se etiqueta como RNG.

El [banco de conversión flotante](contracts/FLOAT-CONVERSION.md) ejecutó después
1.344 combinaciones nativas de los cuerpos originales. La ruta rápida escribe EAX
de 32 bits y conserva EDX; la alternativa devuelve EDX:EAX de 64 bits. Se guardan
contraejemplos a intercambiar sus resultados, además de controles de estado FPU.
En esa primera fase, las entradas se cargaron desde binary64, con precisión x87 de
64 bits y excepciones enmascaradas.

La ampliación a extended80 llevó el banco a 3.360 casos y refutó un modelo demasiado
general de truncamiento. Para `1-2^-64`, la cuantización binary64 puede producir uno
en la ruta rápida y cero en la alternativa, dentro del rango de signed32. Cerca de
los límites de signed64 también importan el rango intermedio FISTP y el atajo de
INT64_MIN. Se conservan las ocho discrepancias del primer modelo ampliado y sus
fuentes. El modelo racional corregido coincide con las observaciones; no se proclama
equivalencia para todas las entradas extendidas o controles de precisión.

La [primitiva de transferencia de POP](contracts/POP-TRANSFER.md) pasó 1.504 fixtures
completos con sus callees reales, destinos inicialmente no vacíos y flag de tipo cero.
Se contrastan población limitada, selección de contadores, producto modular de saldo
y cambio de región. Un destino que alcanza el límite puede registrar toda la cantidad
solicitada aunque su tamaño efectivo aumente menos; no se equiparan esos contadores
con cambios efectivos sin analizar los llamadores. Copia, reserva y wrappers completos
siguen pendientes.

La [reutilización e inicialización parcial](contracts/POP-REUSE.md) añadió 726 fixtures
completos de la inicialización, del núcleo con destino vacío y de los dos wrappers
cuando encuentran un slot reutilizable o una tupla coincidente. Se ejecutan los
copiadores y memmove originales con capacidad existente. La inicialización conserva
campos que no reinicia y bytes fuera del rango lógico de los buffers. Append,
expansión y constructor completo permanecen pendientes.

La [construcción, copia y append](contracts/POP-APPEND.md) añadió después 594 fixtures,
incluidos 324 recorridos completos de los dos wrappers sin coincidencia y con capacidad
libre. Ejecutan constructor, copia, destructor temporal y transferencia originales.
La copia reconstruye identidad, referencias y distribuciones; reinicia los contadores
y escribe dos cachés globales. Se prueba append con origen externo o en cada posición
válida del mismo vector. El constructor se ejecuta con catálogos vacíos y singletons
ya existentes: heap, expansión, catálogos poblados y excepciones siguen pendientes.

La [expansión del vector](contracts/POP-GROWTH.md) se contrastó después en 126 casos
nativos: 126 reservas reales, 123 liberaciones y 123 snapshots completos previos a
liberar. Incluye origen externo o cada posición válida del mismo vector. La expansión
llama al constructor selectivo de los elementos anteriores y a sus destructores,
antes de publicar el nuevo descriptor; no equivale a memcpy. Otros 584 fixtures
ejecutan la selección de capacidad hasta sus fronteras de reserva/error/retorno.
Los vectores internos y catálogos están vacíos: distribución poblada, fallo de heap,
referencias vivas y excepciones permanecen sin validar.

La ampliación posterior añade 120 casos con ocho buffers internos por POP, incluidos
rangos lógicos vacíos con capacidad no nula. El banco combinado suma 246 casos,
2.946 reservas y 2.151 liberaciones originales. Contrasta copias profundas con
capacidad ajustada al rango lógico y el orden de liberación de los buffers antiguos,
sin copiar sus bytes de capacidad sobrante. Incluye origen interno ya reubicado.
Los catálogos siguen vacíos; no demuestra preservación de referencias externas,
catálogos poblados, fallo de reserva ni concurrencia.

La [copia con catálogos](contracts/POP-CATALOG-COPY.md) añadió 216 casos nativos y
5.712 palabras de metadatos contrastadas. Después de copiar los buffers, el
constructor de copia reconstruye sus prefijos desde entradas de dos catálogos.
Si hay elementos lógicos adicionales, conserva la cola copiada; no confundirla con
capacidad sin usar. El banco combinado suma 462 casos, 6.858 reservas y 4.635
liberaciones. El constructor con tipo con catálogos no vacíos sigue sin ejecutarse;
ocho instrucciones adicionales no prueban por sí solas esa ruta completa.

La [construcción/destrucción con catálogos](contracts/POP-CONSTRUCTION.md) añadió
192 ciclos nativos completos. Cruza longitudes A/B 0/1/3/7, patrones de memoria y
cuatro modos de caché; contrasta buffers de valores cero, metadatos, payload antes
y después de destruir y liberaciones reales. El constructor conserva cachés no
nulas y rellena sólo las ausentes en este dominio. El banco combinado suma 654
casos, 8.010 reservas, 5.787 liberaciones y 7.824 palabras de metadatos contrastadas.
Los singletons ya existen, el recurso opcional permanece excluido y no hay registro vivo.

El [recurso opcional de POP](contracts/POP-OPTIONAL.md) añadió 192 ciclos completos
con el byte de tipo `+0x39C` activo. El bloque de 256 bytes contiene dos pools con
vtable vinculada por RTTI a `CGoodsPool`, cada uno con un mapa inicial de 64 bytes
cero y un vector cuyo primer elemento procede de un global de ocho bytes. Se
contrasta el objeto completo y la liberación de ambos buffers antes del recurso.
El banco combinado suma 846 casos, 9.738 reservas y 7.515 liberaciones originales.
Los campos del recurso y la copia posterior con datos siguen parcialmente abiertos.

La [copia de CGoodsPool](contracts/GOODS-POOL-COPY.md) añadió 540 casos emulados y
480 nativos. Copia un prefijo de bytes del mapa, ajusta la longitud del vector y
copia valores empezando por índice uno. El primero conserva el del destino o es
cero si resize lo crea; 360 contraejemplos refutan el modelo de copia literal del
vector completo. La rama nativa cubre crecimiento geométrico 6→9 y comprueba
capacidad nueva sin usar. El banco combinado suma 1.326 casos, 9.870 reservas y
7.599 liberaciones; copiar el recurso completo desde CPop sigue pendiente.

La [copia CPop con recurso fuente](contracts/POP-OPTIONAL-COPY.md) añadió 180
secuencias completas. Asigna sólo el primer pool; el segundo y los campos restantes
conservan los valores de construcción del destino, contrastados frente a fuentes
con patrones distintos. La expansión del primer vector libera su buffer inicial
antes de publicar la nueva terna, y se comprueba esa liberación intermedia. El
banco combinado suma 1.506 casos, 10.518 reservas y 8.247 liberaciones originales.
Distribuciones/catálogos poblados junto con este recurso, registro vivo y errores
siguen pendientes.

La ampliación de [copia CPop con recurso](contracts/POP-OPTIONAL-COPY.md) combinó
los ocho buffers de distribución, catálogos poblados y recurso opcional en 216
secuencias completas. Contrasta metadatos, colas lógicas, copia parcial del recurso
y orden de todas las liberaciones en una misma ejecución. El banco suma 1.722
casos, 12.894 reservas y 10.623 liberaciones; origen y catálogos permanecen intactos.
Registro vivo y referencias externas a objetos reubicados siguen pendientes.

La [identidad registrada de CPop](contracts/POP-REGISTERED-IDENTITY.md) añadió 108
copias y 108 expansiones con alta/baja reales. Copiar y destruir el destino conserva
el origen registrado; expandir el vector sintético destruye y da de baja el elemento
antiguo sin reasignar su clave a la copia. El resolver sin escritura puede conservar
un puntero obsoleto aunque devuelva cero; la variante de actualización lo borra.
No se interpreta ese movimiento sintético como el almacenamiento global del juego.
El banco suma 1.938 casos, 13.218 reservas y 10.947 liberaciones originales.

Los [llamadores y consumo de vectores](contracts/POP-VECTOR-CALLERS.md) añaden 324
llamadas completas al wrapper de `+0x30C`, más fragmentos separados de ruta de
contexto y limpieza. Se contrastan los tipos RTTI de país/provincia y los stores
de sus descriptores. El consumidor candidato `0x004BA780` recorre el mismo vector,
se llama antes de economía en el CFG diario acotado y su cola vacía tamaño/saldo
del slot. La interpretación de contenedores intermedios sigue marcada como inferencia;
esa fase no ejecutó el consumidor completo ni una traza end-to-end del tick.

El [factory de nodos CPop](contracts/POP-FACTORY.md) añadió 1.053 ciclos nativos de
creación y retirada. Selecciona el tipo, construye un temporal con tipo nulo,
reserva 648 bytes, enlaza el nodo, registra una clave `(0x2E,id anterior)` mediante
el slot virtual original y establece tipo/región. El ID procede del contador
dedicado `0x00F09568`, con wrap contrastado; el contador genérico no cambia.
Incluye 648 ciclos con catálogos poblados: el temporal y su copia reservan
buffers separados, reconstruyen metadatos y los liberan en orden inverso.
El destructor libera las distribuciones del nodo antes del enlace de registro;
la expectativa contraria fue refutada en el primer intento poblado.
El banco suma 2.991 casos, 23.964 reservas y 21.693 liberaciones originales.
Se distingue ahora el constructor con tipo `0x00954F40` de la variante con getter
de tipo nulo `0x00954A40`; las etiquetas anteriores no son nombres de C++ recuperados.
El [consumidor completo](contracts/POP-CONSUMER.md) añade después 1.080 llamadas
nativas con creación de nodo, árboles de movimientos preexistentes, limpieza de
slot y pasada final por tres buckets. El banco suma 4.071 casos. Fusión, otras
claves de movimiento, selector alternativo y un tick real siguen abiertos.
La fase [de fusión](contracts/POP-MERGE.md) añade después 3.780 ejecuciones completas
del helper y 1.152 consumidores nativos con un destino compatible existente.
El promedio usa productos y suma con wrap antes de dividir; 1.530 fixtures refutan
sustituirlo por una media de precisión ilimitada. El saldo limitado y sus
contadores reciben tratamientos distintos. El banco nativo suma 5.223 casos.

El [contrato operativo del RNG](contracts/RNG.md) documenta además tres entradas,
sus registros, escrituras, modelo con signo y conexión con el fragmento diario.
Los casos emulados y sus límites se mantienen separados de las afirmaciones estáticas.

- Recuperar límites y tipos tras la corrección de no retorno; el primer pase agotó
  su límite, el reanálisis posterior terminó y los cuerpos siguen siendo candidatos.
- Contrastar el flujo del tick con una traza de ejecución real y registrar base ASLR.
- Auditar llamadas indirectas, excepciones y reentrada antes de formular un orden global.
- Reconstruir contratos de RNG, POPs y economía con entradas, escrituras y efectos laterales.
- La función semántica `function_at` de reverify permanece `INCONCLUSIVE` con el
  backend instalado; los bytes verificados no resuelven ese límite.

La [selección entre destinos](contracts/POP-SELECTION.md) ejecuta otros 305
consumidores completos en emulación y 447 prefijos que paran sin coincidencia
antes del factory. Hay prioridad entre pasadas y orden de lista dentro de cada
una; 45 fixtures refutan buscar una única coincidencia por nodo sin esa prioridad.
La pasada exacta ignora `+0x3D9`; la alternativa de campo inferior elige el primero,
con seis contraejemplos a minimizar dicho campo.

La [elección de tipo antes del factory](contracts/POP-FACTORY-SELECTION.md) añade
1.536 consumidores nativos completos y 18.432 fragmentos independientes. Gana
la última entrada elegible del catálogo, comparada contra el campo de la fuente
original. Hay 50 contraejemplos nativos a minimizar ese campo. Se ejecutan los
predicados virtuales originales y el factory, con bucket/identidad/retirada
contrastados; el banco nativo suma 6.759 casos.

El [selector interno del factory](contracts/FACTORY-INTERNAL-SELECTOR.md) añade
2.178 llamadas nativas completas con predicados virtuales originales. Recorre
filas de 32 bytes del contexto indexado por `propietario+0x58`; retorna el primero
entre solicitado y alternativo que aparece, o solicitado si ninguno. Ambos
resultados y preservación de fixtures/ABI/FS:0 están contrastados; banco nativo
de 8.937 casos sin sumar nuevas reservas o liberaciones en esta fase.

La integración del selector interno añade 960 factories/retiradas nativos. En
216 casos cambia al alternativo y se verifican el tipo del payload y su bucket,
además de identidad, handle y snapshots de liberación. El banco nativo suma
9.897 casos, 31.116 reservas y 29.997 liberaciones. Sigue pendiente combinar ese
cambio interno con la elección previa del consumidor completo.

## Cotas de precios en el mercado mundial

El contrato de [acotación de precios](contracts/PRICE-CLAMP.md) demuestra la
representación en punto fijo de \(2^{15} = 32768\) para los precios de mercado en
`0x00482930` (llamada desde `Economy_Update` en `0x00489BA6` y `EconomyManager_UpdateFull`
en `0x0068BF4A`).

Las cotas mínima y máxima están definidas por los doubles `kPriceMinFactor`
en `0x00E45C30` (`6554.10009765625` = \(0.2 \times 32768 + 0.5\)) y `kPriceMaxFactor`
en `0x00E45C28` (`163840.5` = \(5.0 \times 32768 + 0.5\)). El sesgo de \(+0.5\)
redondea hacia el entero más próximo al truncar con el helper `0x00B31C36`.
Reverify comprueba 36 afirmaciones de bytes, instrucciones y dos sitios CALL de llamada,
además de controles negativos contrastados (control falso refutado e invalidación dependiente).
Unicorn emula 228 fixtures con la secuencia aritmética y condicional original PE32 de 64 bits,
con 0 discrepancias frente a `price_clamp_model.py`. Si el precio bruto rebasa las cotas,
se fija a la cota correspondiente y se registra el evento mediante `0x0047DA50`.

## Probabilidad diaria de eventos y MTTH

El contrato de [MTTH y probabilidad diaria](contracts/EVENT-MTTH.md) demuestra la
rutina `Event_ComputeMTTHProbability` en `0x008AE380` (llamada desde `EventManager_DailyScan`
en `0x008A7E05` para eventos nacionales y `0x008A7FE6` para eventos provinciales).

La función lee el MTTH base en milésimas de día en `[this + 8]`. Si existen modificadores,
evalúa sus disparadores virtuales `[vtable + 0x18]` (`__thiscall`, `ret 4`) y aplica sus
factores mediante aritmética SSE escalada con los doubles `1000.0` en `0x00E45660` y
el sesgo de redondeo `0.0005` en `0x00E45840`. La conversión final divide el MTTH efectivo
entre 1000 usando multiplicación por constante mágica `0x10624DD3`. Si el resultado es
\(\le 1\) día, devuelve \(1.000.000\) (100% diario). En caso contrario calcula
\(\lfloor (\text{mode} \times 1.000.000) / \text{días} \rfloor\), acotado estrictamente a
\([1, 1.000.000]\). El valor se compara posteriormente en `0x008A7E3C` contra una tirada
uniforme del generador Mersenne Twister en `0x00F0ECF0`.

Reverify comprueba 44 afirmaciones de bytes, instrucciones y sitios CALL, con controles
negativos contrastados. Unicorn emula 602 fixtures sobre el código máquina original cubriendo
MTTH de 0 a 2.000.000 de días, fracciones y modos de 1 a 100 sin discrepancias frente
a `mtth_model.py`.

## Ponderación de opciones de eventos por la IA (`ai_chance`)

El contrato de [ponderación de opciones de IA](contracts/EVENT-AI-CHANCE.md) demuestra la
rutina `EventOption_EvaluateAIChance` en `0x008AEB00` (invocada desde `Event_Fire` en
`0x008A8268` para la suma del peso total de opciones y en `0x008A8325` para la selección
ponderada por tirada aleatoria).

La función lee el peso base en `[this + 8]`. Si existen modificadores en el vector
`[this + 0xC]..[this + 0x10]`, evalúa sus disparadores virtuales `[vtable + 0x18]`.
Aplica un cortocircuito estricto si cualquier condición devuelve `AL == 0` (omitiendo
el modificador). Si todas las condiciones son ciertas, multiplica por el factor en
milésimas `[mod + 0x20]` y divide entre 1000 con `0x00AC02A0`. Si el acumulador cae a
\(\le 0\), interrumpe inmediatamente el recorrido de modificadores restantes.
La fase final multiplica por `[this + 0x1C]` y divide entre 1000, almacenando el resultado
en `*[ebp + 0xC]` y retornando dicho puntero en `EAX`.

Reverify comprueba 33 afirmaciones de instrucciones y los dos sitios CALL en `Event_Fire`,
con control negativo refutado e invalidación dependiente. Unicorn emula 97 fixtures
sobre el código máquina original sin discrepancias frente a `ai_chance_model.py`.

## Despacho y encolado de eventos (`CCountryEventEffect::Execute`)

El contrato de [despacho y encolado de eventos](contracts/EVENT-SPAWN.md) demuestra la
rutina virtual `CCountryEventEffect::Execute` en `0x0088D370` (`vtable[11]` en `0x00E2B43C`),
invocada por comandos de efecto como `country_event = { id = <ID> days = <DELAY> }`.

La función:
1. Genera un valor pseudoaleatorio de tirada a partir de dos iteraciones LCG MSVC
   (\(s_{k+1} = s_k \times 214013 + 2531011\)) sobre la semilla en `[scope + 0x40]`,
   multiplicando los 15 bits altos de ambas tiradas (\(r_1 \times r_2\)) y pasando el
   resultado a `0x008A8650`.
2. Busca el identificador del evento `[this + 0x20]` en el registro de objetos `0x01258A98`
   con clave de tipo `0x27` (Evento de País). Si el registro o la entrada no existen, aborta.
3. Evalúa el retraso `delay = [this + 0x24]`:
   - Si `delay <= 0`: disparo inmediato mediante `0x008A8120` (`CCountryEvent::Fire`).
   - Si `delay > 0`: lectura del país destinatario en la tabla `[0x012587E4 + 4][scope + 0x0C]`
     e invocación de `0x00540A70` (`CCountry::AddDelayedEvent`), asignando una estructura de 88
     bytes (`CDelayedEvent`, vtable `0x00E2C858`, tipo `0x18D`, contador `+0x54`) e insertándola
     en el vector `country + 0x68`.

Reverify comprueba 37 afirmaciones (vtables `CCountryEventEffect` y `CProvinceEventEffect`,
instrucciones y llamadas), con control negativo refutado e invalidación dependiente. Unicorn
emula 66 fixtures con 0 discrepancias frente a `event_spawn_model.py`.

## Consumo diario de eventos diferidos (`CCountry::ProcessDelayedEvents`)

El contrato de [procesamiento diario de eventos diferidos](contracts/EVENT-DELAYED-TICK.md)
demuestra el bucle `0x0050B5C8..0x0050B696` dentro de `CCountry::DailyUpdate` (`0x005091A0`).

El bucle:
1. Itera sobre el vector `[ebx + 0x68]..[ebx + 0x6C]`.
2. Valida la vigencia del objetivo con `0x008A58C0(edi)`. Si devuelve 0, encola el evento
   en la lista de remoción `[ebp - 0x5C]` sin dispararlo.
3. Si es válido, ejecuta `dec dword ptr [edi + 0x54]`. Si el contador restante supera 0,
   continúa el bucle sin disparar (retención de espera).
4. Si el contador alcanza \(\le 0\), prepara el contexto con `0x008A6620`, dispara el evento
   vía `0x008A8120` (`CCountryEvent::Fire`) y lo encola en la lista de remoción.
5. Al finalizar el recorrido, elimina cada entrada encolada del vector `country + 0x68`
   mediante `0x004BE200` y libera la lista auxiliar con `0x008601B0`.

Reverify comprueba 27 afirmaciones de instrucciones, con control negativo refutado e invalidación
dependiente. Unicorn emula 37 series de fixtures (individuales, combinadas, expiradas y descartadas)
con 0 discrepancias frente a `delayed_event_tick_model.py`.

## Despacho y encolado de eventos provinciales (`CProvinceEventEffect::Execute`)

El contrato de [despacho y encolado de eventos provinciales](contracts/PROVINCE-EVENT-SPAWN.md)
demuestra la rutina virtual `CProvinceEventEffect::Execute` en `0x0088D6B0` (`vtable[11]` en
`0x00E2B474`), invocada por comandos de efecto como `province_event = { id = <ID> days = <DELAY> }`.

La función:
1. Genera un roll mediante dos pasos LCG idénticos sobre `[scope + 0x40]`, inicializando la
   instancia con `0x008A8650`.
2. Busca el evento con clave `(0x27, id)` en el registro `0x01258A98` vía `0x009C1D40`.
3. Evalúa el retraso `[this + 0x24]`:
   - Si `delay <= 0`: disparo inmediato vía `0x008A8120` (`Event_Fire`).
   - Si `delay > 0`: obtiene la provincia destino en la tabla `[0x012588E8 + 0xACC][scope + 0x10]`
     e invoca `0x004B1FC0` (`CProvince::AddDelayedEvent`), encolando el objeto `CDelayedEvent`
     (88 bytes) en el vector provincial `province + 0x384`.

Reverify comprueba 36 afirmaciones de bytes, vtables e instrucciones, con control negativo refutado
e invalidación dependiente. Unicorn emula 66 fixtures con 0 discrepancias frente a `province_event_spawn_model.py`.

## Consumo diario de eventos provinciales diferidos (`CProvince::ProcessDelayedEvents`)

El contrato de [procesamiento diario de eventos provinciales diferidos](contracts/PROVINCE-EVENT-DELAYED-TICK.md)
demuestra el bucle `0x004B1E16..0x004B1FA5` en `CProvince::DailyUpdate`.

El bucle:
1. Itera sobre el vector `province + 0x384` (`begin = +0x384`, `end = +0x388`).
2. Decrementa `dec dword ptr [ebx + 0x54]`. Si `delay > 0`, continúa el recorrido.
3. Si `delay <= 0`, dispara el evento con `0x008A8120` (`Event_Fire`).
4. Remueve de inmediato la entrada desplazando los elementos siguientes con `0x00AAE480` (`memmove`),
   decrementa `[edi + 0x388] -= 4` e invoca el destructor escalar virtual `[ebx]->vtable[0](1)`.
5. **Comportamiento in-situ del motor:** Al borrarse el evento sin decrementar el puntero iterador
   `[esp + 0x28]` (que ya fue avanzado en `+4`), el elemento contiguo desplazado a la posición actual
   es omitido en el tick actual y procesado en el día siguiente.

Reverify comprueba 25 afirmaciones de instrucciones, con control negativo refutado e invalidación
dependiente. Unicorn emula 21 series de fixtures con 0 discrepancias frente a
`province_event_delayed_tick_model.py`.

## Dinámica de Precios y Acotación Diaria del 1% (`CMarket::ApplyDailyPriceDelta`)

El contrato de [acotación de paso diario y zona muerta](contracts/MARKET-PRICE-DELTA.md)
demuestra la inicialización de la constante global de paso diario en `0x00BD2DC0` y el bucle
de ajuste en `0x00482B8C..0x00482C41`.

Comportamiento:
1. En el arranque del juego, `0x00BD2DC0` toma la constante de punto flotante `328.17999`
   en `0x00E458F8` y mediante `_ftol2` almacena en `0x0125B9E0` el entero de 64 bits `328`
   (\(\lfloor 0.01 \times 32768 + 0.5 \rfloor\)), correspondiente exactamente al 1% de variación máxima.
2. Tras calcular el precio objetivo no acotado a partir del ratio oferta/demanda y la curva
   de elasticidad, el motor evalúa la desviación respecto al precio vigente:
   - **Zona muerta de histéresis:** Si \(|\text{target} - \text{current}| \le 328\), la variación es
     descartada y \(\Delta = 0\) (el precio permanece invariable).
   - **Paso acotado:** Si la variación supera el umbral, el precio se mueve en pasos discretos de
     \(\pm 328\) (\(\pm 1\%\) por día).
   - **Clamp final:** El nuevo precio resultante se restringe al intervalo permitido por el bien
     mediante la rutina de clamp `0x00484BC0`.

Reverify comprueba 19 afirmaciones de instrucciones y constantes, con control negativo refutado
e invalidación dependiente. Unicorn emula 67 fixtures con 0 discrepancias frente a `market_price_delta_model.py`.

## Curva de Elasticidad y Sensibilidad de Precios de Mercado (`CMarket::CalculateSensitivityMultiplier`)

El contrato de [curva de sensibilidad de precios](contracts/MARKET-SENSITIVITY-CURVE.md)
demuestra la función de 795 bytes en `0x00482610..0x0048292B`, invocada en `0x00482B65`
para obtener el multiplicador de precio a partir del ratio oferta/demanda.

El algoritmo opera en punto fijo de 15 bits fraccionarios (\(1.0 = 32768\)):
1. **Ratio de mercado:**
   $$\text{ratio} = \left\lfloor \frac{\text{supply} \times 32768}{\text{demand}} \right\rfloor$$
2. **Tabla escalonada discreta:** Para ratios bajos (\(\text{ratio} < 21823 \approx 0.666\)), aplica
   una escala de 13 tramos discretos (\(0.2230, 0.2580, 0.2880, 0.3160, 0.3330, 0.3530, 0.3770, 0.4080, 0.4470, 0.5000, 0.5770, 0.7000, 0.8160\))
   que amortiguan el recalentamiento de precios.
3. **Fallback sub-lineal por raíz cuadrada:** Para \(\text{ratio} \ge 21823\), la rutina `0x0048C080`
   aplica una curva continua basada en la raíz cuadrada de la sobreoferta:
   $$\text{multiplier} = \left\lfloor \sqrt{\frac{\text{ratio}}{32768.0}} \times 32768.0 + 0.5 \right\rfloor$$
   - Para equilibrio (\(\text{supply} = \text{demand}\), \(\text{ratio} = 32768\)): \(\text{multiplier} = 32768\) (\(1.0000\)).
   - Para sobreoferta doble (\(\text{ratio} = 65536\)): \(\text{multiplier} = 46341\) (\(\approx 1.4142\)).
4. **Requisitos de FPU:** Se confirmó que el runtime de MSVC inicializa el registro de control de
   FPU en `0x027F` (precisión de 53 bits / double precision).

Reverify comprueba 38 afirmaciones de instrucciones, llamadas y constantes, con control negativo
refutado e invalidación dependiente. Unicorn emula 286 fixtures con 0 discrepancias frente a
`market_sensitivity_curve_model.py`.

## Producción Industrial y Consumo de Insumos (`CProductionType::ProduceGoods`)

El contrato de [producción industrial y consumo de insumos](contracts/FACTORY-PRODUCTION.md)
demuestra la rutina de 352 bytes en `0x004DD470..0x004DD5D0`, invocada por `0x004F3560`
en `CStateBuilding::Produce` (fábricas de estados industriales) y `0x00484573` en el mercado.

El algoritmo calcula:
1. **Producción efectiva de salida (`effective_output`):**
   Multiplica la salida base `base_output` (`[eax + 0x20]`) por el modificador de rendimiento de empleados
   `throughput_modifier` (`[eax + 0x30]`) mediante `FixedPoint_Multiply` (`0x00AC9F20`).
   Luego promueve el nivel entero de la fábrica `factory_level` (`[ebp + 0x14]`) a punto fijo (\(\text{level} \ll 15\))
   y ejecuta una segunda multiplicación:
   $$\text{effective\_output} = \text{FixedPoint\_Multiply}(\text{base\_output} \times \text{throughput}, \text{level} \ll 15)$$
2. **Inyección directa a la oferta de mercado:**
   Inyecta `effective_output` al pool de oferta del bien en el mercado mundial mediante
   `0x0047DBB0` y `0x0047DE60`.
3. **Consumo de insumos de la receta (`effective_input`):**
   Itera sobre el vector de insumos del tipo de producción (`0x004DD4F0..0x004DD5A1`):
   Para cada insumo con requerimiento no nulo, multiplica el insumo base por el modificador de
   eficiencia `efficiency_modifier` (`[ebp + 0x18]`) y por `effective_output`:
   $$\text{input\_consumed} = \text{FixedPoint\_Multiply}(\text{input\_base} \times \text{efficiency}, \text{effective\_output})$$
   El insumo consumido se deduce del inventario de la fábrica y se añade a la demanda de mercado.

Reverify comprueba 34 afirmaciones de instrucciones y llamadas, con control negativo refutado
e invalidación dependiente. Unicorn emula 150 fixtures con 0 discrepancias frente a `factory_production_model.py`.

## Cálculo y Acotación de Life Rating Provincial (`CProvince::CalculateEffectiveLifeRating`)

El contrato de [cálculo de life rating provincial](contracts/PROVINCE-LIFE-RATING.md)
demuestra la rutina de 144 bytes en `0x004B9BD0..0x004B9C5F`, invocada por `0x004B1DC4`
en `CProvince::DailyUpdate` para determinar las condiciones de habitabilidad y crecimiento de la población.

El algoritmo calcula:
1. **Punto fijo base:**
   Convierte el valor base `base_life_rating` (entero o punto fijo base en `[ecx + 0x3C]`) a representación de 15 bits fraccionarios:
   $$\text{life\_rating\_fp} = \text{base\_life\_rating} \times 32768$$
2. **Modificador tecnológico de salud pública (`health_tech`):**
   Obtiene el nivel tecnológico de medicina/salud pública de la nación poseedora (`owner_country + 0x4B0`):
   $$\text{tech\_scaled} = \left\lfloor \frac{\text{health\_tech} \times 2^{30}}{32768000} \right\rfloor$$
   $$\text{tech\_factor} = 32768 + \text{tech\_scaled}$$
3. **Cálculo escalado preliminar:**
   $$\text{raw\_effective} = (\text{life\_rating\_fp} \times \text{tech\_factor}) \gg 15$$
4. **Clamping estricto (0 a 40.0):**
   Aplica delimitadores duros del motor:
   - Límite inferior: Si \(\text{raw\_effective} < 0\), se trunca a 0.
   - Techo absoluto: Si \(\text{raw\_effective} > 1310720\) (\(0x00140000 = 40.0 \times 32768\)), se trunca a `0x00140000`.
   - Se refuta formalmente la hipótesis de que una provincia pueda superar un Life Rating efectivo de 40.0, independientemente de los modificadores tecnológicos acumulados.

Reverify comprueba 29 afirmaciones de instrucciones y constantes, con control negativo refutado
e invalidación dependiente. Unicorn emula 199 fixtures con 0 discrepancias frente a `province_life_rating_model.py`.

## Recaudación Impositiva e Ingresos Nacionales (`CCountry::CalculateTotalTaxRevenue`)

El contrato de [recaudación impositiva e ingresos nacionales](contracts/COUNTRY-TAX-REVENUE.md)
demuestra la rutina de 122 bytes en `0x0052B780..0x0052B859`, invocada por `0x008383CF`
para calcular el ingreso fiscal global diario del país a partir de las configuraciones de impuestos por clase social.

El algoritmo calcula:
1. **Recorrido del vector de buckets impositivos:**
   El vector se ubica dinámicamente en `country + 0x0E0` (offset calculado como \(((1 + 13) \ll 4) = 224\)) usando la global `0x00F096C8` (= 1).
2. **Procesamiento de los tres estratos sociales (\(i \in \{0, 1, 2\}\)):**
   Accede a las instancias de `CTaxSetting` en `[country + 0xA0] + i*4`:
   - \(i = 0\): Pobres (`BUDGET_TAX_POOR`, token `0x874`).
   - \(i = 1\): Clase media (`BUDGET_TAX_MIDDLE`, token `0x875`).
   - \(i = 2\): Ricos (`BUDGET_TAX_RICH`, token `0x876`).
   Multiplica la base imponible (`tax_base` a offset `+0x50` / `+0x54`) por la tasa configurada en el slider (`rate` a offset `+0x60` / `+0x64`) mediante `0x00AC9F20` (`__allmul` de 64 bits en la CRT de MSVC):
   $$\text{product} = \text{tax\_base}_i \times \text{rate}_i$$
3. **Alineación de punto fijo y división escalar:**
   Aplica una máscara a los 15 bits fraccionarios inferiores de la parte baja (\(\text{product.lo} \ \& \ \text{0xFFFF8000}\))
   y divide con signo entre \(32,768,000\) (\(0x01F40000 = 1000 \times 32768\)) mediante `0x00AC02A0` (`__alldiv`):
   $$\text{class\_tax}_i = \left\lfloor \frac{\text{masked\_product}}{32768000} \right\rfloor$$
4. **Ingresos fiscales directos adicionales (\(i \ge 3\)):**
   Para índices mayores a las tres clases impositivas, suma directamente el valor del bucket (\(\text{bucket}[i]\)) sin escala adicional.
5. **Acumulación total:**
   Retorna en `ESI` la suma acumulada en punto fijo de 64 bits.

Reverify comprueba 44 afirmaciones de instrucciones, constantes y llamadas, con control negativo
refutado e invalidación dependiente. Unicorn emula 141 fixtures con 0 discrepancias frente a
`country_tax_revenue_model.py`.

## Modificador Administrativo del Gasto Nacional (`CCountry::CalculateAdministrativeSpendingModifier`)

El contrato de [modificador administrativo del gasto nacional](contracts/COUNTRY-ADMIN-MODIFIER.md)
demuestra la rutina de 163 bytes en `0x00538150..0x005381F2`, invocada por `0x00509F62` y `0x005077C2`
en `CCountry::DailyUpdate` para calcular los multiplicadores de eficiencia administrativa y política gubernamental.

El algoritmo calcula:
1. **Escalado tecnológico a 30 bits:**
   Obtiene el nivel tecnológico de administración/comercio en `[country + 0xBCC] + 0x7C` (`tech_val`),
   lo promueve con desplazamiento aritmético a la izquierda de 30 bits (\(\text{tech\_val} \ll 30\))
   y lo divide con signo entre \(32,768,000\) (\(0x01F40000 = 1000 \times 32768\)) mediante `0x00AC02A0` (`__alldiv`):
   $$\text{tech\_fp} = \left\lfloor \frac{\text{tech\_val} \ll 30}{32768000} \right\rfloor$$
2. **Bifurcación por política de gobierno (`ruling_party_flag`):**
   Comprueba la bandera del partido gobernante en `[country + 0x4CC]`:
   - Si `[country + 0x4CC] > 0`: selecciona el buffer de política A.
   - Si `[country + 0x4CC] \le 0`: selecciona el buffer de política B.
   Invoca el selector de políticas `0x0096A2C0` pasando las políticas activas en `[country + 0xA48]`, obteniendo
   el modificador de política de 64 bits `policy_mod`.
3. **Multiplicación escalar y desescalado:**
   Multiplica el modificador de política por \(32,768,000\) mediante `0x00AC9F20` (`__allmul` de 64 bits en la CRT):
   $$\text{product} = \text{policy\_mod} \times 32768000$$
   Y normaliza el resultado mediante desplazamiento aritmético a la derecha de 30 bits:
   $$\text{final\_modifier} = \text{product} \gg 30$$
   Retorna en `EDI` el modificador final de 32 bits con signo.

Reverify comprueba 35 afirmaciones de instrucciones, llamadas y offsets, con control negativo
refutado e invalidación dependiente. Unicorn emula 272 fixtures con 0 discrepancias frente a
`country_admin_modifier_model.py`.

## Doble Acotación y Fijación de Aranceles Nacionales (`CCountry::SetTariffRateAndClamp`)

El contrato de [doble acotación y fijación de aranceles](contracts/COUNTRY-TARIFF-CLAMP.md)
demuestra la rutina de 216 bytes en `0x00538070..0x00538147`, invocada por `0x00582500`
en `CChangeTariffs::Execute` y `0x00524A7B` en `CCountry::DailyUpdate` para fijar y delimitar estrictamente
la tasa arancelaria exterior del país según los límites establecidos por la política económica de gobierno.

El algoritmo calcula:
1. **Asignación preliminar:**
   $$\text{tariff\_rate} = \text{new\_rate}$$
2. **Piso arancelario (límite inferior):**
   Obtiene el límite mínimo de aranceles de la política económica en `[economic_policy + 0xE8]`,
   lo escala a punto fijo mediante desplazamiento de 30 bits y división con signo entre \(32,768,000\) (\(0x01F40000 = 1000 \times 32768\)) vía `0x00AC02A0` (`__alldiv`):
   $$\text{min\_scaled} = \left\lfloor \frac{\text{min\_limit\_raw} \ll 30}{32768000} \right\rfloor$$
   Aplica una comparación con signo de 64 bits (`cmp edx, ecx; jg; jl; cmp eax, edi; jae`):
   $$\text{tariff\_rate} = \max(\text{tariff\_rate}, \text{min\_scaled})$$
3. **Techo arancelario (límite superior):**
   Obtiene el límite máximo de aranceles de la política económica en `[economic_policy + 0xF0]`,
   lo escala con la misma fórmula matemática:
   $$\text{max\_scaled} = \left\lfloor \frac{\text{max\_limit\_raw} \ll 30}{32768000} \right\rfloor$$
   Aplica la comparación con signo de 64 bits:
   $$\text{tariff\_rate} = \min(\text{tariff\_rate}, \text{max\_scaled})$$
4. **Fijación final en memoria:**
   Almacena la tasa acotada definitiva en `[country + 0x1440]` y `[country + 0x1444]`.

Reverify comprueba 45 afirmaciones de instrucciones, llamadas, comparaciones y saltos condicionales,
con control negativo refutado e invalidación dependiente. Unicorn emula 350 fixtures con 0 discrepancias
frente a `country_tariff_clamp_model.py`.

## Consumo y Saturación de Cuotas de Promoción y Empleo (`CPromotionQuotaManager::ConsumeCapacity`)

El contrato de [consumo y saturación de cuotas de promoción](contracts/PROMOTION-QUOTA.md)
demuestra la rutina de 321 bytes en `0x004D1020..0x004D119E`, invocada por `0x00958486` en `CPop::Update`
(`0x00957EA0`) para gestionar la absorción demográfica hacia fábricas y clases sociales con capacidad acotada.

El algoritmo calcula:
1. **Condición de guarda inicial:**
   Verifica que la lista de destinos en `[manager + 0x60]` sea no nula y que la cantidad de población
   solicitada sea estrictamente positiva (\(*\text{inout\_requested\_amount} > 0\)). Si no, retorna de inmediato.
2. **Búsqueda en vector de destinos (\(\text{stride} = 16\)):**
   Calcula el número de entradas como \((end - begin) \gg 4\) y compara secuencialmente la clave de
   cada entrada con `target_key` (`cmp ebx, [ebp + 8]`).
3. **Clamping por capacidad remanente del destino:**
   $$\text{consumed} = \min(*\text{inout\_requested\_amount}, \text{entry.available\_capacity})$$
4. **Deducción conservativa simultánea:**
   - Reduce el remanente en el buffer de población:
     $$*\text{inout\_requested\_amount} = *\text{inout\_requested\_amount} - \text{consumed}$$
   - Deduce la capacidad consumida de la entrada en el vector:
     $$\text{entry.available\_capacity} = \text{entry.available\_capacity} - \text{consumed}$$
   - Deduce la cuota en el objeto destino (`[target_obj + 0x60]`):
     $$\text{target\_obj.quota} = \text{target\_obj.quota} - \text{consumed}$$
5. **Saturación y Desactivación de Destino:**
   Si tras la deducción la capacidad restante es menor o igual a cero (\(\text{entry.available\_capacity} \le 0\)),
   el motor busca el nodo en el árbol STL `std::_Tree` a `[target_list + 0x130]` y lo remueve mediante `0x004F2760`,
   impidiendo que otros POPs se promocionen a un empleo o estrato ya saturado.

Reverify comprueba 43 afirmaciones de instrucciones, saltos y llamadas, con control negativo
refutado e invalidación dependiente. Unicorn emula 106 fixtures con 0 discrepancias frente a
`promotion_quota_model.py`.

### 46. Actualización de Tamaño, Clamping y Disparo de Cuotas de POPs (`CPop::SetSize`)

El contrato de [actualización de tamaño de POPs](contracts/POP-SET-SIZE.md)
demuestra la rutina de 133 bytes en `0x00955FD0..0x00956054`, invocada por 6 puntos neurálgicos
en el bucle diario de demografía (`CPop::Update`), incluyendo deducciones e incrementos en promoción
(`0x009584C8`, `0x009584EB`), asimilación cultural (`0x009587BE`, `0x009587E1`) y conversión religiosa
(`0x00958A81`, `0x00958AA4`).

El algoritmo calcula:
1. **Clamping rígido de población en rango \([0, 2,000,000]\):**
   $$\text{clamped} = \begin{cases} 
   0 & \text{si } \text{new\_size} < 0 \\
   2,000,000 & \text{si } \text{new\_size} > 2,000,000 \ (0\text{x}1E8480) \\
   \text{new\_size} & \text{en otro caso}
   \end{cases}$$
   Evidencia: `0x00955FDA test edi, edi; jns ...; xor edi, edi` y `0x00955FE2 cmp edi, 0x1e8480; jle ...; mov edi, 0x1e8480`.
2. **Evaluación de estrato (`pop_type->flag_40` en `[eax + 0x40]`):**
   - Si `flag_40 == 0`: asigna directamente `[esi + 0x60] = clamped` sin consumir cuotas de promoción.
   - Si `flag_40 != 0`: compara `clamped` contra el tamaño actual `[esi + 0x60]`.
     - Si $\text{clamped} \ge \text{current\_size}$: no hay pérdida poblacional y salta al historial.
     - Si $\text{clamped} < \text{current\_size}$: calcula $\Delta = \text{current\_size} - \text{clamped}$,
       invoca `0x004EE550` para el buffer provincial e invoca `0x004D1020` para deducir cuotas de absorción.
3. **Rotación histórica de población de dos días:**
   $$[esi + 0x5C] = \text{prev\_size} \quad ([esi + 0x58])$$
   $$[esi + 0x58] = \text{clamped}$$
   Si $\text{prev\_size} == 0$ (primer día del POP), fija también $[esi + 0x5C] = \text{clamped}$.

Reverify comprueba 57 afirmaciones de instrucciones, saltos y llamadas, con control negativo
refutado e invalidación dependiente. Unicorn emula 1,218 fixtures con 0 discrepancias frente a
`pop_set_size_model.py`.

### 47. Transferencia Demográfica Bilateral y Absorción por Umbral Mínimo (`POP-TRANSFER-THRESHOLD`)

El contrato de [transferencia demográfica y umbral de supervivencia](contracts/POP-TRANSFER-THRESHOLD.md)
demuestra los 3 canales simétricos de transición demográfica en `CPop::Update`:
- Canal 1: Promoción (`0x009584A6..0x009584FB`, slot `[edi + 0x190]`, acumulador `[edi + 0x164]`).
- Canal 2: Asimilación cultural (`0x0095879C..0x009587F1`, slot `[edi + 0x194]`, acumulador `[edi + 0x164]`).
- Canal 3: Conversión religiosa (`0x00958A5F..0x00958AB4`, slot `[edi + 0x198]`, acumulador `[edi + 0x16C]`).

El algoritmo calcula:
1. **Evaluación del remanente:**
   $$\text{rem} = \text{source\_size} - \text{requested\_delta}$$
2. **Absorción forzada de micro-POPs por umbral mínimo (`[pop_type + 0x3C8]`):**
   $$\text{effective\_delta} = \begin{cases}
   \text{source\_size} & \text{si } \text{rem} < \text{pop\_type.min\_threshold} \ ([\text{edx} + 0\text{x}3\text{C8}]) \\
   \text{requested\_delta} & \text{en otro caso}
   \end{cases}$$
   Evidencia: `0x009584AD / 0x009587A3 / 0x00958A66 cmp ecx, [edx + 0x3c8]; jge ...; mov [edi + slot], ebx`.
   Si el residuo poblacional cayera por debajo del umbral mínimo del estrato, el motor absorbe el 100%
   del POP origen hacia el destino, extinguiéndolo para impedir la proliferación de micro-POPs.
3. **Deducción en POP origen:**
   $$\text{new\_source\_size} = \text{source\_size} - \text{effective\_delta}$$
   Invoca `CPop::SetSize(source, new_source_size)` y acumula $\text{new\_source\_size} - \text{source\_size}$ (negativo).
4. **Incremento en POP destino:**
   $$\text{new\_target\_size} = \text{target\_old\_size} + \text{effective\_delta}$$
   Invoca `CPop::SetSize(target, new_target_size)`.
   El acumulador del destino se actualiza con `(ebx - target_old_size) == effective_delta`.
5. **Conservación de masa demográfica:**
   A menos que el destino sature la cota absoluta de 2,000,000 habitantes, $\Delta_{\text{source}} + \Delta_{\text{target}} = 0$.

Reverify comprueba 72 afirmaciones de instrucciones en los 3 canales, con control negativo
refutado e invalidación dependiente. Unicorn emula 111 fixtures a través de los 3 canales
con 0 discrepancias frente a `pop_transfer_threshold_model.py`.

### 48. Agregación de Financiación y Gasto por Categoría con Clamping a Cero (`CCountry::CalculateCategorySpending`)

El contrato de [cálculo de gasto por categoría](contracts/COUNTRY-CATEGORY-SPENDING.md)
demuestra la rutina de 181 bytes en `0x00539760..0x00539874`, invocada en el bucle presupuestario
diario (`0x00539910`) y balance fiscal gubernamental (`0x00663027`, `0x0071DCFE`, `0x007205A1`)
para computar el gasto público consolidado de cada partida presupuestaria (educación, administración, etc.).

El algoritmo calcula:
1. **Ponderación de Canal 1 (Slider 1 en `[country + 0x1448]`):**
   Multiplica `table_1[idx_1]` por `slider_1` usando la CRT de 64 bits `0x00AC9F20` (`__allmul`) y escala a 15 bits fraccionarios:
   $$\text{term}_1 = \left\lfloor \frac{\text{table}_1[\text{idx}_1] \times \text{slider}_1}{32,768} \right\rfloor$$
2. **Ponderación de Canal 2 (Slider 2 en `[country + 0x1450]`):**
   $$\text{term}_2 = \left\lfloor \frac{\text{table}_2[\text{idx}_2] \times \text{slider}_2}{32,768} \right\rfloor$$
3. **Subsidio o Término Base Aditivo (Canal 3):**
   $$\text{term}_3 = \text{table}_3[\text{idx}_3]$$
4. **Ponderación de Canal 4 (Slider 3 en `[country + 0x1458]`):**
   $$\text{term}_4 = \left\lfloor \frac{\text{table}_4[\text{idx}_4] \times \text{slider}_3}{32,768} \right\rfloor$$
5. **Agregación y Clamping Rígido Inferior a Cero:**
   $$\text{raw\_total} = \text{term}_1 + \text{term}_2 + \text{term}_3 + \text{term}_4$$
   $$\text{final\_spending} = \begin{cases}
   0 & \text{si } \text{raw\_total} \le 0 \\
   \text{raw\_total} & \text{si } \text{raw\_total} > 0
   \end{cases}$$
   Evidencia: `0x0053983D test eax, eax; jl 0x53985e; jg 0x539847; test ecx, ecx; je 0x53985e` y bifurcación a buffer inicializado en 0 mediante `xorpd xmm0, xmm0`.

Reverify comprueba 95 afirmaciones de instrucciones y llamadas, con control negativo
refutado e invalidación dependiente. Unicorn emula 158 fixtures con 0 discrepancias frente a
`country_category_spending_model.py`.

### 49. Agregación Nacional de Unidades Provinciales y Normalización Tecnológica (`CCountry::CalculateNationalInfrastructure`)

El contrato de [infraestructura y modificadores tecnológicos](contracts/COUNTRY-INFRASTRUCTURE-MODIFIER.md)
demuestra la rutina de 460 bytes en `0x00530C70..0x00530E3B`, invocada por el despachador de subsistemas
nacionales en `0x00538063` para agregar las unidades de infraestructura de todas las provincias poseídas
y modularlas por las tecnologías e infraestructuras activas a nivel de estado.

El algoritmo calcula:
1. **Agregación de unidades de provincias (`[country + 0x9D8]` a `[country + 0x9DC]`):**
   $$\text{total\_units} = \sum_{p \in \text{provinces}} \text{GetProvinceUnits}(p)$$
   Invocando `0x004B8870` sobre cada puntero provincial de la tabla global `[0x12588E8 + 0xACC]`.
2. **Normalización tecnológica doble a 30 bits:**
   Para cada entrada activa (`flag_39 != 0`) en la lista `[0x125FDD8]`:
   $$\text{norm}_1 = \left\lfloor \frac{(\text{val}_{0x234} + \text{val}_{0x230}) \ll 30}{32,768,000} \right\rfloor$$
   $$\text{norm}_2 = \left\lfloor \frac{\text{val}_{0x238} \ll 30}{32,768,000} \right\rfloor$$
   $$\text{term}_i = (\text{norm}_1 \times \text{norm}_2) \gg 15$$
   y acumula $\text{sum\_terms} += \text{term}_i$, $\text{valid\_count} += 1$.
3. **Promedio ponderado tecnológico:**
   $$\text{avg\_mod} = \left\lfloor \frac{\text{sum\_terms}}{\text{valid\_count}} \right\rfloor$$
4. **Ponderación agregada y bono nacional de base:**
   $$\text{prod} = \left\lfloor \frac{(\text{total\_units} \ll 15) \times \text{avg\_mod}}{32,768} \right\rfloor$$
   $$[country + 0\text{x}1\text{A0}:0\text{x}1\text{A4}] = \text{prod} + (\text{base\_bonus} \ll 15)$$

Reverify comprueba 49 afirmaciones de instrucciones y llamadas, con control negativo
refutado e invalidación dependiente. Unicorn emula 124 fixtures con 0 discrepancias frente a
`country_infrastructure_model.py`.

### 50. Despachador de Modificadores Provinciales y de Líder (`CProvince::UpdateModifiers`)

El contrato de [despachador de modificadores provinciales](contracts/PROVINCE-MODIFIER-DISPATCH.md)
demuestra la jump table y switch de 8 slots en `0x004D3FF5..0x004D4067` dentro de `CProvince::UpdateModifiers`
(VA base `0x004D3BB0`), invocado en el bucle principal de actualización de provincias en `0x00686228`.

La lógica del despachador realiza:
1. **Indexación y acotación estricta de modificador:**
   $$\text{idx} = \text{modifier\_type} - 1$$
   Si $\text{unsigned}(\text{idx}) > 7$, ejecuta `ja 0x004D4067`, saltándose toda la acumulación y conservando el estado.
2. **Tabla de saltos canónica en `0x004D41F0`:**
   Despacha a 8 destinos canónicos (`0x004D400B, 0x004D4016, 0x004D4021, 0x004D402C, 0x004D4037, 0x004D4042, 0x004D404D, 0x004D4058`),
   donde extrae el modificador desde el objeto emisor `[ecx + 0x30]` con offsets `+0x524` a `+0x540` (por ejemplo slot 1 en `+0x528` correspondiente al factor de desgaste/atrito provincial).
3. **Acumulación aditiva en destino:**
   $$[esi + 0\text{x}280] = [esi + 0\text{x}280] + \text{slot\_value}$$

Reverify comprueba 38 afirmaciones de instrucciones binarias y bytes exactos de la tabla de saltos, con control negativo
refutado e invalidación dependiente. Unicorn emula 132 fixtures cubriendo todos los slots, valores neutros, acumuladores negativos
y valores fuera de rango con 0 discrepancias frente a `province_modifier_dispatch_model.py`.

### 51. Doble Acotación Política del Slider de Gasto Nacional (`CCountry::SetCategorySpendingSlider`)

El contrato de [doble acotación de slider de gasto](contracts/COUNTRY-CATEGORY-SPENDING-CLAMP.md)
demuestra la rutina de 216 bytes en `0x00538070..0x00538147` invocada por el subsistema de IA/Diario (`0x00524A7B`)
y por el despachador de comandos de jugador/UI (`0x00582500` en `CSetSpendingSliderCommand::Execute`).

La rutina implementa:
1. **Normalización de límites de política gubernamental:**
   Lee `[country + 0xA60]` (política económica del partido gobernante) y normaliza los límites inferior (`+0xE8`)
   y superior (`+0xF0`) escalando a 30 bits y dividiendo por $32,768,000$ vía `0x00AC02A0` (`__alldiv`):
   $$\text{min\_bound} = \left\lfloor \frac{\text{policy\_min\_raw} \ll 30}{32,768,000} \right\rfloor$$
   $$\text{max\_bound} = \left\lfloor \frac{\text{policy\_max\_raw} \ll 30}{32,768,000} \right\rfloor$$
2. **Clamping inferior estricto:**
   $$\text{step}_1 = \max(\text{proposed\_slider}, \text{min\_bound})$$
3. **Clamping superior estricto y almacenamiento:**
   $$\text{final\_slider} = \min(\text{step}_1, \text{max\_bound})$$
   $$[country + 0\text{x}1440 : 0\text{x}1444] = \text{final\_slider}$$

Reverify comprueba 70 afirmaciones de instrucciones y llamadores clave, con control negativo
refutado e invalidación dependiente. Unicorn emula 137 fixtures cubriendo todos los casos de acotación,
valores fuera de límites y negativos con 0 discrepancias frente a `country_spending_clamp_model.py`.

### 52. Puntuación de Base Naval y Eficiencia Costera (`CCountry::CalculateNavalBaseScore`)

El contrato de [puntuación de base naval](contracts/COUNTRY-NAVAL-BASE-SCORE.md)
demuestra la rutina en `0x0052FCD0..0x00530020` con el bloque de cálculo de eficiencia costera en `0x0052FF12..0x0052FFB9`,
invocado diariamente por el despachador de subsistemas nacionales en `0x0053805D`.

La rutina computa:
1. **Normalización por división de centenas:**
   Divide el suministro costero y la demanda naval por 100 con redondeo hacia cero usando la constante recíproca `0x51eb851f`:
   $$c_{14} = \text{trunc}(val_{14} / 100), \quad c_{28} = \text{trunc}(val_{28} / 100)$$
2. **Cálculo de razón en punto fijo:**
   $$\text{ratio} = \left\lfloor \frac{c_{14} \ll 30}{c_{28} \ll 15} \right\rfloor \quad (\text{vía } 0\text{x}00\text{AC}02\text{A}0)$$
3. **Doble acotación estricta [Piso 5%, Techo 100%]:**
   - Piso canónico: $5\%$ ($1638$) cargado como `1638.9000244140625` desde `0x00E45820` y truncado a entero.
   - Techo canónico: $100\%$ ($32,768 = 0\text{x}8000$).
   $$\text{ratio}_{\text{clamped}} = \max(1638, \min(32768, \text{ratio}))$$
4. **Ponderación acumulada en 64 bits:**
   $$\text{contrib} = \left\lfloor \frac{\text{ratio}_{\text{clamped}} \times \text{base\_weight}}{32,768} \right\rfloor$$
   $$[country + 0\text{x}198 : 0\text{x}19\text{C}] += \text{contrib}$$

Reverify comprueba 73 afirmaciones de instrucciones binarias y la constante de piso en `0x00E45820`, con control negativo
refutado e invalidación dependiente. Unicorn emula 127 fixtures cubriendo todos los regímenes de acotación y estados previos con 0 discrepancias frente a `country_naval_base_model.py`.

### 53. Asignación y Distribución Diaria de Cuotas por Estrato (`CProvincePromotionBuffer::AllocateTargetQuota`)

El contrato de [asignación de cuotas por estrato](contracts/PROVINCE-PROMOTION-TARGET-ALLOCATION.md)
demuestra la rutina de 428 bytes en `0x004EE150..0x004EE2FB` con 4 llamadores confirmados en actualización
demográfica de estado (`0x004C1412`), despacho de cuotas (`0x004D1638`), balance mensual (`0x004EF185`)
y subsistema industrial (`0x005221B0`).

La rutina implementa:
1. **Paso diario de promoción y democión con amortiguación:**
   Calcula la diferencia $\Delta = \text{desired} - \text{current}$.
   - Para promoción ($\Delta \ge 0$): escala por define provincial `[defines + 0x64]`, normalizado por $32,768,000$.
   - Para democión ($\Delta < 0$): amortigua por factor 4 y escala por `[defines + 0x68]`.
2. **Clamping rígido de paso mínimo demográfico:**
   El motor garantiza que todo paso diario activo tenga un módulo de **al menos 50 POPs**:
   $$\text{step}_{\text{clamped}} = \max(50, \text{scaled\_step})$$
   acotado superiormente por el delta pendiente $\Delta$.
3. **Distribución secuencial voraz a objetivos candidatos:**
   Recorre la lista de candidatos del tipo de POP (`pop_type->candidates`) y asigna vorazmente
   $A_i = \min(\text{remaining\_quota}, C_i)$, invocando al consumidor correspondiente (`0x004EE780` para promoción,
   `0x004EE650` para democión) y descontando $A_i$ hasta agotar la cuota o la capacidad disponible.

Reverify comprueba 170 afirmaciones de instrucciones y llamadores clave, con control negativo
refutado e invalidación dependiente. Unicorn emula 119 fixtures cubriendo regímenes de promoción, democión,
saturación parcial, clamping de 50 POPs y agotamiento de candidatos con 0 discrepancias frente a `province_target_quota_model.py`.

### 54. Agregación de Modificadores Tecnológicos y Suministro Militar (`CCountry::CalculateMilitarySupplyFactor`)

El contrato de [modificador de suministro militar y mantenimiento](contracts/COUNTRY-MILITARY-SUPPLY-FACTOR.md)
demuestra la rutina en `0x005203E3..0x0052047E` (156 bytes) en `CCountry::CalculateMilitarySupplyFactor`.

La rutina implementa:
1. **Acumulación aditiva de fuentes de doctrina y tecnología:**
   - Bono del partido gobernante: `[country + 0xA60]`, offset `+0x380`.
   - Modificador global base: `[defines_obj + 0x40]`, offset `+0x10`.
   - Modificador tecnológico: `[country + 0xBCC]`, offset `+0x60`.
2. **Normalización aritmética en punto fijo a 30 bits:**
   Divide la suma acumulada por la constante universal $32,768,000$ (`0x01F40000`) invocando la rutina matemática auxiliar `0x00AC02A0`.
3. **Piso rígido a cero y almacenamiento primario:**
   Asegura un factor no negativo ($\max(0, \text{factor})$) y lo persiste en `[country + 0x14D8]`.
4. **Reseteo de acumuladores y almacenamiento secundario:**
   - Si no hay vector activo (`[dummy_vec1 + 0x18] == [dummy_vec1 + 0x1C]`), copia `factor` directamente a `[country + 0x14DC]`.
   - Resetea los acumuladores de mantenimiento en `[country + 0x14E0]` y `[country + 0x13E8]` a 0.

Reverify comprueba 52 afirmaciones de instrucciones, accesos a singletons (`0x012586DC`, `0x01258A48`, `0x01258A3C`) y offsets de país,
con control negativo refutado e invalidación dependiente. Unicorn emula 126 fixtures con 0 discrepancias frente a `country_military_supply_model.py`.

### 55. Compuerta de Financiación con Margen de Reserva del 110% en Proyectos de Construcción (`CBuildingProject::UpdateFundingStatus`)

El contrato de [compuerta de financiación con margen de reserva](contracts/PROJECT-BUFFER-FUNDING-GATE.md)
demuestra la rutina en `0x004A4EB0..0x004A4F2E` (127 bytes, 51 instrucciones) con llamadores en actualización
de progreso y financiación de proyectos (`0x004A4FED`, `0x004A5005`) y el tick de inversión nacional (`0x005887A6`).

La rutina implementa:
1. **Discriminación de etapa del proyecto (`stage = [esi + 0x7C]`):**
   - Etapas activas con demanda de capital ($\{0, 1, 3\}$: preparación, acopio y construcción activa):
     evalúan la suficiencia de fondos mediante cálculo métrico con buffer.
   - Etapas no activas:
     - Si `stage == 4` (proyecto finalizado o clausurado): asigna `needs_funding = 0`.
     - Si `stage != 4` (etapa 2 o estados anómalos): asigna `needs_funding = 1`.
2. **Cálculo del umbral de reserva del 110%:**
   - Recupera el costo base total $C$ mediante `0x004A5020`.
   - Carga la constante flotante en `0x00E45BA0` ($36045.30078125$), truncada por `_ftol2` a $36045$ ($36045 / 32768 \approx 1.100006$).
   - Multiplica en 64 bits $C \times 36045$ con `_allmul` y divide por 32768 mediante desplazamiento aritmético a la derecha:
     $$\text{threshold} = (C \times 36045) \gg 15$$
     imponiendo un colchón obligatorio de reserva financiera del $+10.00\%$.
3. **Comparación lexicográfica de 64 bits y escritura de estado:**
   - Compara los fondos acumulados `[esi + 0x64 : esi + 0x60]` frente a `threshold`.
   - Si $\text{funds} < \text{threshold}$: asigna `needs_funding = 1` (requiere inversión adicional).
   - Si $\text{funds} \ge \text{threshold}$: asigna `needs_funding = 0` (suficiencia financiera alcanzada).
   - Persiste el byte en `[esi + 0x80]`.

Reverify comprueba 55 afirmaciones de instrucciones binarias, llamadores y constante flotante en `0x00E45BA0`,
con control negativo refutado e invalidación dependiente. Unicorn emula 142 fixtures cubriendo todas las etapas,
fondos límite, negativos y grandes con 0 discrepancias frente a `project_buffer_model.py`.

### 56. Reglas de Elegibilidad y Cupo Máximo de Fábricas Estatales (`CState::CanBuildFactory`)

El contrato de [elegibilidad y cupo de fábricas](contracts/STATE-FACTORY-BUILD-ELIGIBILITY.md)
demuestra la rutina de 483 bytes en `0x004D04B0..0x004D0692` (151 instrucciones) con llamadores en
decisión industrial de IA (`0x0052CAB1`, `0x0052CB07`) y la interfaz de construcción estatal (`0x008575CE`).

La rutina implementa:
1. **Restricción colonial rígida:**
   Verifica `[state + 0x84]`. Si el estado es colonial (`is_colonial > 0`), prohíbe la industrialización y retorna `0` (`false`).
2. **Tope universal de 8 fábricas por estado:**
   Calcula $\text{remaining\_slots} = 8 - [state + 0\text{x}68]$. Si las plazas restantes son menores a 1, retorna `0` (`false`).
3. **Restricción de no duplicidad de tipo en el estado:**
   Recorre la lista enlazada de fábricas del estado (`state + 0x60`, enlaces en `+0x224`). Si ya existe una fábrica del mismo tipo
   (`node->type == candidate_type`), retorna `0` (`false`).
4. **Heurísticas y reserva de cupo para la IA (`is_ai == true`):**
   - Rechaza duplicar categorías estratégicas en el mismo estado (`+0x13A` y `+0x13B`).
   - Si quedan sólo 1 ó 2 plazas ($\text{remaining\_slots} \le 2$), reserva obligatoriamente estos cupos para industrias
     estratégicas prioritarias (`+0x13A` o `+0x13B`), bloqueando industrias comunes.
5. **Prerrequisito tecnológico y portuario:**
   Si la fábrica exige tecnología (`candidate->tech != NULL`), consulta `0x004D0E70`. Si además requiere puerto (`tech->port != 0`),
   consulta `0x004D0FD0`. Si alguna condición falla, retorna `0` (`false`).
6. **Aprobación:**
   Si todas las reglas son superadas, retorna `1` (`true`).

Reverify comprueba 154 afirmaciones de instrucciones binarias y llamadores con control negativo
refutado e invalidación dependiente. Unicorn emula 141 fixtures con 0 discrepancias frente a `state_factory_build_model.py`.

### 57. Determinación de Moral y Organización Máxima de Regimientos (`CRegiment::CalculateMaxMorale`)

El contrato de [moral máxima de regimientos](contracts/REGIMENT-MAX-MORALE.md)
demuestra la rutina de 364 bytes en `0x005BFFA0..0x005C010C` (98 instrucciones) que calcula la moral
y organización máxima de una unidad militar terrestre o naval (`CRegiment` / `CSubUnit`).

La rutina implementa:
1. **Recuperación de moral base del tipo de regimiento:**
   Extrae la moral base `base_morale = [regiment_type + 0xB4]` (en escala de punto fijo / unidades enteras milésimas).
2. **Identificación de rama (Ejército vs Armada):**
   Consulta el método virtual en el slot 9 (`+0x24`, armada) y slot 10 (`+0x28`, ejército).
3. **Bonificación de doctrina ideológica del partido gobernante:**
   Obtiene el puntero al partido político en `[country + 0xA60]`.
   - Si es ejército: lee el modificador en `[party + 0x70]`.
   - Si es armada: lee el modificador en `[party + 0x68]`.
   Acumula: $\text{scaled} = \text{base\_morale} + \text{doctrine\_bonus}$.
4. **Rasgo del general o almirante asignado:**
   Verifica el puntero al líder militar en `[regiment + 0x74]`. Si está presente (`leader != NULL`),
   recupera el bono de moral en `[mod_obj + 0x20]` y lo suma: $\text{scaled} \leftarrow \text{scaled} + \text{leader\_bonus}$.
5. **Excepción de facción Rebelde (`"REB"`):**
   Compara los 3 bytes del tag en `[regiment + 0x60]` contra `'R'`, `'E'`, `'B'`.
   Si la unidad pertenece a rebeldes, **salta completamente la penalización presupuestaria**,
   otorgando la moral base acumulada completa ($\text{final} = \text{scaled}$).
6. **Escala presupuestaria nacional y piso rígido del 25%:**
   Si la unidad pertenece a un país soberano regular, recupera el slider de gasto militar nacional
   (`[country + 0x1450]` para ejército, `[country + 0x1448]` para armada) en escala $[0, 1000]$:
   - Si el slider excede 1000, se limita a 1000.
   - Aplica la fórmula lineal con piso del 25%:
     $$\text{budget\_factor} = 250 + \left\lfloor \frac{\text{slider} \times 750}{1000} \right\rfloor$$
   - Escala la moral final:
     $$\text{max\_morale} = \left\lfloor \frac{\text{scaled} \times \text{budget\_factor}}{1000} \right\rfloor$$
   Esto demuestra por qué los ejércitos nunca caen a 0 de moral máxima por falta de presupuesto: el motor impone un suelo irreducible del **25.0%**.

Reverify comprueba 129 afirmaciones de instrucciones, vtables y offsets con control negativo refutado
e invalidación dependiente. Unicorn emula 142 fixtures cubriendo ejércitos, armadas, líderes nulos y activos,
rebeldes y el espectro completo del slider de gasto con 0 discrepancias frente a `regiment_max_morale_model.py`.

### 58. Cálculo de Moral Media y Organización de Ejércitos y Flotas (`CUnit::CalculateAverageMorale`)

El contrato de [moral media de ejércitos](contracts/ARMY-AVERAGE-MORALE.md)
demuestra la rutina de 329 bytes en `0x005C8DC0..0x005C8F08` (113 instrucciones), ubicada en el
método virtual canónico del slot 37 (`+0x94`) en la jerarquía polimórfica de unidades:
`CArmy` (`0x00DF8960`), `CNavy` (`0x00E03060`), `CUnit` (`0x00E02F98`) y unidades especializadas (`0x00E03128`).

La rutina implementa:
1. **Inicialización en punto flotante:**
   Evalúa $0.0005 \times 1000.0 = 0.5$ con `floor` y truncamiento a entero de 32 bits, inicializando `*out_morale = 0`.
2. **Acumulación de moral base de subunidades:**
   Si la lista enlazada de regimientos/buques `[this + 0x38]` no está vacía, recorre secuencialmente los nodos (`node->next` en `+0x8`), sumando la moral base de cada tipo de subunidad (`[subunit->type + 0xB4]`):
   $$\text{sum\_base} = \sum_{i=1}^{N} \text{regiment}_i\text{->base\_morale}$$
3. **Normalización aritmética por recuento (`count = [this + 0x40]`):**
   Si `count > 0`, normaliza mediante aritmética entera de 64 bits con `_allmul` y `_alldiv`:
   $$\text{avg\_base} = \left\lfloor \frac{\text{sum\_base} \times 1000}{\text{count} \times 1000} \right\rfloor = \left\lfloor \frac{\text{sum\_base}}{\text{count}} \right\rfloor$$
4. **Bonificación doctrinal del partido político gobernante:**
   - Si `this->IsNavy()` (`vtable[14]` / `+0x38` retorna `true`):
     recupera el país propietario (`[0x12587E4]->countries[this->country_id]`), su partido gobernante (`[country + 0xA60]`) y el modificador naval `doctrine = [party + 0x68]`.
   - Si `this->IsArmy()` (`vtable[15]` / `+0x3C` retorna `true`):
     recupera el modificador militar terrestre `doctrine = [party + 0x70]`.
   - Si se identificó doctrina, aplica factor multiplicativo en milésimas:
     $$\text{morale} \leftarrow \left\lfloor \frac{\text{morale} \times (\text{doctrine} + 1000)}{1000} \right\rfloor$$
5. **Bonificación de líder asignado:**
   Si la unidad tiene un general o almirante (`leader = [this + 0xD8] != NULL`):
   recupera el rasgo en `[leader + 0x48]` y su bono en `leader_bonus = [modifier + 0x20]`.
   Aplica factor multiplicativo en milésimas:
   $$\text{morale} \leftarrow \left\lfloor \frac{\text{morale} \times (\text{leader\_bonus} + 1000)}{1000} \right\rfloor$$
6. Escribe el valor final en `*out_morale` y retorna el puntero.

Reverify comprueba 119 afirmaciones de instrucciones, vtables y constantes con control negativo refutado
e invalidación dependiente. Unicorn emula 180 fixtures cubriendo ejércitos, flotas, unidades vacías, espectro
completo de doctrinas y bonificaciones de líderes con 0 discrepancias frente a `army_average_morale_model.py`.

### 59. Límite de Suministro Territorial y Capacidad de Aprovisionamiento de Ejércitos (`CArmy::CalculateSupplyLimit`)

El contrato de [límite de suministro de ejércitos](contracts/ARMY-SUPPLY-LIMIT.md)
demuestra la rutina de 404 bytes en `0x005D63E0..0x005D6574` (125 instrucciones), ubicada en el
slot 30 (`+0x78`) de la vtable de `CArmy` (`0x00DF8944`).

La rutina implementa:
1. **Comprobación de movimiento/retirada forzada:**
   Si `[army + 0x164] != 0` (la unidad está en retirada forzada o movimiento táctico rápido),
   asigna `*out_limit = 0` inmediatamente y retorna.
2. **Determinación de base territorial amistosa vs hostil:**
   - Si la provincia está controlada por el mismo país propietario (`province->controller_id == army->country_id`),
     el ejército no está bajo asedio (`[army + 0x74] == 0`) y no está trabado en combate (`[army + 0x104] == 0`),
     invoca `0x005DC200` para obtener la base amistosa (`friendly_base`).
   - Si no se cumplen todas las condiciones anteriores (territorio hostil, ocupado, asediado o en combate),
     invoca `0x005DC2A0` para obtener la base hostil reducida (`hostile_base`).
3. **Bonificación de rasgo de líder y patrón Null Object (`CNullLeader`):**
   El puntero en `[army + 0xD8]` siempre apunta a una instancia válida (`CLeader` o `CNullLeader`, vtable `0x00E026C0`).
   Invoca el método virtual `[leader_vt + 0x20]`. Si retorna verdadero, suma el bono de intendencia `[leader->modifier + 0x38]`:
   $$\text{adjusted\_base} = \text{base} + \text{leader\_bonus}$$
4. **Escalado tecnológico nacional:**
   Recupera el modificador tecnológico de suministro militar en `[country + 0xBCC]->offset + 0x20`.
   Aplica factor multiplicativo en milésimas:
   $$\text{scaled} = \left\lfloor \frac{\text{adjusted\_base} \times (\text{tech\_bonus} + 1000)}{1000} \right\rfloor$$
5. **Penalización por terreno y bonificación de infraestructura:**
   - Evalúa el modificador ambiental/terreno provincial mediante `0x004B3C40`, normalizado con el multiplicador $0x10624DD3$ y desplazamiento aritmético (`terrain_penalty`).
   - Evalúa el bono de infraestructura provincial mediante `0x004B80B0` escalado a milésimas (`infra_bonus`).
   $$\text{raw\_supply} = \text{scaled} - \text{terrain\_penalty} + \text{infra\_bonus}$$
6. **Doble acotación estricta (clamping):**
   - Techo provincial: recupera la capacidad portante máxima de la provincia en `[province + 0x9c]->offset + 0x18`, normalizada a milésimas.
     Aplica instrucción condicional `cmovg ecx, eax` para asegurar $\text{supply} \le \text{province\_cap}$.
   - Piso a cero: si el resultado acumulado es negativo, aplica `xor ecx, ecx` para imponer $\max(0, \text{supply})$.
7. **Bonificación de unidad estacionada:**
   Si la unidad se encuentra estacionada o fortificada (`[army + 0x70] != 0`),
   suma el modificador global de `defines` en `[0x012586DC]->0x20->0xDC`.
8. Persiste el valor final en `*out_limit` y retorna el puntero.

Reverify comprueba 126 afirmaciones de instrucciones, vtables y singletons con control negativo refutado
e invalidación dependiente. Unicorn emula 154 fixtures cubriendo retiradas, territorio amigo/hostil, combate, asedios,
líderes, tecnologías, penalizaciones de terreno, techos provinciales y unidades estacionadas con 0 discrepancias frente a `army_supply_limit_model.py`.

### 60. Proporción Relativa de Fuerza y Cuota de Bando en Batalla (`CCombat::CalculateForceRatio`)

El contrato de [proporción relativa de fuerza de combate](contracts/COMBAT-FORCE-RATIO.md)
demuestra la rutina de 190 bytes en `0x0059C460..0x0059C51E` (79 instrucciones), ubicada en el
slot 7 (`+0x1C`) de las vtables polimórficas de batalla: `CCombat` (`0x00E02160`), `CLandCombat` (`0x00E02370`) y `CNavalCombat` (`0x00E023E0`).

La rutina implementa:
1. **Piso mínimo de combatientes:**
   Evalúa la constante flotante $1.5$ en `0x00F141C8` mediante truncamiento entero (`floor`),
   fijando un umbral mínimo de 1 combatiente ($\text{min\_floor} = 1$).
2. **Consulta polimórfica de bandos:**
   - Atacante (`[this + 0x10]`): invoca el método virtual slot 10 (`+0x28`) de `CCombatant` para obtener `attacker_strength`.
   - Defensor (`[this + 0x14]`): invoca el método virtual slot 10 (`+0x28`) de `CCombatant` para obtener `defender_strength`.
3. **Clamping inferior estricto y totalización:**
   Impone mediante `cmovl` un piso de al menos 1 unidad de fuerza en cada bando:
   $$A = \max(1, \text{attacker\_strength}), \quad D = \max(1, \text{defender\_strength})$$
   $$\text{total} = A + D$$
   Si $\text{total} == 0$, asigna `-1` (`0xFFFFFFFF`) en `*out_ratio` y retorna.
4. **Bifurcación algorítmica por umbral de desbordamiento de 32 bits ($2,147,482$):**
   Comprueba el rango de la fuerza del atacante evaluando $(A + 1610611) \le 3758093$:
   - **Camino rápido de 32 bits ($A \le 2,147,482$):**
     Como $A \times 1000 \le 2,147,482,000 < 2^{31} - 1$, la multiplicación cabe estrictamente en `int32`.
     Calcula directamente con la instrucción x86 `idiv`:
     $$\text{ratio} = \left\lfloor \frac{A \times 1000}{\text{total}} \right\rfloor$$
   - **Camino seguro extendido de 64 bits ($A > 2,147,482$):**
     Cuando la fuerza del atacante excede $2.147$ millones de unidades, el producto desbordaría 32 bits.
     El motor conmuta automáticamente a 64 bits invocando `_allmul` (`0xAC9F20`) y `_alldiv` (`0xAC02A0`):
     $$\text{ratio} = \text{\_alldiv}(A \times 1000, \text{total})$$
5. Escribe el ratio en `*out_ratio` en milésimas ($[0, 1000]$) y retorna el puntero.


## Determinación de Ancho de Frente de Combate (`CCombat::CalculateFrontage`)

El contrato de [ancho de frente de combate](contracts/COMBAT-FRONTAGE.md) demuestra la rutina `CCombat::CalculateFrontage` en `0x0059C520..0x0059C624` (261 bytes, 89 instrucciones), llamada en los núcleos de despliegue táctico (`0x0059ACE8`, `0x0059B19C`, `0x0059B9BD`) y renderizado de interfaz de combate (`0x00786601`, `0x00786A56`, `0x0082B1C0`).

La rutina resuelve el ancho disponible de la línea de batalla para el despliegue de regimientos:
1. **Frente base y mínimo tentativo:**
   Inicializa el acumulador de frente mínimo en $30,000$ milésimas ($30.0$ unidades, `0x7530`).
   Lee la definición base global en `[0x012586DC + 0x20] + 0x0C` (típicamente $30,000$).
2. **Determinación por tecnología de participantes (Regla Victoria II):**
   - Recorre las listas de países participantes de ambos bandos (`[pCombat + 0x10]` atacantes y `[pCombat + 0x14]` defensores).
   - Para cada país $i$:
     $$\text{frontage}_i = \text{base\_frontage} + \Delta_{\text{tech\_frontage}}$$
     donde $\Delta_{\text{tech\_frontage}} = \text{[country}_i + \text{0xBCC]->0x38}$.
   - Aplica piso inferior de tecnología: $\text{frontage}_i = \max(2000, \text{frontage}_i)$ ($2.0$ unidades).
   - Registra el mínimo global de la batalla: $\text{min\_frontage} = \min(\text{min\_frontage}, \text{frontage}_i)$.
   - En consecuencia, la tecnología militar avanzada (que reduce el frente táctico para simular frentes estrechos y guerra de trincheras) la impone la nación más avanzada de la batalla.
3. **Penalización por terreno provincial:**
   - Lee el modificador de frente del terreno provincial en `[pCombat + 0x18]->[province + 0x5C]->[terrain + 0x14]->0x94`.
   - Escala el frente mínimo mediante llamada a `_alldiv` (`0x00AC02A0`):
     $$\text{scaled} = \left\lfloor \frac{\text{min\_frontage} \times (1000 + \Delta_{\text{terrain}})}{1000} \right\rfloor$$
   - Aplica piso absoluto post-terreno: $\text{effective} = \max(2000, \text{scaled})$.
4. **Conversión a columnas de combate:**
   Divide entre 1000 usando la constante mágica `0x10624DD3` ($\approx 274877907$) con desplazamiento aritmético a la derecha de 38 bits:
   $$\text{slots} = (\text{effective} \times \text{0x10624DD3}) \gg 38 = \left\lfloor \frac{\text{effective}}{1000} \right\rfloor$$
   Retorna `slots` en `EAX` (e.g. 2 a 30 regimientos).


## Avance de Refuerzos y Despliegue de Segunda Línea (`CLandCombatant::AdvanceReinforcementLine`)

El contrato de [avance de refuerzos de combate](contracts/COMBAT-LINE-REINFORCEMENT.md) demuestra las rutinas `CLandCombatant::AdvanceColumnReinforcement` en `0x0059B0E0..0x0059B14B` (108 bytes, 33 instrucciones) y `CLandCombatant::AdvanceReinforcementLine` en `0x0059B150..0x0059B180` (49 bytes, 18 instrucciones), invocadas diariamente en `CCombat::DailyUpdate` (`0x0059CAE5` para el bando atacante y `0x0059CAEC` para el defensor).

El algoritmo modela el relevo táctico desde la segunda línea (`back_line[30]` en `+0xEC`) hacia la primera línea (`front_line[30]` en `+0x6C`):
1. **Barrido del centro a los flancos (`0x0059B150`):**
   Itera sobre las 30 columnas tácticas mediante la secuencia alternante:
   $$\text{col}_k = 16 + (-1)^k \cdot \left\lfloor \frac{k + 1}{2} \right\rfloor \quad \implies \quad 16 \to 15 \to 17 \to 14 \to 18 \dots \to 30 \to 1$$
2. **Ascenso directo:**
   Si la columna frontal correspondiente está desocupada (`front_line[col] == 0`), el regimiento asciende de inmediato: `front_line[col] = regimiento`, `back_line[col] = 0`.
3. **Escudo de soporte (Artillería):**
   Si la columna frontal está ocupada, consulta el atributo en `[regimiento + 0x38]->0x23C`:
   Si $\text{support} > 0$ (Artillería / Ingenieros), **la unidad permanece en segunda línea** y no avanza a posiciones de flanco.
4. **Desborde de flanco (Infantería / Caballería):**
   Si $\text{support} \le 0$:
   - Comprueba el flanco derecho: si $\text{col} + 1 < 30$ y `front_line[col + 1] == 0`, avanza a dicha casilla.
   - En caso contrario, comprueba el flanco izquierdo: si $\text{col} - 1 \ge 0$ y `front_line[col - 1] == 0`, avanza a dicha casilla.
   - Si ambos flancos están bloqueados, permanece en reserva en la segunda línea.


## Tabla Universal de Daño por Tirada de Combate (`CCombat::LookupDiceDamage`)

El contrato de [tabla universal de daño por tirada de combate](contracts/COMBAT-DICE-DAMAGE-TABLE.md) demuestra la rutina `CCombat::LookupDiceDamage` en `0x00594230..0x005944A9` (634 bytes, 144 instrucciones), invocada en los cálculos de bajas tanto terrestres (`0x0059A973` en `CLandCombatant::ExecuteRegimentAttack`) como navales (`0x005979C9`, `0x00597C82` en `CNavalCombatant::DailyDamage`).

La rutina resuelve la curva de efectividad táctica según el resultado del dado y los modificadores de combate:
1. **Mapeo y Clamping de Índice:**
   Aplica un desplazamiento de $+2$ a la tirada efectiva `roll` y la acota al rango $[0, 17]$:
   $$\text{index} = \min(17, \max(0, \text{roll} + 2))$$
2. **Inicialización perezosa de tabla en punto fijo:**
   Evalúa el bit de inicialización en `[0x013F1BB8] & 1`. En la primera ejecución convierte mediante `floor` (`0x00401000`) y `_ftol2` (`0x00B31C00`) los 18 valores flotantes de `.rdata` a enteros, almacenándolos en `0x013F1B70..0x013F1BB4` y activando la bandera. En ejecuciones posteriores lee directamente por desplazamiento de 4 bytes.
3. **Curva de Daño Progresiva por Tramos:**
   $$\text{TABLE} = [20, 40, 60, 80, 100, 120, 160, 200, 250, 300, 350, 400, 450, 500, 600, 700, 800, 900]$$
   - Tiradas críticas negativas ($\le -2$): piso irreducible de $20$.
   - Tiradas estándar ($0 \dots 3$): escalón suave de $+20$ por nivel ($60 \to 120$).
   - Tiradas medias-bajas ($4 \dots 5$): escalón acelerado de $+40$ por nivel ($160, 200$).
   - Tiradas medias-altas ($6 \dots 11$): escalón de $+50$ por nivel ($250 \to 500$).
   - Tiradas superiores críticas ($12 \dots 15+$): escalón de choque de $+100$ por nivel ($600 \to 900$).


## Selección y Adquisición de Objetivos Tácticos por Maniobra (`CLandCombatant::FindTargetRegiment`)

El contrato de [adquisición de objetivos tácticos](contracts/COMBAT-TARGET-ACQUISITION.md) demuestra la rutina `CLandCombatant::FindTargetRegiment` en `0x0059B610..0x0059B779` (364 bytes, 132 instrucciones), llamada en `CLandCombatant::ExecuteRegimentAttack` (`0x0059A927`) y en la evaluación de objetivos tácticos (`0x0059B01F`, `0x0059B588`).

La rutina resuelve la asignación de blanco enemigo para cada unidad atacante mediante una jerarquía de 4 fases:
1. **Condición de unidad operativa:**
   Un regimiento enemigo es elegible como blanco si y solo si $\text{strength} \ge 100$ (comparado con la constante flotante $100.5$ en `0x00E45A18`) y su organización es $\ge 1.000$ milésimas ($1.0$).
2. **Fase 1 (Objetivo frontal directo):**
   Si la casilla frontal directa `front_line[col]` en `[target_combatant + col*4 + 0x6C]` contiene una unidad operativa, la selecciona inmediatamente y retorna.
3. **Fase 2 (Barrido frontal de flanqueo):**
   Si el frente directo está desierto o desbandado, escanea la primera línea enemiga de izquierda a derecha en el intervalo:
   $$c \in [\max(0, \text{col} - \text{maneuver}), \min(30, \text{col} + \text{maneuver})]$$
   Selecciona la primera unidad operativa encontrada dentro del alcance de maniobra.
4. **Fase 3 (Objetivo directo en retaguardia):**
   Si toda la primera línea enemiga al alcance está destruida, ataca a la artillería en la casilla opuesta de la segunda línea: `back_line[col]` en `[target_combatant + col*4 + 0xEC]`.
5. **Fase 4 (Barrido de flanqueo en retaguardia):**
   Si la retaguardia directa está vacía, escanea la segunda línea enemiga dentro del radio de maniobra.
6. **Fase 5 (Sin objetivo):**
   Si no hay unidades operativas al alcance de maniobra, retorna `NULL` (`0`) y la unidad no inflige daño en esa ronda.

Reverify comprueba 135 afirmaciones de instrucciones y llamadas de motor con control negativo refutado e invalidación dependiente. Unicorn emula 45 fixtures verificando las 4 fases de adquisición y casos de fallo con 0 discrepancias frente a `combat_target_acquisition_model.py`.


## Ejecución del Ataque de Regimiento y Cómputo de Bajas (`CLandCombatant::ExecuteRegimentAttack`)

El contrato de [ataque de regimiento y cómputo de bajas](contracts/COMBAT-REGIMENT-ATTACK.md) demuestra la rutina `CLandCombatant::ExecuteRegimentAttack` en `0x0059A8E0..0x0059ACAF` (464 bytes, 143 instrucciones), invocada en el bucle principal de combate diario (`0x0059AD3A` para regimientos de primera línea y `0x0059AD63` para artillería en segunda línea).

La rutina integra toda la cadena de cálculo táctico de daño para cada unidad individual:
1. **Validación de ejército activo:**
   Verifica que `[pRegiment + 0x74] != NULL` y que `[pArmy + 0xA4] != 0`. En caso contrario aborta inmediatamente.
2. **Adquisición de objetivo táctico:**
   Divide la maniobra de la unidad entre 1000 con la constante mágica `0x10624DD3` e invoca a `CLandCombatant::FindTargetRegiment` (`0x0059B610`). Si retorna `NULL`, limpia los identificadores `[esi + 0x7C] = 0` y `[esi + 0x80] = 0` y finaliza sin daño.
3. **Selección de fase fuego / choque:**
   Evalúa la fase de combate en `[pAttackerCombatant + 0x18]`:
   - Fase de Fuego (`phase != 0`): selecciona la estadística de ataque de fuego `[pType + 0x230]`.
   - Fase de Choque (`phase == 0`): selecciona la estadística de ataque de choque `[pType + 0x234]`.
4. **Consulta a la tabla de daño por tirada:**
   Suma el modificador de terreno/líder en `[pAttackerCombatant + 0x30]` a la tirada del dado e invoca a `CCombat::LookupDiceDamage` (`0x00594230`).
5. **Multiplicador de ataque y escala por soporte y fuerza:**
   - Multiplicador de ataque con constante global `BASE_CASUALTY_MODIFIER` ($100$ en `0x0125F5C8`):
     $$\text{attack\_mult} = 1000 + \left\lfloor \frac{100 \times \text{attack\_stat}}{1000} \right\rfloor$$
   - Aplica el factor de soporte táctico (1000 para primera línea, o atributo de soporte de artillería en segunda línea):
     $$\text{supp\_damage} = \left\lfloor \frac{\text{dice\_damage} \times \text{support\_factor}}{1000} \right\rfloor$$
   - Escala por la fuerza actual del regimiento atacante (`[pRegiment + 0x3C]`):
     $$\text{damage} = \left\lfloor \frac{\text{supp\_damage} \times \text{attack\_mult} \times \text{strength}}{1,000,000} \right\rfloor$$
6. **Mitigación por fuerte provincial y penetración de reconocimiento:**
   Si la provincia no está controlada por el atacante y hay guerra o presencia rebelde ("REB"), el nivel de fuerte reduce el daño. El reconocimiento del ejército atacante (`0x005CCDB0` y `0x005CCDF0`) reduce el nivel efectivo de la fortificación:
   $$\text{effective\_fort} = \max\left(0, \text{fort\_level} - \lfloor \text{effective\_recon} / 1000 \rfloor\right)$$
   $$\text{damage} = \left\lfloor \frac{\text{damage} \times 1000}{1000 + \text{effective\_fort} \times 100} \right\rfloor$$
7. **Mitigación por tácticas del regimiento defensor:**
   Aplica la estadística de tácticas del objetivo (`[pTarget + 0x34]`) escalada por `BASE_TACTICS_DAMAGE_MODIFIER` ($10$ en `0x0125F594`):
   $$\text{damage} = \left\lfloor \frac{\text{damage} \times 1000}{1000 + \lfloor (\text{target\_tactics} \times 10) / 1000 \rfloor} \right\rfloor$$
8. **Atenuación por defensa y tácticas militares nacionales:**
   - Bajas en hombres: multiplica el daño por 10 y divide entre la defensa de la unidad enemiga (`[pTargetType + 0x238]`).
   - Pérdida de organización: divide entre la base doctrinal ($1000$) más el bono tecnológico nacional de tácticas militares (`[target\_country + 0xBCC]->0x70`).
9. **Escalado final y acumulación diaria:**
   Aplica el factor `BASE_MORALE_DAMAGE_MODIFIER` ($200$ en `0x0125F578`) dividiendo entre $5$ ($200/1000$), y acumula los daños directamente en el regimiento defensor:
   - `[pTarget + 0x70] +=` $\Delta\text{casualties}$
   - `[pTarget + 0x6C] +=` $\Delta\text{org\_loss}$

Reverify comprueba 156 afirmaciones de instrucciones y llamadas de motor con control negativo refutado e invalidación dependiente. Unicorn emula 86 fixtures verificando todas las ramas operativas, mitigaciones de fuerte/recon, defensas y tácticas con 0 discrepancias frente a `combat_regiment_attack_model.py`.


## Poda de Regimientos Quebrantados y Compactación Centrípeta de Línea (`CLandCombatant::PruneAndConsolidateLine`)

El contrato de [poda y compactación de línea](contracts/COMBAT-LINE-CONSOLIDATION.md) demuestra la rutina `CLandCombatant::PruneAndConsolidateLine` en `0x0059AEF0..0x0059B0D9` (490 bytes, 157 instrucciones), llamada en `0x0059ACD4` al inicio de cada jornada de combate terrestre.

La rutina mantiene la integridad topológica del frente de combate:
1. **Barrido del centro a los flancos:**
   Escanea las 30 columnas en orden alternante central ($16 \to 15 \to 17 \to 14 \dots$).
2. **Criterio de quebranto moral/físico:**
   Identifica unidades con $\text{strength} < 100$ (comparación con $100.5$ en `0x00E45A18`) u $\text{organization} < 1.000$ milésimas ($1.0$).
3. **Despacho a listas de retirada / desbandada:**
   - Si `CCombat::IsTacticalRetreatAllowed` es verdadero: desvincula la unidad de la primera línea y la añade a la lista de desbandadas (`routed_list` en `0x17C`).
   - Si la retirada táctica está prohibida: evalúa `CLandCombatant::FindTargetRegiment` (`0x0059B610`); si no hay objetivos o la unidad colapsó, se transfiere a la lista de retirada estándar (`retreat_list` en `0x16C`).
   - Tras vaciar la casilla, invoca inmediatamente a `CLandCombatant::AdvanceColumnReinforcement` (`0x0059B0E0`) para que la reserva de segunda línea intente relevar el puesto.
4. **Despliegue de reservas:**
   Invoca a `CLandCombatant::DeployFromReserve` (`0x0059B190`), incorporando reservas generales en las columnas vacantes opuestas a unidades enemigas.
5. **Compactación centrípeta de brechas (Gap Closing):**
   Itera de columna 1 a 28 cerrando huecos hacia el centro del campo de batalla:
   - Flanco izquierdo ($1 \le \text{col} < 15$): si `front_line[col] == 0` y la casilla exterior izquierda `front_line[col - 1]` está ocupada, desplaza el regimiento hacia la derecha en dirección al centro.
   - Flanco derecho ($15 \le \text{col} < 29$): si `front_line[col] == 0` y la casilla exterior derecha `front_line[col + 1]` está ocupada, desplaza el regimiento hacia la izquierda en dirección al centro.

Reverify comprueba 158 afirmaciones de instrucciones y llamadas de motor con control negativo refutado e invalidación dependiente. Unicorn emula 39 fixtures comprobando quebrantos, relevos de retaguardia, listas de retirada y el cierre centrípeto de huecos con 0 discrepancias frente a `combat_line_consolidation_model.py`.

## Determinación de Victoria, Retirada y Aniquilación Total (`CCombat::EvaluateVictoryAndStackwipe`)

El contrato de [victoria y stackwipe](contracts/COMBAT-VICTORY-STACKWIPE.md) describe la rutina virtual `CCombat::EvaluateVictoryAndStackwipe` en `0x0059C630..0x0059C8A7` (632 bytes, 197 instrucciones). Corresponde al slot 11 (`+0x2C`) de las vtables de combate:
- `CCombat` (`0x00E02174`)
- `CLandCombat` (`0x00E02384`)
- `CNavalCombat` (`0x00E02464`)

La rutina es invocada periódicamente desde el bucle de batalla (`0x0059AF34`, `0x005954F0`, `0x005990E0`) para determinar si las hostilidades han alcanzado su desenlace:
1. **Regla de pausa de depuración / combate congelado:**
   Comprueba el flag de motor `is_debug_pause` en `[pCombat + 0x64]`. Si está activo, el desenlace se congela sin alterar el curso del combate.
2. **Evaluación de operatividad moral:**
   Verifica mediante llamada virtual a `CLandCombatant::HasOperationalUnits` (`slot 7, +0x1C`) si cada bando conserva al menos un regimiento con organización activa ($\text{org} \ge 1.000$).
3. **Mecanismo formal de Aniquilación Total (Stackwipe 2:1):**
   - Si las fuerzas del defensor quedan completamente desprovistas de organización moral (`HasOperationalUnits == 0`) y la fuerza física del atacante supera el doble de la del defensor ($\lfloor \text{fuerza\_atacante} / 2 \rfloor > \text{fuerza\_defensor}$), o bien el ejército derrotado carece de provincia contigua legal para replegarse (`retreat_province_id == -1` por cerco, isla sin flota o cerco hostil completo):
   - El motor asigna `defender_final_strength = 0`, ejecutando el aniquilamiento completo de la fuerza antes de transferirla a la lista de resolución.
4. **Declaración de vencedor y entrega a ConcludeBattle:**
   - Si un bando tiene 0 tropas o 0 moral mientras el rival conserva presencia operativa, o bien la fuerza de un bando es superada por el umbral de arrollamiento instantáneo (`OVERRUN_RATIO`), la batalla concluye (`battle_ended = True`).
   - Se despacha al ganador (`0` atacante, `1` defensor) mediante llamada virtual a `CCombat::ConcludeBattle` (`0x005A0180`).
Reverify comprueba 233 afirmaciones de instrucciones en PE32 y slots de vtables con control negativo refutado e invalidación dependiente. Unicorn emula 73 fixtures dinámicos con 0 discrepancias frente a `combat_victory_stackwipe_model.py`.

## Prioridad Táctica y Ordenación de Reserva de Combate (`CSubUnit::CompareTacticalValue`)

El contrato de [prioridad de reserva](contracts/COMBAT-RESERVE-PRIORITY.md) formaliza la rutina comparadora `CSubUnit::CompareTacticalValue` en `0x0059B780..0x0059B833` (84 bytes, 64 instrucciones), invocada en `0x005AB8B7` durante la inserción ordenada de subunidades en la cola de reserva de combate (`CLandCombatant::InsertReserveRegiment`).

La rutina implementa un ordenamiento estricto ($A < B$) para mantener las unidades de mayor rendimiento táctico al frente de la cola de refuerzo:
1. **Agregación de atributos de combate:**
   Suma las estadísticas tácticas del tipo de unidad (`CUnitType`):
   $$\text{stat\_sum} = \text{fire\_attack} (\text{+0x230}) + \text{shock\_attack} (\text{+0x234}) + \text{maneuver} (\text{+0x240})$$
2. **Evaluación de operatividad de liderazgo:**
   Inspecciona el líder asignado (`[pRegiment + 0x74]`). Si `pLeader != NULL` y el flag `[pLeader + 0x164] != 0` (líder destituido o inhabilitado), la organización efectiva colapsa a 0 ($\text{effective\_org} = 0$). En caso contrario, se utiliza la organización íntegra del regimiento (`[pRegiment + 0x40]`).
3. **Puntuación táctica ponderada:**
   Mediante división entera escalada de 64 bits (`_alldiv` en `0x00AC02A0` con divisor 1000):
   $$\text{step}_1 = \left\lfloor \frac{\text{effective\_org} \times \text{stat\_sum}}{1000} \right\rfloor$$
   $$\text{score} = \left\lfloor \frac{\text{step}_1 \times \text{strength}}{1000} \right\rfloor$$
4. **Comparación estricta:**
   Retorna en `al` el valor booleano $\text{score}_A < \text{score}_B$.

Reverify comprueba 40 afirmaciones de instrucciones en PE32 y punto de llamada en `0x005AB8B7` con control negativo refutado e invalidación dependiente. Unicorn emula 64 fixtures dinámicos cubriendo variaciones de fuerza, moral, perfiles de ataque y líderes inoperativos con 0 discrepancias frente a `combat_reserve_priority_model.py`.

## Proporción Relativa de Fuerza del Atacante (`CCombat::CalculateAttackerStrengthRatio`)

El contrato de [proporción de atacante](contracts/COMBAT-ATTACKER-RATIO.md) formaliza el método virtual `CCombat::CalculateAttackerStrengthRatio` en `0x0059C460..0x0059C51B` (188 bytes, 79 instrucciones), correspondiente al slot 6 (`+0x18`) de las tablas de métodos virtuales de `CCombat` (`0x00E02160`), `CLandCombat` (`0x00E02370`) y clases derivadas (`0x00E023E0`).

La rutina calcula la cuota proporcional que representan las tropas atacantes sobre la totalidad del teatro de operaciones:
1. **Umbral numérico de estabilización:**
   Carga el parámetro flotante en `0x00F141C8` ($1.5$), truncándolo mediante `floor` (`0x00401000`) y `_ftol2` (`0x00B31C00`) a $\text{min\_threshold} = 1$.
2. **Extracción y acotación de combatientes:**
   Invoca virtualmente a `GetTotalRawStrength` (slot 10, `+0x28`) para el atacante (`pCombat + 0x10`) y el defensor (`pCombat + 0x14`). Clampea cada contingente mediante `cmovl` a un mínimo de 1 hombre ($\text{att} \ge 1, \text{def} \ge 1$).
3. **Cómputo de masa total y caso degenerado:**
   $\text{total} = \text{att} + \text{def}$. Si $\text{total} == 0$, asigna `*out_ratio = -1` y concluye.
4. **Bifurcación aritmética 32-bit vs 64-bit:**
   Verifica el límite de desbordamiento en 32 bits: $\text{att} \le 2,147,482$.
   - Camino de 32 bits (`imul` / `idiv`): calcula directamente $(\text{att} \times 1000) / \text{total}$.
   - Camino de 64 bits (`_allmul` en `0x00AC9F20` y `_alldiv` en `0x00AC02A0`): realiza la multiplicación de 64 bits por 1000 y división por el total de 64 bits, asegurando precisión exacta en batallas con millones de hombres sin desbordar el registro de 32 bits.
5. **Retorno de puntero:**
   Escribe el ratio en `*out_ratio` y retorna el puntero de salida `eax = out_ratio`.

Reverify comprueba 83 afirmaciones de instrucciones en PE32, slots de vtables y constante flotante con control negativo refutado e invalidación dependiente. Unicorn emula 45 fixtures dinámicos con 0 discrepancias frente a `combat_attacker_ratio_model.py`.

## Suficiencia de Suministro y Carga Logística Provincial (`CArmy::EvaluateSupplySufficiency`)

El contrato de [suficiencia de suministro de ejército](contracts/ARMY-SUPPLY-SUFFICIENCY.md) formaliza el método virtual `CArmy::EvaluateSupplySufficiency` en `0x005D5E30..0x005D5EE3` (180 bytes, 69 instrucciones), correspondiente al slot 3 (`+0x0C`) de la tabla virtual de `CArmy` en `0x00DF8950` (`vtable + 0x0C`).

La rutina determina si un ejército dispone de cobertura logística adecuada en la provincia destino o si entra en sobrecarga y déficit de suministro:
1. **Control de entorno marítimo vs terrestre:**
   Inspecciona el flag `is_water` en `[pProvince + 0x5C]->0x2A`:
   - En zonas marítimas: si el ejército está embarcado (`[pArmy + 0x164] != 0`), retorna inmediatamente `True` (1). Si no, delega a `pArmy->CanTraverseSea(pProvince)` (`0x005CD2F0`).
2. **Agregación logística provincial:**
   - Inicializa la demanda logística con el peso propio del ejército: $\text{demanded} = \text{pArmy.supply\_weight}$ (`+0x40`).
   - Inicializa la capacidad aportada por la intendencia: $\text{capacity} = 0$.
   - Itera por la lista enlazada de ejércitos estacionados en la provincia (`[pProvince + 0xEC]`):
     - Omite al ejército propio.
     - Si el ejército $A_i$ pertenece al mismo país (`[A_i + 0xC4] == [pArmy + 0xC4]`):
       - Si `A_i->IsAlliedTo()` (slot 14, `+0x38`) es verdadero, acumula su peso: $\text{demanded} \mathrel{+}= A_i\text{.supply\_weight}$.
       - Si `A_i->IsSupplyContributor()` (slot 15, `+0x3C`) es verdadero, acumula su capacidad efectiva mediante `GetArmyEffectiveCapacity(A_i)` (`0x005CD580`): $\text{capacity} \mathrel{+}= \text{cap}(A_i)$.
3. **Criterio de autosuficiencia y mitigación de desgaste:**
   - Compara la capacidad disponible contra la demanda total: $\text{capacity} \ge \text{demanded}$.
   - Retorna en `al` 1 si hay suficiencia de suministro (evitando desgaste por sobrecarga), o 0 si la demanda supera la capacidad (activando el desgaste provincial).

Reverify comprueba 70 afirmaciones de instrucciones en PE32 y slot de vtable con control negativo refutado e invalidación dependiente. Unicorn emula 44 fixtures dinámicos cubriendo zonas marítimas, transportes navales, ejércitos individuales y agregaciones de coalición con 0 discrepancias frente a `army_supply_sufficiency_model.py`.

## Posicionamiento y Factor de Fuerza en Combate Naval (`CNavalCombat::CalculateForceRatio`)

El contrato de [proporción y posicionamiento naval](contracts/NAVAL-COMBAT-RATIO.md) formaliza el método virtual polimórfico `CNavalCombat::CalculateForceRatio` en `0x005AB710..0x005AB75F` (80 bytes, 29 instrucciones), correspondiente al slot 6 (`+0x18`) en la vtable de combate naval (`0x00E02450`).

A diferencia de las batallas terrestres (donde el slot 6 calcula la proporción de masa humana entre los contendientes), el motor naval especializa esta rutina para gobernar el factor de posicionamiento y fricción de flota derivado de las condiciones de la zona marítima:
1. **Extracción y discretización de congestión marítima:**
   Extrae la penalización de la provincia marítima (`[pNavalCombat + 0x18]->0x114`).
   Aplica división entera por 1000 optimizada por compilador con el multiplicador mágico `0x10624DD3` y re-multiplica por 1000:
   $$\text{truncated} = \lfloor \text{penalty} / 1000 \rfloor \times 1000$$
2. **Margen respecto a la base máxima:**
   Calcula el diferencial respecto a la base de 100,000 milésimas ($100.0\%$ de efectividad):
   $$\Delta = 100,000 - \text{truncated}$$
3. **Escalado aritmético de 64 bits:**
   Multiplica $\Delta$ por 1000 (`_allmul` en `0x00AC9F20`) y divide entre la base 100,000 (`_alldiv` en `0x00AC02A0`):
   $$\text{ratio} = \left\lfloor \frac{\Delta \times 1000}{100,000} \right\rfloor = \left\lfloor \frac{(100,000 - \text{truncated}) \times 1000}{100,000} \right\rfloor$$
4. **Almacenamiento:**
   Escribe el ratio resultante en `*out_ratio` y retorna el puntero de salida `eax = out_ratio`.

Reverify comprueba 30 afirmaciones de instrucciones en PE32 y slot de vtable con control negativo refutado e invalidación dependiente. Unicorn emula 36 fixtures dinámicos cubriendo zonas despejadas, saturación por casco y penalizaciones negativas con 0 discrepancias frente a `naval_combat_ratio_model.py`.

## Viabilidad de Refuerzo Demográfico de Regimiento (`CRegiment::CanReinforce`)

El contrato de [viabilidad de refuerzo demográfico de regimiento](contracts/REGIMENT-REINFORCE.md) formaliza el método virtual `CRegiment::CanReinforce` en `0x005CC4D0..0x005CC529` (90 bytes, 35 instrucciones), correspondiente al slot 20 (`+0x50`) de la tabla virtual de `CRegiment` en `0x00DF88D4`.

La rutina evalúa si una unidad militar puede recibir refuerzos de población para reponer bajas según el estado y ubicación de su POP de soporte original:
1. **Verificación de existencia del POP de origen:**
   Inspecciona el puntero al POP soldado de reclutamiento en `[pRegiment + 0x108]`. Si `pHomePop == NULL` (debido a asimilación, migración total, promoción o extinción biológica del contingente), la reposición es físicamente inviable y retorna inmediatamente `False` (0).
2. **Jurisdicción y control nacional:**
   Invoca virtualmente a `pHomePop->GetPopResidenceLocation()` (slot 22, `+0x58`) para obtener la tupla de ubicación y país soberano de la provincia de residencia. Si el país coincide con el propietario del regimiento (`pop_country_id == regiment_country_id`), el refuerzo está habilitado de inmediato y retorna `True` (1).
3. **Comprobación de corredor de acceso y abastecimiento:**
   Si la provincia natal se encuentra bajo ocupación hostil o transferida territorialmente, delega a `HasMilitaryAccessOrSupplyRoute(regiment_location, pop_location)` (`0x005CC2E0`). Solo si existe continuidad de paso militar o línea marítima despejada retorna `True` (1); de lo contrario, la unidad queda bloqueada logísticamente (`False` / 0).

Reverify comprueba 36 afirmaciones de instrucciones en PE32 y slot de vtable con control negativo refutado e invalidación dependiente. Unicorn emula 40 fixtures dinámicos cubriendo POPs extintos, territorio patrio, corredores aliados y bloqueos de acceso militar con 0 discrepancias frente a `regiment_reinforce_model.py`.

## Determinación Polimórfica de Fuerza Total de Formación Militar (`CArmy::CalculateTotalStrength` y `CNavy::CalculateTotalStrength`)

El contrato de [fuerza total de formación militar](contracts/FORMATION-TOTAL-STRENGTH.md) formaliza las rutinas polimórficas virtuales en el slot 10 (`+0x28`):
- `CArmy::CalculateTotalStrength`: `0x005D61A0..0x005D61F8` (89 bytes, 29 instrucciones), vtable `0x00DF88F4`.
- `CNavy::CalculateTotalStrength`: `0x005D91D0..0x005D91E5` (21 bytes, 7 instrucciones), vtable `0x00E02FF4`.

Invocadas polimórficamente desde el cálculo de proporción táctica en combate (`0x0059C48C` y `0x0059C49A` en `CCombat::CalculateAttackerStrengthRatio`), las rutinas resuelven el volumen bélico bruto:
1. **Formación Terrestre (`CArmy`):**
   - Evalúa el parámetro de inicialización $0.0005 \times 1000.0 = 0.5$ truncado a 0 (`floor`), escribiendo `*out_strength = 0`.
   - Recorre la lista enlazada de subunidades en `[pArmy + 0x38]`, acumulando la fuerza física de cada regimiento individual (`[pRegiment + 0x3C]`).
   - Retorna el puntero `out_strength` en `eax`.
2. **Formación Naval (`CNavy`):**
   - Extrae el recuento de buques de guerra en `[pNavy + 0x40]`.
   - Multiplica directamente por 1000 (`imul ecx, ecx, 0x3E8`), equiparando cada buque al orden de magnitud demográfico de un regimiento terrestre completo ($1,000$ hombres).
   - Escribe el resultado en `*out_strength` y retorna el puntero en `eax`.

Reverify comprueba 42 afirmaciones de instrucciones en PE32, vtables y constantes flotantes con control negativo refutado e invalidación dependiente. Unicorn emula 59 fixtures dinámicos cubriendo ejércitos vacíos, regimientos individuales, múltiples contingentes masivos y flotas navales con 0 discrepancias frente a `formation_total_strength_model.py`.

## Agregación de Carga Logística Provincial y Presencia de Tropas (`CProvince::CalculateFriendlyTroopStrength` y `CProvince::CalculateTotalTroopStrength`)

El contrato de [carga logística provincial y tropas](contracts/PROVINCE-TROOP-STRENGTH.md) formaliza las rutinas gemelas de agregación demográfica provincial:
- `CProvince::CalculateFriendlyTroopStrength`: `0x005DC200..0x005DC297` (149 bytes, 47 instrucciones).
- `CProvince::CalculateTotalTroopStrength`: `0x005DC2A0..0x005DC322` (128 bytes, 39 instrucciones).

Invocadas como el motor de carga demográfica territorial en `CArmy::CalculateSupplyLimit` (`0x005D6442` para territorio amistoso no asediado y `0x005D644F` para territorio hostil o en combate), las rutinas determinan la masa de maniobra que satura la provincia:
1. **Fuerza Amistosa en Territorio Propio (`0x005DC200`):**
   - Inicializa `*out_strength = 0` mediante constante flotante $0.0005 \times 1000.0$.
   - Itera por los ejércitos presentes en la lista provincial:
     - Comprueba el estado operativo (`IsArmyActive()`, slot virtual 14, `+0x38`).
     - Compara la nacionalidad del ejército (`army->country_id` en `+0xC4`) contra el país soberano de la provincia (`target_country_id` en `[eax + 4]`). Si difiere, la unidad es ignorada.
     - Si coincide, itera sus regimientos (`[army + 0x38]`) y suma sus efectivos (`regiment->strength` en `+0x3C`) en `*out_strength`.
2. **Fuerza Total en Territorio Hostil o Asediado (`0x005DC2A0`):**
   - Inicializa `*out_strength = 0`.
   - Itera por todos los ejércitos operativos sin filtrar por nacionalidad, sumando la totalidad de los efectivos presentes. En territorio hostil, ocupado o disputado, todas las fuerzas beligerantes y de ocupación compiten y agotan de manera conjunta la capacidad de intendencia provincial.

Reverify comprueba 112 afirmaciones de instrucciones en PE32, llamadas de llamada y constantes flotantes con control negativo refutado e invalidación dependiente. Unicorn emula 34 fixtures dinámicos cubriendo listas vacías, ejércitos inactivos, combinaciones multinacionales aliadas y enemigas, y contingentes masivos con 0 discrepancias frente a `province_troop_strength_model.py`.

## Aplicación Diaria de Bajas y Desglose de Pérdidas de Combate (`CCombatant::CommitCasualtiesAndMoraleLoss` y `CCombatant::CommitCasualtiesByUnitType`)

El contrato de [aplicación de bajas de combate](contracts/COMBAT-CASUALTY-COMMIT.md) formaliza las rutinas de resolución diaria de daño físico y moral en combate:
- `CCombatant::CommitCasualtiesAndMoraleLoss`: `0x005DC330..0x005DC3BD` (141 bytes, 46 instrucciones).
- `CCombatant::CommitCasualtiesByUnitType`: `0x005DC3C0..0x005DC45B` (155 bytes, 49 instrucciones).

Invocadas al término de cada jornada táctica en `0x00595E71` y `0x00595F12` dentro de `CCombat::ResolveDailyCasualtiesAndMoraleLoss`:
1. **Aplicación Global y Amortiguación (`0x005DC330`):**
   - Recorre todos los regimientos de todos los ejércitos asignados al combatiente.
   - Aplica el daño mediante `CRegiment::CommitCombatDamage` (`0x005C0160`), clampeando las bajas para que la fuerza no sea inferior a 0 ($\text{eff\_cas} = \min(\text{strength}, \text{pending\_casualties})$) y la pérdida moral ($\text{eff\_mor} = \min(\text{morale}, \text{pending\_morale\_loss})$).
   - Descuenta las pérdidas de las estadísticas del regimiento y limpia los acumuladores pendientes (`pending_casualties = 0`, `pending_morale_loss = 0`).
   - Suma las bajas efectivas en `*out_total_loss`.
2. **Desglose Específico por Categoría Táctica (`0x005DC3C0`):**
   - Comprueba la categoría de cada subunidad frente a la requerida (`[regiment->type + 0x24] == [filter + 0x24]`).
   - Aplica el descuento únicamente sobre las unidades correspondientes y suma sus bajas al subtotal de la categoría en `*out_type_loss`, alimentando los desgloses estadísticos de la interfaz y los informes de batalla.

Reverify comprueba 99 afirmaciones de instrucciones en PE32, puntos de llamada y constantes flotantes con control negativo refutado e invalidación dependiente. Unicorn emula 40 fixtures dinámicos cubriendo ejércitos vacíos, regimientos sin daño, saturación por encima de la fuerza actual y filtros por categoría con 0 discrepancias frente a `combat_casualty_commit_model.py`.

## Censo y Clasificación de Subunidades de Formación Militar (`CCombatant::CountRegimentsByFilterObject` y `CCombatant::CountRegimentsByDirectId`)

El contrato de [censo de subunidades](contracts/SUBUNIT-CENSUS.md) formaliza las rutinas de contabilización y agregación estructural de unidades militares:
- `CCombatant::CountRegimentsByFilterObject`: `0x005DC050..0x005DC093` (65 bytes, 29 instrucciones).
- `CCombatant::CountRegimentsByDirectId`: `0x005DC0A0..0x005DC0DF` (63 bytes, 27 instrucciones).

Invocadas en los motores de interfaz de batalla (`0x00786B65`, `0x00786BE3`, `0x00786C67` en `CCombatView::UpdateUnitTypeIcons`) y vistas militares (`0x0081FC0D`, `0x008208EC`):
1. **Censo por Objeto Filtro (`0x005DC050`):**
   - Recorre el grafo jerárquico de ejércitos enlazados y sus listas de subunidades.
   - Compara la categoría de arma de cada regimiento (`[regiment->type + 0x24]`) contra la del filtro (`[filter + 0x24]`).
   - Retorna en `eax` la suma total de regimientos coincidentes.
2. **Censo por Identificador Directo (`0x005DC0A0`):**
   - Recorre las formaciones comparando el código directo de subunidad (`[regiment->type + 0x34]`) frente al identificador numérico pasado por valor (`target_id` en `[ebp + 8]`).
   - Retorna en `eax` el recuento exacto de regimientos de esa clase específica.

Reverify comprueba 70 afirmaciones de instrucciones en PE32 y puntos de llamada con control negativo refutado e invalidación dependiente. Unicorn emula 88 fixtures dinámicos cubriendo formaciones vacías, subunidades homogéneas y heterogéneas, y ramas de infantería, caballería y artillería con 0 discrepancias frente a `subunit_census_model.py`.

## Cómputo de Fuerza Efectiva y Fuerza Actual de Combatiente Militar (`CCombatant::CalculateEffectiveStrength` y `CCombatant::CalculateTotalCurrentStrength`)

El contrato de [fuerza de combatiente](contracts/COMBATANT-STRENGTH.md) formaliza las rutinas de agregación y estimación de masa militar en combate:
- `CCombatant::CalculateEffectiveStrength`: `0x005DC0E0..0x005DC17C` (159 bytes, 60 instrucciones).
- `CCombatant::CalculateTotalCurrentStrength`: `0x005DC180..0x005DC1F3` (118 bytes, 45 instrucciones).

Invocadas como el motor de ponderación de fuerza de batalla (`0x0059C65C`, `0x0059C66D`, `0x005A9D66`, `0x005A9D77` en `CCombat`) y visualización de interfaz (`0x00785DA0` en `CCombatView`):
1. **Fuerza Efectiva Polimórfica (`0x005DC0E0`):**
   - Inicializa `*out_val = 0` mediante constante flotante $0.0005 \times 1000.0$.
   - Recorre jerárquicamente todos los ejércitos y subunidades del combatiente.
   - Evalúa el método virtual slot 9 (`+0x24`): `CSubUnit::IsLand()`.
   - Si la unidad es terrestre (`CRegiment`, slot 9 retorna 1 en `0x00A31490`), acumula la dotación física actual (`regiment->strength` en `+0x3C`).
   - Si la unidad es naval (`CShip`, slot 9 retorna 0 en `0x0058CFD0`), acumula el parámetro de potencia intrínseca/dotación de buque (`ship->type->max_strength` en `+0x244`), equiparando la presencia naval a su escala potencial de combate.
2. **Fuerza Actual Total (`0x005DC180`):**
   - Inicializa `*out_val = 0` mediante constante flotante $0.0005 \times 1000.0$.
   - Recorre todos los ejércitos y subunidades sumando directamente los efectivos vivos actuales (`subunit->strength` en `+0x3C`) sin distinción de rama.
   - Retorna el puntero `out_val` en `eax` para ser consumido por `CCombatView` (que divide entre 1000.0 para reportar los miles de hombres activos) y por `0x005954DC` (que contrasta los efectivos contra el umbral mínimo de batalla en `[0x0125F594]`).

Reverify comprueba 117 afirmaciones de instrucciones en PE32, vtables, constantes flotantes y puntos de llamada con control negativo refutado e invalidación dependiente. Unicorn emula 58 fixtures dinámicos cubriendo formaciones vacías, regimientos de tierra, buques navales, armadas mixtas y contingentes masivos con 0 discrepancias frente a `combatant_strength_model.py`.

## Ponderación de Moral Media y Organización Máxima de Combatiente (`CCombatant::CalculateAverageMorale` y `CCombatant::CalculateAverageMaxMorale`)

El contrato de [moral de combatiente](contracts/COMBATANT-MORALE.md) formaliza las rutinas de agregación y normalización de la moral operativa de batalla:
- `CCombatant::CalculateAverageMorale`: `0x005DC630..0x005DC6FD` (206 bytes, 70 instrucciones).
- `CCombatant::CalculateAverageMaxMorale`: `0x005DC710..0x005DC7B2` (163 bytes, 59 instrucciones).

Invocadas en el motor de interfaz de batalla (`0x00785B1B` y `0x00785B2E` en `CCombatView::UpdateMoraleProgress`):
1. **Moral Viva Ponderada (`0x005DC630`):**
   - Inicializa `*out_val = 0` mediante constante flotante $0.0005 \times 1000.0$.
   - Itera por todos los ejércitos o armadas enlazadas en el combatiente.
   - Lee el recuento de subunidades $N_k = [A_k + 0x40]$ e invoca virtualmente a `A_k->CalculateAverageMorale()` (slot 37, `+0x94` en `CArmy` y `CNavy`, implementado en `0x005C8DC0`).
   - Pondera cada ejército en 64 bits mediante `_alldiv`: $W_k = \lfloor (N_k \times 1000 \times M_k) / 1000 \rfloor = N_k \times M_k$.
   - Acumula la suma ponderada y el total de subunidades.
   - Divide la masa total acumulada entre el recuento total con `_allmul` y `_alldiv` en milésimas, retornando la moral media global del contingente.
2. **Moral Máxima Teórica (`0x005DC710`):**
   - Inicializa `*out_val = 0`.
   - Itera por los ejércitos leyendo $N_k = [A_k + 0x40]$ e invocando virtualmente a `A_k->CalculateMaxMorale()` (slot 17, `+0x44`, implementado en `0x005CFA90`).
   - Pondera idénticamente por el número de regimientos/buques en 64 bits y normaliza entre el recuento total.
   - La ratio $\frac{\text{MoralViva}}{\text{MoralMáxima}}$ alimenta de forma directa el porcentaje de llenado de la barra verde/roja de moral de atacante y defensor en la ventana táctica de combate.

Reverify comprueba 157 afirmaciones de instrucciones en PE32, vtables (slots 37 y 17 en CArmy y CNavy), constantes flotantes y puntos de llamada en CCombatView con control negativo refutado e invalidación dependiente. Unicorn emula 78 fixtures dinámicos cubriendo formaciones vacías, ejércitos individuales, contingentes con pesos asimétricos y flotas multinacionales con 0 discrepancias frente a `combatant_morale_model.py`.

## Recuento de Subunidades y Cómputo de Peso de Suministro Militar (`CCombatant::CountTotalRegiments`, `CCombatant::CalculateSupplyWeight` y `CArmy::CalculateSupplyWeight`)

El contrato de [peso y recuento de subunidades](contracts/SUBUNIT-WEIGHT.md) formaliza la tríada de rutinas de agregación estructural y demanda logística de formaciones:
- `CCombatant::CountTotalRegiments`: `0x005DC560..0x005DC58F` (48 bytes, 18 instrucciones).
- `CArmy::CalculateSupplyWeight`: `0x005DC590..0x005DC5CB` (60 bytes, 17 instrucciones).
- `CCombatant::CalculateSupplyWeight`: `0x005DC5D0..0x005DC621` (82 bytes, 29 instrucciones).

Invocadas en los informes de batalla (`0x0078F55F`, `0x00791601` en `CCombatView`), interfaces de selección militar (`0x00828AED`, `0x008296ED` en `CArmyView`) y el motor de embarque marítimo (`0x0084E97B` en `CShipView::CanEmbark`):
1. **Censo Total de Regimientos (`0x005DC560`):**
   - Recorre todos los ejércitos enlazados y sus listas de subunidades en `[army + 0x38]`.
   - Suma linealmente la cantidad de subunidades activas en `eax`, alimentando los desgloses cuantitativos de la interfaz y la verificación de límites operativos de maniobra.
2. **Carga Logística y Peso de Embarque de Ejército (`0x005DC590`):**
   - Itera por la lista de subunidades del ejército accediendo al descriptor de tipo (`[regiment + 0xA4]`).
   - Lee el consumo de suministro / peso unitario `[type + 0x258]`.
   - Aplica división entera por 1000 mediante la constante mágica `0x10624DD3`.
   - Suma la carga en `eax` para ser contrastada directamente contra la capacidad de bodegas de transporte de la flota naval (`[ship + 0x98]`).
3. **Carga Logística Agregada de Selección Múltiple (`0x005DC5D0`):**
   - Recorre las formaciones seleccionadas y sus subunidades en `[army + 0x90]`.
   - Divide idénticamente el consumo `[type + 0x258]` entre 1000 y acumula el total en `eax`, permitiendo a la interfaz validar transferencias masivas, fusiones de ejército y adecuación logística global.

Reverify comprueba 85 afirmaciones de instrucciones en PE32, constantes de división entera y puntos de llamada con control negativo refutado e invalidación dependiente. Unicorn emula 66 fixtures dinámicos cubriendo formaciones vacías, regimientos individuales, agrupaciones compuestas y valores paramétricos extremos con 0 discrepancias frente a `subunit_weight_model.py`.

## Determinación de Amenaza Hostil Provincial y Fuerzas Beligerantes (`CProvince::CalculateHostileTroopDivisions` y `CProvince::CountHostileRegiments`)

El contrato de [amenaza hostil provincial y fuerzas beligerantes](contracts/HOSTILE-TROOP.md) formaliza las rutinas de evaluación territorial de presencia enemiga:
- `CProvince::CalculateHostileTroopDivisions`: `0x005DC7C0..0x005DC8AD` (238 bytes, 76 instrucciones).
- `CProvince::CountHostileRegiments`: `0x005DC8B0..0x005DC938` (137 bytes, 49 instrucciones).

Invocadas en la interfaz militar y evaluación táctica de amenaza (`0x00828A13`, `0x00828CF4`, `0x00829484`, `0x0082A666` en `CArmyView`):
1. **Filtro Naval y Nacional Propio:**
   - Descarta inmediatamente flotas navales mediante `A_k->IsNavy()` (slot 15, `+0x3C`).
   - Descarta ejércitos pertenecientes a la misma nación soberana (`A_k.country_id == target_country_id`).
2. **Determinación Diplomática y Rebelde de Beligerancia:**
   - Comprueba la matriz de relaciones diplomáticas (`[country + 0xBE8]`): si `rel.is_at_war != 0` (`+0x34`), la fuerza es considerada hostil.
   - En ausencia de guerra formal, inspecciona los tags nacionales ASCII de 3 bytes: si el país objetivo o el ejército en evaluación posee el tag `b"REB"` (`0x52, 0x45, 0x42`), se clasifica como facción rebelde insurgente y se trata como hostil.
3. **Cómputo Cuantitativo de Amenaza:**
   - `0x005DC7C0` (`CalculateHostileTroopDivisions`): acumula los efectivos vivos de los regimientos (`regiment->strength` en `+0x3C`) y calcula las divisiones hostiles normalizadas a unidades de 1,000 hombres mediante la constante de división entera mágica `0x10624DD3` (`floor(total_strength / 1000)`).
   - `0x005DC8B0` (`CountHostileRegiments`): acumula el conteo nominal de subunidades del ejército (`[army + 0x40]`).

Reverify comprueba 136 afirmaciones de instrucciones en PE32, slots de vtables, constantes mágicas de división y tags rebeldes con control negativo refutado e invalidación dependiente. Unicorn emula 30 fixtures dinámicos cubriendo ejércitos propios, aliados, neutrales, beligerantes, rebeldes y flotas navales con 0 discrepancias frente a `hostile_troop_model.py`.

## Determinación de Fuerza Hostil Naval y Censo Directo de Beligerancia Provincial (`CProvince::CalculateHostileNavalDivisions` y `CProvince::CountHostileUnitsDirect`)

El contrato de [fuerza hostil naval y censo directo provincial](contracts/HOSTILE-NAVAL-DIRECT.md) formaliza las rutinas complementarias de escrutinio de amenazas marítimas y censo militar:
- `CProvince::CalculateHostileNavalDivisions`: `0x005DC940..0x005DCA2F` (240 bytes, 78 instrucciones).
- `CProvince::CountHostileUnitsDirect`: `0x005DCA30..0x005DCAB4` (133 bytes, 50 instrucciones).

Invocadas en el motor naval de patrulla, intercepción y bloqueo (`0x005B9AC3`, `0x005B9CB2`), así como en la evaluación táctica de guarnición provincial (`0x008238F0` en `CArmyView`):
1. **Filtro Terrestre vs Exclusión Polimórfica:**
   - En `CalculateHostileNavalDivisions` (`0x005DC940`), el motor invoca polimórficamente `U_k->IsLand()` (slot 14, `+0x38`):
     - En `CArmy` (`vtable 0x00DF88CC` + `0x38 = 0x00DF8904` -> `0x00A31490`), retorna `true` (1), por lo que las fuerzas terrestres son descartadas de inmediato.
     - En `CNavy` (`vtable 0x00E02FCC` + `0x38 = 0x00E03004` -> `0x0058CFD0`), retorna `false` (0), permitiendo evaluar exclusivamente flotas y escuadras navales.
   - En `CountHostileUnitsDirect` (`0x005DCA30`), no se invocan filtros virtuales; evalúa de manera uniforme todas las formaciones militares presentes en la provincia (`ecx = &armies`).
2. **Determinación Diplomática y Rebelde:**
   - Descarta formaciones pertenecientes a la nación soberana propia (`country_id == target_country_id`).
   - Evalúa beligerancia formal mediante la matriz diplomática (`[country + 0xBE8]->is_at_war` en `+0x34`).
   - Si no hay guerra declarada, comprueba si el tag del país objetivo o de la fuerza militar coincide con `"REB"` (`0x52, 0x45, 0x42`), tratando a los insurgentes como enemigos activos.
3. **Métrica Naval y Censo Cuantitativo:**
   - `0x005DC940`: acumula la potencia viva de los buques (`ship->strength` en `+0x3C`) y calcula las divisiones de escuadra normalizadas a unidades de 1,000 mediante la constante entera mágica `0x10624DD3` (`floor(total_strength / 1000)`). El llamador en `0x005B9AC8` / `0x005B9CB7` multiplica por 1000 (`imul eax, 0x3E8`) para contrastar la potencia naval enemiga frente a la propia.
   - `0x005DCA30`: totaliza directamente el conteo nominal de regimientos y subunidades (`[army + 0x40]`) de todas las fuerzas beligerantes.

Reverify comprueba 150 afirmaciones de instrucciones en PE32, slots 14 y 15 de vtables en `CArmy` y `CNavy`, constantes mágicas de división entera, constantes de punto flotante y puntos de llamada con control negativo refutado e invalidación dependiente. Unicorn emula 60 fixtures dinámicos cubriendo escuadras navales, ejércitos terrestres, formaciones mixtas, coaliciones y fuerzas rebeldes con 0 discrepancias frente a `hostile_naval_direct_model.py`.

## Capacidad de Aprovisionamiento y Límite de Suministro Naval (`CNavy::CalculateSupplyLimit`)

El contrato de [límite de suministro naval](contracts/NAVY-SUPPLY-LIMIT.md) formaliza el método virtual `CNavy::CalculateSupplyLimit` en `0x005D81A0..0x005D82FE` (351 bytes, 117 instrucciones), correspondiente al slot 30 (`+0x78`) de la vtable de `CNavy` en `0x00E03044` (vtable base en `0x00E02FCC`).

Esta rutina constituye el homólogo marítimo exacto de `CArmy::CalculateSupplyLimit` (`0x005D63E0`, Suite 52), computando el techo de aprovisionamiento de una flota naval en puertos y fondeaderos provinciales:
1. **Filtro de Infraestructura Naval Nacional:**
   Inspecciona la tabla de bases navales activas en `[0x012588E8] + 0xAEC`. Si el país de la flota carece de registro de bases navales, retorna de inmediato `0` milésimas (mediante floor de $0.0005 \times 1000.0$).
2. **Entorno Geográfico y Acceso a Dique:**
   - Si la provincia es mar abierto (`[province + 0x5C]->is_water != 0`), escribe `0` (las flotas en alta mar carecen de límite estático provincial y sufren atrición de travesía).
   - En provincias costeras con puerto, invoca `0x004B7DB0`. Si se deniega el acceso a atraque (`al != 0`), escribe `0`.
3. **Bloqueo Hostil y Control Enemigo:**
   Si la provincia dispone de base naval construida (`[province + 0x5C]->has_naval_base != 0`), invoca `0x00539260` contrastando la soberanía contra la nación de la flota. Si el puerto está bajo ocupación hostil o bloqueado por el enemigo, retorna `0`.
4. **Cálculo Base por Nivel Portuario:**
   Escala la intendencia a razón de 2,000 milésimas por nivel de base naval más 1,000 milésimas de margen base:
   $$\text{base\_supply} = (\text{naval\_base\_level} \times 2000) + 1000$$
5. **Bonificación de Rasgo de Almirante:**
   Si la flota tiene comandante asignado (`[navy + 0xD8]`), invoca `pLeader->HasActiveSupplyTrait()` (slot 8 en su vtable). Si está activo, añade el modificador de suministro del almirante `[leader + 0x48]->0x38`.
6. **Escalado Tecnológico Naval en 64 bits:**
   Aplica el piso a cero ($\max(0, \text{base})$) y multiplica por el modificador tecnológico naval en `[country + 0xBCC]->0x24` ($\text{tech}$ en milésimas):
   $$\text{limit} = \left\lfloor \frac{\text{base\_supply} \times (\text{tech} + 1000)}{1000} \right\rfloor$$
   Calculado mediante producto entero de 64 bits y división `_alldiv` (`0x00AC02A0`), persistiendo el resultado en `*out_limit`.

Reverify comprueba 120 afirmaciones de instrucciones en PE32, slot 30 de vtable en `CNavy`, constantes enteras $2000$ y $1000$, constantes IEEE 754 y singletons de estado con control negativo refutado e invalidación dependiente. Unicorn emula 45 fixtures dinámicos cubriendo países sin bases, mar abierto, puertos bloqueados, puertos aliados, niveles escalonados de base naval, rasgos de almirante y tecnología logística sin discrepancias frente a `navy_supply_limit_model.py`.

## Mantenimiento Operativo y Evaluación de Atrición Naval (`CNavy::CalculateSeaAttrition` y `CNavy::EvaluateResupplyNecessity`)

El contrato de [atrición y necesidad de reabastecimiento naval](contracts/NAVY-ATTRITION-RESUPPLY.md) formaliza las rutinas que gobiernan el desgaste en alta mar y la necesidad de retirada o carenado de flotas:
- `CNavy::CalculateSeaAttrition`: `0x005D7EC0..0x005D7F6E` (175 bytes, 58 instrucciones), correspondiente al slot 31 (`+0x7C`) de la vtable de `CNavy` en `0x00E03048` (`0x00E02FCC + 0x7C`).
- `CNavy::EvaluateResupplyNecessity`: `0x005D8120..0x005D8199` (122 bytes, 36 instrucciones).

El motor naval estructura el mantenimiento marítimo en dos fases:
1. **Atrición por Tiempo en Alta Mar (`0x005D7EC0`):**
   - Comprueba el tiempo de navegación `[navy + 0x1BC]` contra el umbral de gracia en `[defines + 0xF0] // 1000` (discretizado mediante la constante entera mágica `0x10624DD3`). Si la flota permanece dentro del periodo de gracia, retorna inmediatamente `0`.
   - Superado el umbral, evalúa la distancia `[navy + 0xB0]` respecto a la base naval amiga más cercana dividida entre `[defines + 0xE4]` mediante bifurcación 32-bit vs 64-bit (`_allmul` / `_alldiv`).
   - El factor de tensión $\Delta = 1000 - \text{ratio}$ modula la atrición máxima permitida `[defines + 0xEC]`, retornando el porcentaje diario de desgaste por travesía en `*out_attrition`.
2. **Evaluación de Necesidad de Reabastecimiento (`0x005D8120`):**
   - Invoca virtualmente a `CalculateSeaAttrition` (slot 31, `+0x7C`). Si la flota sufre atrición activa ($> 0$), retorna de inmediato `true` (1), forzando a la IA o interfaz a ordenar el regreso a puerto.
   - En caso contrario, si la flota está estacionada en una provincia con fondeadero o muelle operativo ($[port + 0x20] > 0$) y dispone de buques ($[navy + 0x40] > 0$), invoca polimórficamente a `CUnit::CalculateAverageSubunitHealthRatio` (slot 21, `+0x54` en `0x005CFE90`).
   - Compara la salud media de los buques contra el umbral estricto en la constante flotante `0x00E45ADC`: $850.5$ milésimas ($85.0\%$). Si la integridad estructural media es inferior al $85.0\%$, retorna `true` (1), activando los protocolos de reparación y refuerzo portuario; de lo contrario, retorna `false` (0).

Reverify comprueba 121 afirmaciones de instrucciones en PE32, slots 31 y 21 de vtables en `CNavy` y `CArmy`, constante mágica de división entera, constantes de milésimas, constante IEEE 754 de 850.5 y singletons globales con control negativo refutado e invalidación dependiente. Unicorn emula 20 fixtures dinámicos cubriendo periodos de gracia, navegación lejana, fondeaderos sin capacidad, buques íntegros y cascos dañados con 0 discrepancias frente a `navy_attrition_resupply_model.py`.

## Evaluación de Cohesión y Ratios Promedio de Fuerza y Moral en Formaciones Militares (`CUnit::CalculateAverageSubunitStrengthRatio` y `CUnit::CalculateAverageSubunitMoraleRatio`)

El contrato de [evaluación de cohesión y ratios promedio](contracts/FORMATION-COHESION.md) formaliza los dos métodos virtuales polimórficos de `CUnit` que cuantifican la integridad de combate de ejércitos y armadas:
- `CUnit::CalculateAverageSubunitStrengthRatio`: `0x005CFE90..0x005CFF85` (246 bytes, 96 instrucciones), correspondiente al slot 21 (`+0x54`) en las vtables de `CArmy` (`0x00DF8920`) y `CNavy` (`0x00E03020`).
- `CUnit::CalculateAverageSubunitMoraleRatio`: `0x005CFF90..0x005D0099` (266 bytes, 103 instrucciones), correspondiente al slot 22 (`+0x58`) en las vtables de `CArmy` (`0x00DF8924`) y `CNavy` (`0x00E03024`).

Ambas rutinas operan sobre la lista enlazada de subunidades de la formación (`[this + 0x38]`) con la siguiente mecánica:
1. **Inicialización en Punto Fijo:**
   Inician `*out_ratio = 0` mediante el constructor en línea de `CFixedPoint(0.0f)` (evaluado como $\lfloor (0.0 + 0.0005) \times 1000.0 \rfloor = 0$).
2. **Ratio Individual de Fuerza / Salud (`0x005CFE90`):**
   - Para cada subunidad, lee `current_strength = [subunit + 0x3C]` e invoca polimórficamente `vtable[12]` (`CSubUnit::GetMaxStrength(&temp, 0)` en `0x005BFF80`, slot 12 de `CRegiment` `0x00DF88B4` y `CShip` `0x00E02A94`).
   - Si `max_strength == 0`, asigna el centinela `-1` ($-0.001$).
   - Si `max_strength > 0`, computa $(\text{current\_strength} \times 1000) / \text{max\_strength}$. Si el valor está en el intervalo $[-1610611, 2147482]$ (`[ebx + 0x189373] <= 0x39580d`), utiliza `imul`/`idiv` de 32 bits; si excede el rango, recurre a `_allmul` y `_alldiv` de 64 bits.
   - Acumula los ratios en `sum`.
3. **Ratio Individual de Moral y Filtro de Insurrección Rebelde (`0x005CFF90`):**
   - Inspecciona el POP de reclutamiento de la subunidad: si `[subunit + 0x74] != NULL` y la bandera de lealtad rebelde `[pop + 0x164] != 0`, la moral efectiva es anulada inmediatamente a `0`. En caso contrario, lee la moral nominal `[subunit + 0x40]`.
   - Invoca polimórficamente `vtable[13]` (`CSubUnit::GetMaxMorale(&temp, 0)` en `0x005BFFA0`, slot 13 de `CRegiment` `0x00DF88B8` y `CShip` `0x00E02A98`).
   - Si `max_morale == 0`, asigna `-1`; en caso contrario, computa $(\text{effective\_morale} \times 1000) / \text{max\_morale}$ respetando la bifurcación 32-bit vs 64-bit.
4. **Normalización por Conteo:**
   - Si el número total de subunidades $C = \text{[this + 0x40]}$ es 0, preserva el valor acumulado (0 para lista vacía).
   - Si $C > 0$, divide el acumulado entre $C \times 1000$ mediante `_alldiv(_allmul(sum, 1000), C * 1000) = floor(sum / C)`, asignando el resultado normalizado en milésimas a `*out_ratio`.

Reverify comprueba 214 afirmaciones de instrucciones en PE32, slots 21 y 22 de `CArmy`/`CNavy`, slots 12 y 13 de `CRegiment`/`CShip`, cotas de desbordamiento de 32 bits, constantes de punto flotante y padding de alineación con control negativo refutado e invalidación dependiente. Unicorn emula 60 fixtures dinámicos cubriendo formaciones vacías, regimientos íntegros, desgastados, facciones insurgentes y valores fuera de escala con 0 discrepancias frente a `formation_cohesion_model.py`.

## Ciclo Diario de Mantenimiento Naval y Aplicación de Daño por Atrición (`CNavy::DailyUpdate` y `CSubUnit::SetStrength`)

El contrato de [mantenimiento naval diario y aplicación de atrición](contracts/NAVY-DAILY-UPDATE.md) formaliza el ciclo diario de desgaste y daño marítimo que sufren las flotas navales:
- `CNavy::DailyUpdate`: `0x005C7AE0..0x005C7B79` (153 bytes, 54 instrucciones), correspondiente al slot 29 (`+0x74`) en la vtable de `CNavy` (`0x00E03040`).
- `CSubUnit::SetStrength`: `0x005C02F0..0x005C036A` (122 bytes, 46 instrucciones), la rutina universal de asignación acotada de fuerza militar.

El motor ejecuta la simulación diaria de cada flota según la siguiente secuencia:
1. **Delegación Base:** Invoca `CUnit::DailyUpdate` (`0x005C7B80`).
2. **Conmutador Global de Atrición:** Comprueba `[0x012588E8] + 0xD1C`. Si la simulación de atrición naval está desactivada globalmente, aborta de inmediato sin alterar el estado naval.
3. **Control Logístico de Travesía:** Compara la eficiencia de suministro de la flota (`[navy + 0xB0]`) contra el umbral de alcance naval `[defines + 0xE4]`:
   - Si $\text{supply\_efficiency} \ge \text{range\_divisor}$: la flota está adecuadamente abastecida y reinicia el contador de días en el mar: `[navy + 0x1BC] = 0`.
   - Si $\text{supply\_efficiency} < \text{range\_divisor}$: la flota carece de línea logística y acumula un día más en alta mar: `[navy + 0x1BC] += 1`.
4. **Cálculo de Desgaste de Flota:** Invoca virtualmente `CalculateSeaAttrition(&attrition)` (slot 31 en `0x005D7EC0`, formalizado en Suite 83). Si la atrición es nula ($\le 0$), finaliza el ciclo.
5. **Aplicación de Daño y Piso de Supervivencia:**
   - Lee el umbral mínimo de supervivencia del buque en `[defines + 0xE8]` (típicamente 100 milésimas).
   - Recorre cada buque de la flota (`[navy + 0x38]`):
     - Si la fuerza del buque es menor o igual al umbral mínimo, no recibe daño (evitando el hundimiento pasivo por atrición).
     - Si supera el umbral, deduce el daño de atrición: $\text{damaged} = \max(\text{min\_strength}, \text{current\_strength} - \text{attrition})$.
     - Invoca `ship->SetStrength(damaged)` (`0x005C02F0`), que acota la fuerza estrictamente a $[0, \text{max\_strength}]$ y la persiste en `[ship + 0x3C]`.

Reverify comprueba 112 afirmaciones de instrucciones en PE32, slots de vtables de `CNavy`, `CArmy`, `CShip` y `CRegiment`, punteros a singletons de estado y defines, constantes de punto flotante y padding de alineación con control negativo refutado e invalidación dependiente. Unicorn emula 40 fixtures dinámicos cubriendo atrición desactivada, aprovisionamiento suficiente, días en alta mar, periodo de gracia, atrición activa, múltiples buques y pisos de supervivencia con 0 discrepancias frente a `navy_daily_update_model.py`.



## Cadena y estructura del job diario de IA por país (`AI_FrameUpdate` → `FUN_0081e9e0` → `AI_DecisionUpdate`)

Primer avance sobre el bloque de IA del [mapa](PLAN.md): [AI-DAILY-JOB.md](AI-DAILY-JOB.md) fija
la cadena de llamadas y la forma del bucle, separando lo verificado de lo inferido.

- `FUN_0081e9e0` (**196 bytes**, `0x0081E9E0..0x0081EAA4`) es el job de IA de un país y tiene
  exactamente **tres** llamadores, los tres recorriendo una lista enlazada por `+0x208`:
  `0x00687578` (dentro de `AI_FrameUpdate`), `0x0064F01C` y `0x006690CD`. Comprobado con
  `scripts/find_callers.py`.
- El cuerpo empieza descartando países cuyo tag es `REB` (comparación literal de los bytes
  `'R'`,`'E'`,`'B'` en `[esi+0x30]`, `confirmed`; la interpretación como rebeldes es `inferred`),
  resuelve el país por un vector global en `0x12587E4` indexado con `[esi+0x34]`, y si el vector
  `[country+0x9D8]..[country+0x9DC]` está vacío termina sin trabajo.
- Con trabajo pendiente arma un acumulador auxiliar con `lea eax,[country+0x7B4]; call 0x5DCAC0`
  (lista de nodos de 16 bytes, `head`/`tail` en `+0x90`/`+0x94`, contador `+0x98`, suma en
  `+0x8C`), ejecuta una llamada virtual por `[vtable+0x24]` y lo descarta con `call 0x5DCB70`
  (libera y pone a cero esos cuatro campos). **No es un lock**: se verificó desensamblando ambas
  rutinas, y corrige la lectura anterior. Después encadena `0x81F3B0`, `0x81E5B0`, y
  `0x81FB00`/`0x820760` bajo `[country+0xBB8]==0`.
- `AI_DecisionUpdate` (`0x00821190`, **885 bytes**) tiene **un solo llamador**: `0x0081EA9B`,
  dentro de ese mismo job. Usa SEH y contenedores locales de 56 bytes.
- `FUN_00876240` (**1793 bytes**) tiene **siete** sitios de llamada directa y arranca contando
  elementos de un vector de 4 bytes colgado de `0x12587E4`; el camino corto copia el par
  `[arg+0x108]`/`[arg+0x10C]` a `[esi+8]`/`[esi+0xC]`. La hipótesis anterior de que fuera un
  switch de triggers **no está contrastada** y queda marcada como tal.

Consecuencia para paralelizar: la unidad natural del AI es el país, la cola entrega índices y el
país se resuelve por el vector de `0x12587E4`. **No hay lock ni mutex en la ruta del job** (se
descartó al desensamblar `0x5DCAC0`/`0x5DCB70`: son un acumulador, no sincronización). Quedan
tres requisitos antes de pensar en varios hilos: auditar que ningún job escriba en otro país,
resolver el spin de `[country+0x208]`, y determinar de dónde sale el estado del LCG por país.

### Consumo de RNG en el job de IA por país (hallazgo con impacto directo en paralelización)

`AI_DecisionUpdate` (`0x00821190`) llama **dos veces** al LCG del CRT en `0x008212FA` y
`0x00821453`, con el patrón `rand() % 100 < (int)(chance * 100.0)`:

- `0x00AB047B` es `mov eax,[ecx+0x14]; imul eax,eax,0x343FD; add eax,0x269EC3;
  mov [ecx+0x14],eax; shr eax,0x10` — el mismo LCG que modela
  [`event_spawn_model.py`](../scripts/event_spawn_model.py) (`lcg_step`), distinto del MT19937
  del contrato [RNG](contracts/RNG.md).
- `0x00E455E8` es el double `100.0` (`0x4059000000000000`), leído del archivo.
- El umbral sale de una llamada previa (`0x008212DC` / `0x00874EA0`) cuyo float se multiplica por
  ese 100.0 y se trunca con `fistp`.

**Origen del estado (resuelto)**: `0x00AB047B` llama primero a `0x00AB98AF`, que es el
`__acrt_getptd()` de MSVC (`call 0x00AB9836`, y `push 0x10; call 0x00AB220B` si devuelve cero).
El estado está en `ptd+0x14`, la rutina hace `seed = seed*0x343FD + 0x269EC3`, lo guarda, y
devuelve `(seed >> 16) & 0x7FFF`. Es **`rand()` del CRT con estado por hilo**, idéntico a
`lcg_step` + `& 0x7FFF` de `scripts/event_spawn_model.py` (contrato
[EVENT-SPAWN](contracts/EVENT-SPAWN.md)). Tiene 38 referencias en el binario.

**Consecuencia**: al repartir el bucle de países entre hilos cada hilo tendría su propio `ptd` y
su propia secuencia, así que el resultado deja de coincidir con la partida secuencial. Mantener
determinismo exige un estado controlado por país o serializar el consumo.

`FUN_00876240` usa además **otro** generador: `0x009B7910`, con el estado pasado explícitamente
en `this+0x40` (dos pasos del mismo LCG). Los dos conviven.

Detalle adicional: `0x008A88D0` escribe `0x00E2C904` en `[eax]` y `0x18D` en `[eax+4]`, copiando
tres palabras de `[ecx+8..0x10]`; en `0x00E2C904` hay seis punteros seguidos del literal
`Event_Election_Window`, al que apunta el último de ellos (`0x004010C0`).

### `AI_FrameUpdate` consume una cola con presupuesto de tiempo y hace spin por país

`FUN_006874c0` (`0x006874C0..0x006875DA`, 282 bytes) no recorre la lista de países: saca trabajos
de una cola cuyo contador está en `+0x8`, los libera con `0xAae91b` y por cada uno resuelve el
país con el vector de `0x12587E4` para llamar `FUN_0081e9e0`.

- Antes de procesar lee un `double` por una llamada virtual (`[0x1258A8C]` → `[vtable+0x14]` →
  `fstp qword`), que actúa como presupuesto de tiempo del frame.
- Entre `0x00687572` y `0x00687574` hay un **spin** que espera a que `[country+0x208]` deje de ser
  cero antes de invocar el job. `inferred`: inicialización perezosa del nodo de IA del país, o
  bandera de ocupado.
- Inicializa perezosamente el singleton `0x00F20C18` (alloc de 4 bytes, escribe `0x00E38B28`), y
  repite el mismo bloque al final de la función.

Consecuencia: el coste del AI no es sólo el trabajo por país, sino el troceado de la cola entre
frames. Un spin sobre estado compartido es además un riesgo concreto para cualquier intento de
ejecutar estos jobs en varios hilos.

### Evaluadores AND/OR y hoja comparadora de la cadena de condiciones del AI

Los nodos que el perfil de muestreo atribuye al AI resultaron ser evaluadores genéricos sobre un
vector de punteros:

- `0x008B8260` (66 B) — **AND**: `n = ([this+0xC]-[this+8])>>2`; por cada elemento llama
  `elem->vtable[6](arg)` y devuelve `false` al primer falso.
- `0x008B9240` (66 B) — **OR**: mismo recorrido, `cmp al,1; jz` devuelve `true` al primer
  verdadero.
- `0x008B94B0` (117 B) — construye contexto con `0x008A8650`, llama a la selección aleatoria
  `0x00876240` pasando `[this+0x1C]`, y luego evalúa el vector con ese contexto.
- `0x008E2A70` (47 B) — hoja: `country = ((Countries*)0x12587E4)->begin[arg->[0xC]]`,
  `return country->[0xE64] == this->[0x1C]` (`setz al`).

`0x008B8260` y `0x008B9240` comparten estructura y sólo cambian la condición de corte; ambos usan
el slot 6 (`[vtable+0x18]`) como método de evaluación. La hoja compara un único campo del país
(`+0xE64`) contra un valor del nodo, que es la forma mínima de un trigger de igualdad.

### Las dos sub-rutinas restantes del job de IA (`0x00820DF0`, `0x0081E280`)

- `FUN_00820DF0` (**788 B**, 263 instr., 18 llamadas directas): toma `list = country->[0xCE4]`,
  recorre con `next` en `+0x8` y por nodo llama `0x00911760` (1142 B), una virtual al slot 27
  (`[vtable+0x6C]`) y exige `[esi+0x24] == 1` antes de entrar en una cadena de llamadas a
  `0x0084xxxx`. Un solo salto hacia atrás.
- `FUN_0081E280` (**812 B**, 283 instr., 9 llamadas, 7 saltos hacia atrás): mismo esqueleto que
  `0x0081E5B0` (país por `0x12587E4`, gate `[country+0x67C]`, vector `[+0x9D8]..[+0x9DC]`,
  `[world+0xACC]` como tabla), división en milésimas con `0x00AC9F20`/`0x00AC02A0` y dos
  comprobaciones de vector (`0x00A513F0`, `cmp eax,0x3FFFFFFE`). Termina eligiendo un elemento con
  `rand() % n` y llamando `[[esi+0x38] + 0x24]`.

Ambas quedan con **cierre de rango incompleto** en Capstone (el desensamblado no consume todos los
bytes hasta el `end_va` de Ghidra), señal de tablas de datos o de código inalcanzable dentro del
rango declarado. No se publican como completas.

### Singleton de `AI_FrameUpdate`

El objeto que `0x006874c0` asegura en `0x00F20C18` se asigna con `push 4; call 0xAAE9AF` y su
único campo es `0x00E38B28`, que es una tabla de punteros (`0x009A7200`, `0x009A6E80`,
`0x009A6EA0`, `0x009A6F40`, …). `inferred`: un objeto de 4 bytes cuya vtable lo identifica como
funtor o interfaz usada por la cola.

### `0x00911760`: condición con fecha del mundo y matriz de relaciones

`FUN_00911760` (1142 B, 333 instrucciones, 63 llamadas entrantes) es la primera llamada de
`0x00820DF0` y resulta ser un método de condición (`this` en `esi`, con vtable). Lecturas
verificadas por bytes:

- `[world+0xD11]` (byte) y `[world+0xB24]` (puntero) antes de una virtual `[vtable+0x24]`.
- `Countries->begin[[esi+0xC]]` para resolver un país por índice y `country->[0xBE8][[esi+0x14]]`
  para llegar al objeto de relación: la misma matriz 683×683 ya identificada en el proyecto.
- Compara `[world+0xB0C]` (fecha de simulación; el mismo contador que se usó para medir días)
  contra `[relacion+0x64]`, una fecha guardada en la relación.
- Consulta el byte `[pais+0x31]` y las banderas `[0x125873E]` y `[world+0xD11]`; repite la virtual
  `[vtable+0x64]` (slot 25) en dos ramas.

Hipótesis de trabajo (`hypothesis`): filtro de "relación conocida y vigente". No confirmar.

### Las once salidas de `FUN_00876240` son filtros en cascada

`FUN_00876240` no tiene un `ret` único: hay **11 saltos al epílogo compartido `0x008767F0`**, que
hace `mov byte [esi+0x1C],0` y retorna con `ret 4`. Cada salto lleva su propia condición:
virtual `[vtable+0x20]` falso, `[edi+0x18]==0`, lista vacía (`test ecx,ecx`), contador de opciones
≤ 0, `[edi+0x18]` nulo, `[world+0xACC][idx]->[+0x188]==0` (dos ramas), `[objeto+0x288]==0`,
`[world+0xCF8]->[+0x8]==0`, `[edi+0x10]` nulo, y
`[0x125870C]+0x2238 -> [eax+edi*4] -> [+0x188]==0`.

Dos consecuencias verificables: la función recorre **tres listas por desplazamientos distintos**
(`+0x8` en el bucle de selección, `+0x18` y `+0x10` en ramas posteriores), y tres de las salidas
consultan el campo `+0x188` del objeto obtenido de una tabla indexada. Las ocho primeras salidas
limpian `[esi+0x1C]` en vez de devolver un valor en `al`, lo que todavía no está explicado.

### El destino de la selección aleatoria es un `CEventScope`

`0x008A8650` (215 B) es el constructor del objeto que `FUN_00876240` usa como destino, y fija
`[esi] = 0x00E2C904` y `[esi+4] = 0x18D`, además de `[esi+8] = 0x2D2D2D` (el literal `---`) y dos
palabras a cero. Son **la misma vtable y el mismo valor 0x18D** que escribe `0x008A88D0` desde
`AI_DecisionUpdate`: las dos rutas construyen la misma clase.

**Corrección**: `0x00E2C904` es la vtable de **`CEventScope`** según el inventario RTTI (locator
`0x00E60C68`). Este apartado decía antes "`Event_Election_Window`", tomado del literal que está
detrás de la tabla (`0x00E2C918`); ese literal es un **campo** del objeto, no el nombre del tipo.

El cierre del resultado usa dos bytes contiguos: `0x00876240` pone `byte [esi+0x1D] = 1` en
`0x008767EC` (ruta de éxito) y `byte [esi+0x1C] = 0` en el epílogo `0x008767F0`. Un escaneo de
`mov byte [reg+0x1C], 1` (`C6 /0` con `disp8=0x1C, imm8=1`) encuentra 30 sitios en `.text` y
**ninguno dentro de la función**; el constructor los inicializa juntos con
`mov word [esi+0x1C], cx`, cuyo valor no se puede determinar estáticamente. Queda como pregunta
abierta que necesita traza dinámica.

### Contrato de los bytes `+0x1C`/`+0x1D` del objeto resultado (resuelto)

El constructor `0x008A8650` fija el valor él mismo, sin tomarlo de un argumento:
`xor eax,eax; mov ecx,1; ...; mov word [esi+0x1C], cx`, o sea `+0x1C = 1` y `+0x1D = 0`.

`FUN_00876240` (21 `ret 4` en total):
- las **11 salidas por filtro** van a `0x008767F0`, que pone `+0x1C = 0`;
- la **ruta de éxito** pasa por `0x008767EC` (`+0x1D = 1`) y cae en ese mismo epílogo;
- la ruta rápida y las ~9 salidas tempranas por error **no tocan** ninguno de los dos bytes, así
  que conservan el 1 inicial.

Lectura: `+0x1C == 1` significa "la selección no descartó el objeto"; `+0x1D == 1` significa "se
eligió una opción". El invocador `0x008B94B0` comprueba `cmp byte [esp+0x2C], 0`, que cae en
`+0x1C`, y abandona con `al = 0` cuando es cero. Ya no hace falta traza dinámica.

### El job de IA itera y elige provincias, no países

Cruzando las tablas del job con lo ya documentado:

- `[country+0x9D8]..[country+0x9DC]` es el **vector de provincias del país**, ya formalizado en
  [COUNTRY-INFRASTRUCTURE-MODIFIER](contracts/COUNTRY-INFRASTRUCTURE-MODIFIER.md).
- `[0x012588E8 + 0xACC]` es la **tabla de punteros a provincias** de `g_ProvinceManager`, ya
  formalizada en [PROVINCE-EVENT-SPAWN](contracts/PROVINCE-EVENT-SPAWN.md).

Con eso, `0x0081E280` toma los ids del vector de provincias del país, los traduce con la tabla
global y **elige una provincia al azar** (`rand() % n`, LCG del CRT), no un país. Y las tres
salidas de `FUN_00876240` que consultan `[world+0xACC][idx]` están mirando provincias; el campo
`+0x188` de la provincia queda sin identificar.

Sigue sin documentar `0x125870C` (+0x2238), que indexa con el mismo id y expone el mismo `+0x188`.

### Ciclo de vida del gestor de países (`0x012587E4`)

- **Creación**: `FUN_0055cdc0` (`0x0055CDC0..0x0055CE4F`, 143 B, cierre exacto). Comprueba el
  singleton, hace `alloc(0x424)` (1060 bytes), pone a cero cuatro dwords, construye un contenedor
  interno con `sub_AAEB25(&obj[0x14], 0x10, 0x40, 0x413490, 0xAA8540)` y guarda el puntero en
  `0x012587E4`. El vector de países queda en `+4`/`+8`.
- **Destrucción**: función en `0x0055C750` que **Ghidra no detectó** (hueco entre `FUN_0055c6c0` y
  `FUN_0055c7e0`). Vacía dos contenedores globales con `0x55CF70`, anula `0x125DD9C`, y si el
  gestor existe llama a `0x55C7E0` (destructor), lo libera con `0xAAE91B` y escribe NULL en
  `0x012587E4`.

Con esto queda explicado el `0x0055C7CF` que el control de direcciones marcaba como fuera de
`functions.csv`: es código real en una función no reconocida por el analizador, no una dirección
inválida.

### Anclaje por RTTI de los tipos del job de IA

Con el inventario RTTI del repositorio (`evidence/generated/rtti/inventory.json`) se cierran las
clases por su vtable, y de ahí los constructores por la escritura del vptr:

| clase | vtable | constructor |
| --- | --- | --- |
| `CProvince` | `0x00DFD280` (+0x00) y `0x00DFD2A8` (+0x08) | `0x004A84FA` / `0x004A8500` |
| `CCountry` | `0x00DFFACC` | `0x004F6A39` |
| `CStaticModifier` | `0x00DF9944` | `0x004F6F70` |

Resultados directos:

- El subobjeto embebido del país en `+0x768` es un **`CStaticModifier`** (antes era sólo
  "subobjeto con vtable 0xDF9944").
- `0x125870C` **es el gestor de definiciones de provincia**: el constructor de `CProvince` hace
  `edx = [[0x125870C]+0x2AA4]; eax = [edx+eax*4]; [province+0x5C] = eax`. Es la misma familia que
  la tabla `+0x2238` que usa el job.
- El constructor de `CProvince` (`0x004A84E0`, 101 campos inicializados) **no toca `+0x188` ni
  `+0x18C`**: salta de `+0x184` a `+0x190` y ninguna instrucción menciona `0x188`. Si el job lo lee
  como puntero, se llena en otra ruta (carga de mapa o `memset` previo).
- `province+0x384` se inicializa a 0 en el constructor, coherente con lo que ya documentaba
  `PROVINCE-EVENT-SPAWN`.

### Tipos de todos los subobjetos, por RTTI

El inventario RTTI permite nombrar cada vtable que aparece en este bloque:

| vtable | clase |
| --- | --- |
| `0x00DFD280`, `0x00DFD2A8` | `CProvince` |
| `0x00DFD604` | `CSelectable` (base de `CProvince`) |
| `0x00DF9914` | `CProvinceModifier` (subobjeto de provincia en `+0x84`) |
| `0x00DF817C`, `0x00DF81A0` | `CFlags` (dos subobjetos de provincia, `+0x328` y `+0x34C`) |
| `0x00E02BB0` | `CUniqueUnitName` (subobjeto de provincia en `+0x35C`) |
| `0x00DF9944` | `CStaticModifier` (subobjeto del país en `+0x768`) |
| `0x00E2C904` | `CEventScope` |

Con esto, el objeto que construyen `0x008A8650` y `0x008A88D0` es un **ámbito de evento**, y la
estructura de provincia queda compuesta por dos vtable propias, un `CProvinceModifier`, dos
`CFlags` y un `CUniqueUnitName`.

### El tick diario dibuja el frame 11 veces

`FUN_006859c0` (`0x006859C0..0x006874BA`: 6906 bytes, 1958 instrucciones, 122 llamadas directas)
es el tick diario completo. Contando sus llamadas:

- **`UpdateTimeThrottle` (`0x00685620`) aparece 11 veces**, intercalado entre fases, no una sola vez
  al final. Es la explicación directa del 28 % de tiempo de pared que el perfil de muestreo
  atribuía a `UpdateTimeThrottle → App_ProcessMessagePumpAndUpdate`: el motor dibuja en cada corte
  entre fases.
- `0x00AC02A0` (helper aritmético de 64 bits) se llama **15 veces** por día; `0x00AAE9AF` (alloc)
  11 y `0x00AAE91B` (free) 10.
- El **MT19937 se regenera y se vuelve a sembrar dentro del mismo día** (`0x009B7700` en
  `0x00685BAD`, `0x009B7670` en `0x0068619F`).
- La **economía** (`0x00489990`) corre después de `Country_DailyUpdate` (`0x005091A0`) y antes del
  bloque de eventos (`0x008A7CD0`).

Secuencia de fases completa en [DAY-TICK.md](DAY-TICK.md).

### Cinco preguntas del bloque de IA resueltas con hooks en ejecución

Plugin nuevo `experiments/v2probe/` (stubs en ensamblador que registran y hacen `jmp` al original,
más resolución de RTTI **en runtime**: `vtable[-1] → COL`, `COL+0x0C → TypeDescriptor`, `+8 → nombre`).
Medido en partida real (España, 1836):

| campo | tipo resuelto |
| --- | --- |
| `[country+0x7B4]` (nodo y `+0xA0`) | **`CArmy`** — la lista es de ejércitos |
| `province+0x188` | **`CState`** (compartido por las provincias del mismo estado; `+0x18C = 0`) |
| `country+0xE64` | **`CCulture`** — es lo que compara la hoja `0x008E2A70` |
| `country+0xBCC` | **`CTechnologyStatus`** — confirma lo que el repositorio ya decía |
| `country+0xCE4` | **nulo** en tiempo de paz: la ruta de `0x00820DF0` no hace nada sin guerra |

Nodo de ejército medido: `elem` y `+0xA0` son `CArmy`; `+0x38` y `+0x98` valen `0x00080004` (dos
mitades de 16 bits, **no** punteros).
