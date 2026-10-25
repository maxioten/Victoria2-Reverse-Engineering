# Mapa de investigación

El alcance final es todo el engine; el entorno y la línea base ya están preparados.
Un inventario automático no equivale a haber entendido cada función.

| Bloque | Evidencia que se busca | Criterio de cierre |
| --- | --- | --- |
| PE, imports, CRT, RTTI y convenciones | Secciones, tablas, funciones, vtables y llamadas | Mapa reproducible, direcciones y binario identificados |
| Arranque y carga | Flujo desde entry point, inicializadores y creación del mundo | Llamadas y objetos contrastados con una carga observada |
| Frame, calendario y RNG | Quién encola/ejecuta ticks; estado temporal y aleatorio | Ruta llamada por llamada y trazas con entradas conocidas |

Primer avance del bloque de frame: [DAY-TICK.md](DAY-TICK.md) fija la secuencia de las 122 llamadas
del tick diario (`0x006859C0`) y documenta que **`UpdateTimeThrottle` se invoca 11 veces por día**,
una entre cada par de fases, lo que explica el 28 % de tiempo de pared del perfil. También deja
anotado que el MT19937 se regenera y se vuelve a sembrar dentro del mismo día.
| Modelo de datos | Países, provincias, POPs, unidades y relaciones | Campos con lectores/escritores, tamaños, vidas e invalidaciones |
| Economía y POPs | Fixed point, bienes, necesidades, mercado, migración | Dependencias y efectos laterales; pruebas de primitivas y sumas |
| IA y scripts | Triggers, scopes, decisiones, eventos y planificación | Contratos, RNG y órdenes; no atribuir pureza sin auditar escrituras |
| Ejército, flota y combate | Movimiento, pathfinding, refuerzo y resolución | Formatos, ecuaciones y orden de actualización verificados |
| Interfaz y recursos | Callbacks, render, entrada, audio y assets | Contratos y relación con el estado de simulación |
| Guardado y red | Serialización, comandos, checksum, sincronización | Layouts, rutas de carga/guardado y trazas de comandos |
| Optimización o reemplazo | Rutina original frente a candidato | Equivalencia dentro del dominio declarado y ganancia medida |

Primera investigación: seguir el comando temporal hasta la actualización del mundo y el
tick diario, contrastando las cuatro llamadas candidatas ya verificadas con las funciones
y referencias exportadas por Ghidra. Los nombres externos siguen siendo pistas.

Medir cobertura por separado: funciones detectadas, funciones revisadas, contratos
documentados y casos dinámicos validados. No publicar un porcentaje de «RE completado»
basado únicamente en el número de funciones autoanalizadas.

Hallazgos revisados y procedimientos: [HALLAZGOS.md](HALLAZGOS.md).

Bloque de IA en curso: [AI-DAILY-JOB.md](AI-DAILY-JOB.md). Estado actual, todo verificado por
bytes y llamadas salvo lo marcado como inferencia:

- Cadena `AI_FrameUpdate (0x006874C0)` → `FUN_0081e9e0 (0x0081E9E0)` → `AI_DecisionUpdate
  (0x00821190)`, con la cola de trabajos, el presupuesto de tiempo por frame y el spin por
  `[country+0x208]`.
- Las 11 sub-rutinas del job con sus sitios de llamada, y los evaluadores AND (`0x008B8260`), OR
  (`0x008B9240`), selección aleatoria (`0x008B94B0` → `0x00876240`) y hoja comparadora
  (`0x008E2A70`).
- **RNG**: `0x00AB047B` es `rand()` del CRT con estado por hilo (`__acrt_getptd`, `ptd+0x14`,
  15 bits), distinto del LCG con estado en `this+0x40` que usa `0x009B7910`.
- **Modelo de datos tocado**: vector de provincias del país (`+0x9D8`/`+0x9DC`), matriz de
  relaciones (`+0xBE8`), lista con head/tail/contador (`+0x7B4`/`+0x7B8`/`+0x7BC`), y el gestor de
  países como singleton de 1060 bytes en `0x012587E4` creado por `FUN_0055cdc0`.
- **No** hay contrato ni reverify para el bloque, y quedan seis preguntas abiertas anotadas en el
  documento (contenido de la lista `+0x7B4`, campo `province+0x188`, tipo de `0x125870C`, rango
  real de dos funciones, semántica de `0x911760` y del campo `+0xE64`).

Método que resultó imprescindible en este bloque: los conteos salen de **Capstone** (Rizin se
desincroniza en `FUN_00876240`, `0x0081E5B0` y `0x006874C0`), y los campos se identifican por el
**constructor del tipo**, no por el escaneo de offsets, que mezcla tipos distintos.
Contratos operativos en curso: [RNG](contracts/RNG.md) y
[selección y recorrido de POPs](contracts/POP-SCHEDULE.md).

Frontera actual de contenedores: [crecimiento de POP](contracts/POP-GROWTH.md).
La expansión tiene evidencia nativa de copia, destrucción y reservas exitosas,
incluidos ocho buffers internos poblados, copias profundas y snapshots previos a
liberar. La copia con catálogos poblados y reconstrucción de prefijos ya tiene
evidencia nativa. El constructor con tipo y su destructor con catálogos poblados
y cuatro modos de caché también tienen ciclos nativos completos. Continuar con
la combinación de elección del consumidor y cambio interno del factory,
otras claves del registro de movimientos,
las ramas alternativas del factory
`0x004B8D30`, y estudiar los grafos de referencias reales. Los llamadores y tipos respaldan la interpretación de
contenedores intermedios; 324 llamadas completas al tercer wrapper y fragmentos
separados de contexto/limpieza están contrastados. El factory y unlink tienen
1.053 ciclos con tipos/virtuales originales, listas de hasta dos nodos anteriores
y contador dedicado: 405 con catálogos vacíos y 648 poblados, con buffers del
temporal y de la copia contrastados hasta su liberación. El registro controlado
y los handles tienen ya 108 copias y 108 expansiones: esta expansión retira la clave
del elemento antiguo sin registrarla en la copia. No atribuir a ese vector la
semántica de almacenamiento global sin evidencia de sus llamadores. La copia completa CPop con
recurso fuente tiene 180 secuencias nativas, más 216 combinadas con distribuciones
y catálogos poblados: asigna sólo el primer pool; el segundo y los campos restantes
conservan la inicialización del destino.
El método de copia aislado de CGoodsPool tiene pruebas de resize, índice cero y
reserva nativa. Su
construcción y liberación tienen ya 192 ciclos nativos con dos pools `CGoodsPool`
vinculados por RTTI. No usar el
resultado de contenedores temporales como prueba de
que el almacén global de POP tenga el mismo contrato o sea seguro en paralelo.

El consumidor tiene ya 1.080 ejecuciones nativas completas por la ruta de nodo
nuevo, árboles existentes y misma clave de movimiento; incluye recorrido final
de tres buckets. Ver [dominio y fronteras](contracts/POP-CONSUMER.md).

La fusión con un destino compatible existente tiene 1.152 consumidores nativos
completos y 3.780 fixtures aislados del helper: media ponderada modular, saldo
y eventos contrastados. Ver [POP-MERGE](contracts/POP-MERGE.md).

La búsqueda entre múltiples candidatos tiene 305 consumidores completos emulados
y 447 prefijos sin coincidencia: prioridad de pasadas y orden de lista contrastados.
La elección posterior en `0x004BAA33` tiene 1.536 consumidores nativos completos: último
elegible del catálogo y factory original hasta retiro. Continuar con el selector
interno dentro del consumidor cuando cambia el tipo, o los árboles de movimientos.
Ver [POP-SELECTION](contracts/POP-SELECTION.md).

El selector interno `0x004B8C80` tiene 2.178 entradas nativas completas con
ambas ramas y orden exhaustivo de filas hasta longitud cuatro. Devuelve el
primero entre solicitado/alternativo que aparece, o solicitado si ninguno.
Ver [FACTORY-INTERNAL-SELECTOR](contracts/FACTORY-INTERNAL-SELECTOR.md).

El factory directo integra ya 960 ciclos del selector interno, con 216 cambios
de tipo/bucket y retiro completo. Quedan pendientes la combinación con la elección
previa del consumidor, otros llamadores y contextos más amplios.
