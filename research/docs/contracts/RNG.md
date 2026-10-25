# RNG: contrato operativo reconstruido

Estado: **confirmed para las instrucciones y casos declarados**, sin prueba universal
de equivalencia de implementación. No es fuente original ni un reemplazo instalado.
Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA con base preferida `0x00400000`; los RVA se indican por separado.

## Entradas y datos

| Entrada VA | RVA | Entrada observada | Datos y efectos observados |
| --- | --- | --- | --- |
| `0x009B7610` | `0x005B7610` | EAX = puntero al estado | Lee 624 palabras, actualiza índice a `+0x9C0`, devuelve palabra transformada en EAX; si índice inicial cero llama a regeneración |
| `0x009B7670` | `0x005B7670` | EAX = semilla, ECX = destino | Escribe 624 palabras; deja intacta la palabra del índice a `+0x9C0` en los casos probados |
| `0x009B7700` | `0x005B7700` | EDI = puntero al estado | Regenera en el mismo buffer 624 palabras, sin actualizar el índice en los casos probados |

No se asigna una convención C estándar a estas entradas: usan registros específicos.
En las invocaciones emuladas preservan EBX, ESI, EDI y EBP, y retornan con ESP
incrementado en cuatro bytes (dirección de retorno retirada). Los flags y registros
volátiles no tienen aquí contrato de preservación.

El layout probado ocupa 2.500 bytes: 624 palabras de 32 bits y un índice de 32 bits.
El dominio de las extracciones probadas usa índices válidos de 0 a 623, memoria accesible
y ausencia de concurrencia. No se han validado punteros ni índices inválidos.

## Modelo

La implementación operativa está en `scripts/rng_model.py`. Usa patrones de 32 bits,
conversión explícita a entero con signo para los desplazamientos aritméticos y máscara
de 32 bits tras las operaciones relevantes.

- Inicialización: `s[0]=seed`; las palabras siguientes usan la multiplicación por
  `0x6C078965`, XOR con el desplazamiento aritmético de 30 bits y suma del índice.
- Regeneración: combina el bit superior de `s[i]` con los 31 inferiores de
  `s[(i+1)%624]`; mezcla con `s[(i+397)%624]` y desplazamiento aritmético de un bit.
  El XOR con `0x9908B0DF` depende de que el resto **con signo** por 2 sea +1.
  Las actualizaciones ocurren en el mismo buffer y su orden forma parte del modelo.
- Extracción: usa desplazamientos aritméticos de 11 y 18 bits, junto con las
  máscaras `0xFF3A58AD` y `0xFFFFDF8C` antes de desplazar 7 y 15 bits.
- El índice se incrementa módulo 624; índice cero provoca regeneración antes de leer.

Estos detalles impiden sustituirlo por una implementación genérica de MT19937 sin
demostrar equivalencia. Contraejemplo aislado, índice inicial 1 y palabra `0x80000000`:
el original devuelve `0x180FF9FC`; el candidato con desplazamientos lógicos devuelve
`0x88102204`.

Semilla cero: se prueba la creación diferida del buffer global VA `0x00F08778` desde
un primer valor forzado a `0xFFFFFFFF` y su reutilización en una segunda llamada.
Se observan 624 escrituras al buffer en la primera y ninguna en la segunda; ambas
copian las mismas 624 palabras al destino. No se cambia el índice del destino.
Esto exige investigar por separado qué llamadores inicializan ese índice.

## Pruebas y alcance

`scripts/verify_rng.py` ejecuta las tres entradas originales en Unicorn:

- Siete inicializaciones: cero dos veces, 1, 5489, INT32_MAX, `0x80000000` y `0xFFFFFFFF`.
- Seis vectores de 624 palabras: cero, todos los bits a uno, bit superior, alternado,
  ascendente y datos pseudoaleatorios deterministas.
- Una regeneración completa por vector y 1.250 extracciones por vector, cruzando
  dos vueltas de índice; se compara la palabra devuelta y las 625 palabras del estado
  después de cada extracción. Son 7.500 extracciones sin discrepancias.
- El candidato que sustituye SAR por desplazamiento lógico debe fallar.

Reverify verifica ocho instrucciones estructurales. La equivalencia de comportamiento
de los casos anteriores se comprueba por el harness de Unicorn, no por un veredicto
semántico global de reverify. El PE emulado se protege contra escrituras salvo los
datos autorizados. Las pruebas de inicialización vigilan cada destino escrito.

Recibos: `evidence/generated/rng/{claims.json,reverify.json,emulation.json}`.
Reproducción desde la raíz: `source research/env.sh`, después
`python research/scripts/verify_rng.py`.

## Conexión con el tick diario

`scripts/verify_daily_rng.py` ejecuta el fragmento original VA `0x00685B69` a
`0x00685C09`, incluyendo las llamadas reales a `0x009B7700`. Verifica la inicialización
de ESI a cero, la salida de 1.000 palabras en `[EBP-0x108C]`, el incremento del contador
VA `0x00F20C14` por 1.000 y la actualización del estado global VA `0x00F0ECF0` e índice
VA `0x00F0F6B0`.

Nueve combinaciones: semillas 0, 5489 y `0x80000000`, cada una con índice 0, 1 o 623.
Se comparan 9.000 salidas y los estados finales, incluyendo los puntos de regeneración.
El singleton en `0x00F20C18` está ya presente; se excluye expresamente su asignación.
Reverify comprueba ocho instrucciones del fragmento, sin inferir tipos del singleton.
Recibos: `evidence/generated/daily-rng/{claims.json,reverify.json,emulation.json}`.

No se ejecutan las otras fases del tick, APIs del sistema ni una partida real. Tampoco
se demuestra seguridad entre hilos, independencia del orden de las extracciones ni
equivalencia en todos los estados posibles.

## Reconstrucción global desde semilla y contador

**confirmed en 21 casos:** la entrada VA `0x009B7C80` (RVA `0x005B7C80`), con
singleton existente y lista auxiliar vacía, produce el estado obtenido al inicializar
con la semilla de VA `0x00F20C1C`, poner el índice en cero y avanzar el contador
guardado en VA `0x00F20C14`. No calcula la transformación final de cada extracción
descartada: sólo regenera cuando corresponde y avanza el índice.

Se ejecuta la entrada original completa con sus callees. Los tres campos auxiliares
VA `0x0131C9F4`, `0x0131C9F8` y `0x0131C9FC` terminan a cero en la ruta con cabeza
de lista nula. La semilla y el contador se conservan. Se preservan EBX, ESI, EDI y EBP.

Casos: semillas 0, 5489 y `0x80000000`, con contadores 0, 1, 623, 624, 625, 1000 y
1248. Se compara el estado completo y los puntos de regeneración. La rutina de
inicialización no pone a cero el índice; esta entrada sí lo hace en VA `0x009B7CC3`.

**inferred:** el nombre operativo «reconstruir desde semilla y contador» describe
estos efectos. Su uso al cargar una partida o sincronizar red aún no se ha trazado.
Se excluyen asignación del singleton, eliminación de listas no vacías, contadores
inválidos y ejecución concurrente.

Reproducción: `python research/scripts/verify_rng_restore.py` después de cargar el
entorno. Ocho instrucciones verificadas por reverify y recibos en
`evidence/generated/rng-restore/{claims.json,reverify.json,emulation.json}`.

Las otras tres entradas tienen nombres operativos `RE_RngNext_Signed32`,
`RE_RngInitialize_Signed32` y `RE_RngRegenerate_Signed32` y comentarios de alcance
en el proyecto Ghidra, sin instalar tipos ni convenciones C supuestos. La auditoría
queda en `evidence/generated/analysis-annotations/rng-annotations.txt`.
