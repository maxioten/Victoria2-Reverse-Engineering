# Identificadores automáticos y bloqueo local

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida `0x00400000`; base real del banco nativo `0x30000000`, delta
`0x2FC00000`. Las direcciones de código siguientes son VA preferidas.

## Selección y generación

**confirmed, instrucciones y 36 ciclos nativos:** la capa exterior `0x009C1390`
compara la clave de entrada con los dwords globales de `0x01268FEC` y `0x01268FF0`.
En la ruta sin coincidencia previa, si ambos campos son iguales al par global, genera
un identificador. El banco usa el par inicial cero/cero de la imagen privada, sin
ejecutar inicializadores del motor; no afirma que siga siendo cero en una partida.

| Dato | VA preferida | VA real del banco | Tamaño |
| --- | --- | --- | --- |
| Desplazamiento del tipo | `0x01258A90` | `0x30E58A90` | 16 bits, lectura sin signo |
| Contador de identificador | `0x01258A9C` | `0x30E58A9C` | 32 bits |
| Byte de bloqueo | `0x0131CA68` | `0x30F1CA68` | 8 bits |

La secuencia observada es:

```text
adquirir bloqueo de un byte
id = (contador + 1) mod 2^32
contador = id
tipo = zero_extend_16(desplazamiento) + 0x1268
liberar bloqueo escribiendo cero
objeto+8 = tipo
objeto+0xC = id
insertar enlace en el registro
objeto+0x10 = 1
```

La suma del tipo ocurre en 32 bits: no se vuelve a truncar a 16 bits. Un desplazamiento
`0xFFFF` produce tipo `0x11267` (70.247). El contador `0xFFFFFFFF` produce id cero;
no se omite ese valor en la ruta probada. No se demuestra con ello unicidad tras el
wrap ni comportamiento con una clave generada que ya exista en una tabla poblada.

## Matriz nativa y duración de vida

El banco cruza seis valores de 16 bits (`0`, `1`, `0x1268`, `0x7FFF`, `0x8000`,
`0xFFFF`) con seis semillas (`0`, `17`, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFE`,
`0xFFFFFFFF`). Para cada combinación ejecuta el alta original, comprueba contador y
tipo, busca el objeto y lo destruye mediante la lista de POPs. La búsqueda final de
su clave generada devuelve cero. Los dos campos de la clave de entrada permanecen
a cero y se verifica la restauración de FS:0.

Hay una reserva real de enlace y dos liberaciones originales por ciclo. Los 36 ciclos
añaden 36 reservas, 72 liberaciones y 72 comparaciones antes de liberar al banco
anterior. Los POPs poseen cadenas internas y contenedores propios vacíos; no se combina
todavía este dominio con las referencias a regimientos ni con buffers externos.

Los resultados de tipo e id se contrastan también en Python contra enteros sin límite
y máscara explícita de 32 bits. El word vecino en `0x01258A92` permanece intacto.

## Adquisición del bloqueo: VA 0x009C12D0

**confirmed en tres pruebas nativas aisladas:** recibe en EAX la dirección de un byte.
Hace `LOCK CMPXCHG` comparando con cero y escribiendo uno. Cuando adquiere, deja el
byte en uno y devuelve EAX cero. El propio helper no libera el bloqueo.

La lectura estática muestra espera con `PAUSE`, un valor de espera que se duplica hasta
superar 16 y llamadas por la IAT `0x00C8A188`, identificada como `SwitchToThread`.
El banco instala un callback que registra y reenvía al SwitchToThread real.

| Byte inicial | Comprobación |
| --- | --- |
| `0` | Adquisición directa, retorno cero, byte final uno, sin cesiones |
| `1` | Worker alcanza la cesión y sigue esperando mientras el propietario conserva el byte; adquiere tras liberarlo |
| `0x7F` | Mismo circuito: cualquier valor no cero probado impide la adquisición inicial |

En los dos casos retenidos, un evento indica que el worker llegó a la cesión. El hilo
principal confirma que aún no terminó, verifica el byte y lo libera mediante una
escritura atómica del harness. Después espera el retorno del worker con un límite de
cinco segundos. Se comprueba byte uno, retorno cero y contador de identificadores
intacto. Sólo se ejecuta concurrentemente el helper aislado; no se insertan objetos
en el registro desde varios hilos. El número exacto de cesiones depende del scheduler
y no es un resultado determinista exigido por el recibo.

## Alcance de la sección crítica

**confirmed, orden local de instrucciones:** en `0x009C1550` se libera el byte, antes
de escribir la clave al objeto y antes del CALL a la inserción en `0x009C156A`.
El bloqueo observado protege la generación del par, no toda la mutación de la tabla.
No se ha demostrado si los llamadores añaden otra sincronización. Su presencia no
certifica seguridad del alta concurrente, justicia del bloqueo ni progreso bajo
contención ilimitada.

## Reproducción y límites

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_object_registry.py
python research/scripts/build_native_pop_probe.py
python research/scripts/run_native_pop_probe.py
```

Reverify contrasta 19 instrucciones nuevas: 65 checks para el registro en total.
Las pruebas nativas forman parte de `research/harnesses/native_registry_cases.h`.
Recibo: `research/evidence/generated/native-pop/execution.json`. El total combinado
es **452 casos**, **81 reservas originales**, **790 liberaciones originales** y
**350 comparaciones previas a liberar**. Incluye 41 ciclos registrados (cinco explícitos
y 36 automáticos) y tres pruebas del bloqueo. La línea base anterior se conserva en
`native-pop/baseline-413-cases/`.

Son fixtures bajo Wine 11.19 con copia privada reubicada del PE; no se valida una partida,
inicialización global, error de clave duplicada, fallo de heap, excepciones, reentrada
o mutación paralela del registro. Las escrituras de fixture, anchos y destinos se
declaran en el manifiesto de construcción.
