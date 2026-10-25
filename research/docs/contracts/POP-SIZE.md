# Cambio de tamaño y estadísticas relacionadas

Perfil SHA-256 `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferida base `0x00400000`; entrada `0x00955FD0`, RVA `0x00555FD0`.
Se ejecuta la entrada completa original, con EAX como valor solicitado y ESI como
objeto. Termina con `RET`; EBX, ESI, EDI, EBP y la pila quedan conservados en los casos
probados. «Tamaño», «asignado», «tipo» y «región» son nombres operativos; no se afirma
una declaración C++ original ni la unidad de todos los campos.

## Escrituras del objeto

**confirmed para 1.362 fixtures de Unicorn:**

```text
nuevo = clamp(signed32(EAX), 0, 2000000)
objeto+0x58 = nuevo
objeto+0x5C = antiguo(objeto+0x58), salvo que sea cero: entonces nuevo
```

Esto prueba el límite de esta entrada, no un máximo global que todos los escritores
del motor deban respetar.

El contexto `objeto+0x68` contiene un byte de selección en `+0x40`. Cuando vale cero,
la entrada escribe también `objeto+0x60=nuevo`. Si es distinto de cero, no asigna ese
campo directamente. Cuando el nuevo tamaño es menor, con signo, que el valor anterior
de `+0x60`, calcula la diferencia y llama a:

| Destino VA | Papel observado en el dominio del banco |
| --- | --- |
| `0x004C25B0` | Devuelve un singleton ya existente en VA `0x01258728` |
| `0x004EE550` | Busca una fila para el objeto y descuenta una cantidad de sus estadísticas |
| `0x004D1020` | Consulta una raíz de propietario; en estos fixtures está vacía y retorna |
| `0x004C8D10` | En la ruta con fila remanente positiva, busca el valor de un mapa ya poblado |

No se reemplazan estos cuerpos por stubs. La creación del singleton, la inserción
en el mapa, la eliminación de filas y una jerarquía de propietarios no vacía quedan
fuera del dominio comprobado.

## Filas y agregados existentes

Los 42 fixtures adicionales usan una fila de 16 bytes y un mapa de un nodo con
sentinela válido. Si hay reducción y queda una cantidad positiva, se comprueba:

- Disminución de `objeto+0x60`.
- Disminución de la cantidad de la fila, ubicada en su `+0x0C`.
- Disminución del valor de mapa, del agregado del contenedor `+0x48` y de su array
  indexado por el dword `contexto_tipo+0x28`.
- Conservación del resto de bytes de objeto, fila, mapa, contexto y regiones del banco.

El mapa contiene desde el inicio el elemento buscado: no se presupone que una búsqueda
con efecto de inserción sea pura. Cuando la fila está vacía o no existe, los helpers de
estos fixtures no reducen `objeto+0x60`, aunque el tamaño solicitado sea menor. Eso
describe entradas sintéticas; no demuestra que tal inconsistencia pueda aparecer en
una partida con todas sus invariantes satisfechas.

## Cobertura de entradas

La primera matriz tiene 1.320 casos: cinco tamaños anteriores, cuatro patrones del
campo `+0x60`, once solicitudes (incluidos negativos, `INT32_MIN`, `INT32_MAX` y valores
alrededor de dos millones), flags `0`, `1`, `0xFF` y dos índices de región. Mantiene
vacíos los vectores y la raíz de propietario.

Los otros 42 cruzan tres cantidades iniciales con siete solicitudes positivas y dos
índices de región. Incluyen reducción con remanente positivo, igualdad e incremento.
Se comparan los **65.536 bytes** del arena de fixtures después de cada llamada; un
guard restringe las escrituras a ese arena y al stack. Las entradas con patrones
incompatibles con un POP real se conservan como pruebas aritméticas acotadas, no como
estados observados del juego.

## Reproducción y límites

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_pop_size.py
```

Reverify contrasta 16 instrucciones. Recibos:
`evidence/generated/pop-size/{claims.json,reverify.json,emulation.json}`. La vista
parcial de Ghidra `PopSizeView108_Operational` nombra sólo los campos alcanzados;
no se aplica a memoria viva ni cambia firmas automáticamente.

No se ejecuta con estos casos la actualización completa del POP. Faltan borrados,
reservas, las jerarquías de propietario no vacías, registros de una partida,
excepciones y concurrencia. Las escrituras de agregados observadas se deben tener
en cuenta antes de considerar cualquier paralelización del llamador.
