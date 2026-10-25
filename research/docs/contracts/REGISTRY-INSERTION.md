# Alta en el registro y ciclo de vida de un POP registrado

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferida base `0x00400000`. El banco PE32 usa base real `0x30000000`, delta
`0x2FC00000`; todas las VA siguientes son preferidas.

## Inserción operativa: VA 0x009C1590

**confirmed para 80 casos nativos:** recibe el objeto en EAX y retorna con `RET`.
Guarda los dos campos de clave `objeto+8` y `objeto+0xC`. Si `objeto+0x10` no es cero,
llama a la [baja](OBJECT-REGISTRY.md), y después restaura la clave guardada.

Selecciona VA `0x01258A98` para tipo sin signo menor o igual que `0x1268`, y
`0x01258A94` para valores superiores. Si la tabla seleccionada es nula, devuelve AL cero.
La presencia de la otra tabla no es requisito de inserción, aunque sí afecta a la baja
previa. Si la tabla existe y la reserva tiene éxito:

1. Calcula el bucket con el mismo hash truncado a 32 bits de la búsqueda.
2. Solicita ocho bytes mediante `0x00AAE9AF`, que alcanza `0x00AB049C` y HeapAlloc.
3. Escribe el puntero al objeto y la cabeza anterior en el enlace nuevo.
4. Cambia la cabeza al enlace nuevo, aumenta `tabla+0` y devuelve AL uno.

El helper no pone a uno `objeto+0x10`; sus 32 bytes de fixture quedan idénticos al
retornar, incluida la clave restaurada tras la baja. No comprueba por sí mismo la
ausencia de claves duplicadas antes de insertar. En las combinaciones con byte activo
cero se confirma la inserción al principio delante de una clave ya existente.
Esto describe la primitiva; no afirma que el API exterior permita esos duplicados.

Se cruzan cinco tipos (`0`, `0x1268`, `0x1269`, `0x80000000`, `0xFFFFFFFF`), byte activo
cero/uno, las cuatro combinaciones de tablas presentes y clave previa presente/ausente.
Hay 40 reservas originales exitosas y cinco liberaciones previas de enlaces. La tabla
opuesta permanece intacta. El modelo verifica cabezas, enlaces, contador y bytes de
todos los objetos anteriores. La limpieza del harness libera los enlaces nuevos al
terminar cada caso y se contabiliza aparte de las liberaciones del código original.

## Capa exterior y circuito completo

**confirmed para cinco ciclos nativos:** `0x009C1390` recibe objeto en ECX y una clave
de dos dwords por argumento de pila; termina con `RET 4`. Para cada uno de los cinco
tipos anteriores e id 17, con tablas vacías presentes y byte activo inicial cero:

1. Su búsqueda de clave previa no encuentra nada.
2. Copia la clave explícita al objeto y llama a `0x009C1590`.
3. La ruta original reserva el enlace, lo inserta y la capa exterior escribe `+0x10=1`.
4. La búsqueda original `0x009C1D40` devuelve ese mismo POP.
5. La eliminación de lista `0x004BE8D0` llama al destructor real de POP.
6. La baja `0x009C1650` retira el enlace del registro y lo libera; después transforma
   los campos del identificador. El destructor retorna y la lista libera el nodo POP.
7. La búsqueda de la clave inicial devuelve cero sobre la tabla vacía, sin acceder a
   memoria liberada. La lista también queda vacía y su contador llega a cero.

Se ejecutan los cuerpos originales y las rutas exitosas de los helpers CRT, con
relocaciones del cargador. No hay stubs de asignación: el callback de HeapAlloc reenvía
al heap real y registra handle, flags cero, tamaño ocho y resultado. La excepción-chain
real FS:0 se conserva después del alta y después de destruir el POP.

Justo antes de liberar el enlace se compara el POP completo de 648 bytes y se confirma
que el contador del registro aún vale uno. Antes de liberar el POP, el registro ya está
vacío y los campos han pasado de `(tipo,17)` a `(17,0xFFFE)`, conservando `+0x10=1`.
Se compara otra vez el objeto completo. No se lee el objeto después de liberarlo.

Las tablas se construyen como fixtures; este banco no llama al constructor del mundo.
El POP tiene cadenas internas y contenedores vacíos. La referencia externa `+0x220`
tiene clave cero; no resuelve otro objeto durante la limpieza. No se combinan todavía
estos cinco ciclos con los buffers y regimientos de las otras 134 pruebas.

## Límites y ramas pendientes

La lectura estática de la capa exterior muestra una ruta de clave duplicada y otra
que genera identificadores cuando la entrada coincide con el par global de referencia.
La primera sigue pendiente. La generación se validó después con 36 ciclos y tres
pruebas del bloqueo, documentados en [identificadores automáticos](AUTOMATIC-IDS.md).
Las cinco claves explícitas de esta sección no recorren esa rama. Tampoco se prueba
la capa exterior con tabla ausente.

El cuerpo de inserción contiene una rama para resultado de reserva nulo que escribe
cero en la cabeza y aumenta el contador. **No se atribuye eso al comportamiento real
ante falta de memoria:** el helper CRT tiene rutas adicionales de reintento/excepción
que todavía no se han contrastado. No se fuerza un fallo de HeapAlloc ni se asume que
esa rama sea alcanzable con el allocator original.

## Reproducción y recibos

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_object_registry.py
python research/scripts/build_native_pop_probe.py
python research/scripts/run_native_pop_probe.py
```

La fase de inserción añadió 18 comprobaciones estáticas; la ampliación automática
llevó después el contrato del registro a 65 checks. No sustituyen la ejecución nativa.
El recibo combinado actual `research/evidence/generated/native-pop/execution.json`
suma **452 casos**, **81 reservas originales**, **790 liberaciones originales** y
**350 comprobaciones previas a liberar**. Los 274 casos aislados del registro
contabilizan 76 liberaciones; los cinco
ciclos integrados añaden diez liberaciones y cinco reservas. Las fuentes propias y los
hashes quedan en los recibos de cada intento. La línea base anterior está archivada en
`native-pop/baseline-328-cases/`.

Alcance: proceso PE32 aislado bajo Wine 11.19, copia privada del binario, objetos y tablas
sintéticos. No valida una partida, inicialización global, errores de heap, excepciones,
reentrada o mutaciones concurrentes del registro. La contención del bloqueo aislado
tiene su propio dominio en el contrato de identificadores automáticos.
