# Registro de objetos y resolución de handles

Estado: **confirmed en instrucciones y casos acotados**. Perfil SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida VA `0x00400000`; RVA = VA − base.

| Entrada VA | RVA | Entradas observadas | Resultado observado |
| --- | --- | --- | --- |
| `0x009C1D40` | `0x005C1D40` | EAX = clave de dos dwords, ECX = tabla | Puntero al primer objeto coincidente de la cadena, o cero |
| `0x00967F50` | `0x00567F50` | ESI = handle | Busca el objeto, escribe el resultado en `handle+0`, devuelve el puntero |
| `0x00967F10` | `0x00567F10` | EAX = handle | Busca el objeto y devuelve el puntero sin escribir el handle |
| `0x009C1CB0` | `0x005C1CB0` | EAX = clave, argumento de pila = tabla | Retira el primer enlace coincidente, lo libera y reduce `tabla+0`; AL indica coincidencia |
| `0x009C1650` | `0x005C1650` | ESI = objeto | Bajo condiciones declaradas, intenta retirar su clave y transforma sus campos; AL no indica necesariamente coincidencia |
| `0x009C1590` | `0x005C1590` | EAX = objeto | Inserta un enlace al principio del bucket seleccionado; puede llamar antes a la baja |
| `0x009C1390` | `0x005C1390` | ECX = objeto, argumento de pila = clave | Capa exterior: comprueba clave, prepara identificador, llama a inserción y escribe `+0x10=1`; dominio nativo acotado |

Los nombres «registro», «tipo», «id» y «handle» son **inferred** por su uso general y
la referencia `Engine/Event_System.md` de la revisión fijada en `docs/HALLAZGOS.md`.
Los campos y operaciones siguientes se contrastan contra las instrucciones originales.

## Layout mínimo operativo

| Estructura | Offset | Campo leído |
| --- | --- | --- |
| Tabla | `+0x00` | La búsqueda no lo lee. Inserción lo incrementa y borrado lo reduce: contador operativo de entradas; creación de tablas aún pendiente |
| Tabla | `+0x04` | Número de buckets, divisor sin signo, debe ser positivo en el dominio probado |
| Tabla | `+0x08` | Puntero al array de cabezas de cadena, entradas de 4 bytes |
| Nodo de cadena | `+0x00` | Puntero al objeto |
| Nodo de cadena | `+0x04` | Puntero al siguiente nodo, o cero |
| Objeto | `+0x08`, `+0x0C` | Dos dwords comparados con la clave completa |
| Handle | `+0x00` | Puntero guardado, sobrescrito por la variante de actualización |
| Handle | `+0x04`, `+0x08` | Los dos dwords de la clave |

La selección de bucket es `(((tipo << 16) + id) & 0xFFFFFFFF) % bucket_count`.
La suma y el desplazamiento se truncan a 32 bits antes de la división sin signo.
Dentro de la cadena se comparan los dos campos completos de 32 bits, no sólo el hash.
Si hay claves duplicadas, devuelve el primer nodo coincidente en el orden de esa cadena.
La creación de tablas y el orden inicial en una partida siguen pendientes. La
inserción al principio del bucket y la eliminación por clave quedaron contrastadas
después en el banco nativo descrito más abajo y en el [contrato de alta](REGISTRY-INSERTION.md).

Las dos variantes de resolución seleccionan VA `0x01258A98` cuando el tipo, interpretado
sin signo, es menor o igual que `0x1268`; para valores superiores seleccionan
VA `0x01258A94`. Si la tabla seleccionada es nula, el resultado es cero.

La variante `0x00967F50` no se limita a reutilizar el puntero ya almacenado: incluso con
un valor previo distinto de cero vuelve a resolver y escribe el resultado, también
cuando no se encuentra el objeto. La variante `0x00967F10` deja ese valor anterior
intacto. Confundir ambas operaciones puede conservar punteros obsoletos.

## Evidencia reproducible

`scripts/verify_object_registry.py`, después de cargar `research/env.sh`:

- 20 tablas sintéticas, combinando 1, 3, 7 y 257 buckets con 0, 1, 5, 31 y 64 objetos.
- 684 búsquedas: aciertos, fallos, claves duplicadas, colisiones y patrones con bit
  superior activo. Se compara el resultado contra un modelo independiente de la lista
  de claves y se comprueba que la tabla permanece idéntica.
- 32 fixtures ejecutados en ambas variantes de handle: tipos 0, `0x1268`, `0x1269`
  y `0xFFFFFFFF`; tabla presente/ausente; clave encontrada/ausente; puntero anterior
  cero/no cero. Se verifica el retorno y el contenido de los doce bytes del handle.
- Se ejecutan las entradas completas originales, incluyendo la llamada real a la búsqueda.
- Reverify contrasta 68 instrucciones: doce de búsqueda/resolución, dieciséis
  del borrado/baja, dieciocho del alta, diecinueve de generación automática/bloqueo
  y tres de identidad en copia de CPop. Recibos en
  `evidence/generated/object-registry/{claims.json,reverify.json,emulation.json}`.

Se preservan EBX, ESI, EDI y EBP y el retorno retira cuatro bytes de la pila en los
casos probados. Las convenciones C sugeridas por el decompilador no sustituyen este
contrato de registros.

No se cubren divisor cero, cadenas cíclicas, punteros inválidos, mutaciones concurrentes,
tablas pobladas por una partida real ni la propiedad o duración de vida del objeto.
El coste de recorrer la cadena depende de su longitud; no se afirma una cota constante
en el peor caso ni se presume que se pueda acceder a estas tablas desde varios hilos.

## Borrado por clave: ejecución nativa

**confirmed para 114 casos:** se ejecuta completa la entrada `0x009C1CB0` en una copia
privada del PE con relocaciones de carga. El banco combina 1, 3 y 7 buckets con 0, 1,
5 y 16 objetos, claves presentes y ausentes, duplicados y patrones con bit superior.
Cada caso reconstruye la tabla; no encadena las consultas sobre una misma tabla mutada.

La rutina compara la clave completa, retira **el primer enlace** coincidente del
bucket y libera sólo ese enlace de ocho bytes mediante HeapFree real. Conserva
intactos todos los objetos referenciados, incluido el que pertenecía al enlace retirado.
Los enlaces restantes y las cabezas se comparan con un modelo por orden de filas.
En los 66 aciertos se comprueba la corrección de enlaces antes de liberar y que el
contador se reduce después. Los 48 fallos devuelven AL cero y conservan la tabla.

Esto confirma el uso de `tabla+0` como contador operativo en esta ruta; no demuestra
por sí solo la inicialización ni todas las invariantes del registro real.

## Baja de objeto y transformación del identificador

**confirmed para 80 casos:** la entrada `0x009C1650` comprueba primero que **ambas**
tablas globales sean no nulas y después que el byte `objeto+0x10` no sea cero. Si falla
alguna condición, devuelve AL cero y deja objeto y tablas intactos. Esto difiere de los
resolvers, que sólo necesitan la tabla seleccionada.

Cuando las condiciones se cumplen, selecciona tabla con la misma comparación sin
signo del tipo frente a `0x1268`, llama a `0x009C1CB0` y después escribe:

```text
objeto+0x08 = valor anterior de objeto+0x0C
objeto+0x0C = 0x0000FFFE
objeto+0x10 = valor anterior, sin borrar ese byte
AL = 1
```

La transformación sucede **aunque no encuentre la clave**. Por tanto, el retorno AL
uno de esta entrada no demuestra que se haya eliminado un enlace. El banco contiene
cinco contraejemplos explícitos: tablas presentes, byte activo y clave ausente.
No se interpreta el nuevo par como un identificador válido ni se supone que el byte
activo se borre automáticamente.

Se cruzan tipos `0`, `0x1268`, `0x1269`, `0x80000000` y `0xFFFFFFFF`, byte activo cero/uno,
las cuatro combinaciones de tablas presentes/ausentes y clave presente/ausente. La tabla
opuesta permanece intacta. La clave presente tiene duplicados: se comprueba que se
retira el primer enlace por clave, sin exigir identidad entre su objeto y el argumento
de baja. Son fixtures deliberados; la validez de duplicados en una partida no se afirma.

## Recibos y dominio de la fase nativa

Los 194 casos nuevos liberan 71 enlaces reales y comprueban sus ocho bytes justo antes
de liberar. Fuente: `research/harnesses/native_registry_cases.h`, incluida en el banco
PE32. Procedimiento, base real, relocaciones y limitaciones de Wine:
[banco nativo](NATIVE-POP.md). Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_object_registry.py
python research/scripts/build_native_pop_probe.py
python research/scripts/run_native_pop_probe.py
```

La fase posterior añadió [inserción y ciclo de vida registrado](REGISTRY-INSERTION.md).
El recibo combinado actual contiene 452 casos: 134 de POP/regimientos, 274 aislados del
registro, 41 ciclos de POP registrado y tres pruebas del bloqueo; 81 reservas originales,
790 liberaciones reales y 350 comprobaciones antes de liberar. La ampliación se detalla
en [identificadores automáticos](AUTOMATIC-IDS.md). Los casos del registro
usan cadenas acíclicas, divisores positivos y punteros válidos. La baja aislada no es
una partida real. La integración nativa ahora cubre 41 POPs sintéticos registrados,
con contenedores propios vacíos; quedan abiertos la población real, los fallos de heap,
la corrupción, la reentrada y la concurrencia.
