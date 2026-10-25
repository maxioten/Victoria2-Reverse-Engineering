# Construcción, copia y append de POP

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Direcciones VA para base preferida `0x00400000`; RVA = VA − base.

**confirmed para 594 fixtures completos de Unicorn**, con los cuerpos y callees
originales, sin retornos o asignaciones de heap simulados:

| Entrada VA | Convención observada | Casos |
| --- | --- | --- |
| `0x00954F40` | EDX = tipo, argumento = destino; RET 4, EAX = destino | 72 constructor |
| `0x00955450` | argumentos = destino, origen; RET 8, EAX = destino | 72 copia |
| `0x004BEB50` | EDI = descriptor, ECX = origen; RET, EAX = nuevo elemento | 126 append |
| `0x00534810`, `0x00534930` | tres argumentos; RET 12; EAX sin contrato | 324 wrappers completos |

Se comparan los 65.536 bytes de los fixtures, registros no volátiles, balance del
stack, restauración de FS:0 sintético y dos escrituras globales de caché declaradas.
Los destinos comienzan con patrones cero, `0x5A` o `0xFF`; las entradas escalares
de copia se generan con semilla fija. Así se distinguen los campos copiados,
reiniciados y los bytes conservados. El oráculo de campos es explícito y no se
genera a partir de los operandos que ejecuta Unicorn.

## Dominio y efectos de construcción

Los dos catálogos globales en `0x01258A3C/0x01258A48` contienen rangos vacíos.
Los singletons de `0x012587EC/0x0125880C`, las cachés y el singleton de
`0x0131BB34` ya existen. El byte de tipo `+0x39C` es cero. Estas condiciones
excluyen las reservas de inicialización perezosa y del recurso opcional `+0x1D4`.
No se atribuyen nombres de gameplay a los singletons por su mera dirección.

El constructor instala vtable `0x00E36428`, identificador `0x18D`, copia las dos
palabras globales de clave, deja inactivo el byte `+0x10` y construye cuatro
distribuciones con vtable `0x00DFD2CC`. Cada distribución contiene dos vectores
vacíos, con descriptores begin/end/capacity nulos. Los cuerpos reales de
`0x004BE4F0` se ejecutan cuatro veces. Conserva agujeros del payload: no equivale
a memset de los 632 bytes.

El constructor escribe `0x8000` en `+0x130/+0x138`. También convierte la constante
binary64 `3277.300048828125`, en VA `0x00E457F0`, mediante el cuerpo original
`0x00B31C36` y escribe `3277` en el campo de 64 bits `+0x128`. La prueba utiliza
CW `0x037F`; no establece equivalencia para otros controles x87 ni nombres
semánticos para ese campo.

## Copia: selección de campos y reinicio

La rutina `0x00955450` no es una copia literal del payload. Copia `+0x4C`, dwords
`+0x58..+0x70`, `+0x118..+0x144`, `+0x150/+0x154`, `+0x180/+0x184`,
`+0x1C8/+0x1CC`, `+0x268`, `+0x270/+0x274`. Reconstruye cuatro distribuciones
mediante `0x00955980`: copia su palabra `+4`, instala la vtable y copia sus dos
vectores. En esta fase los ocho vectores de origen están vacíos.

Reinicia, entre otros campos, el vector de referencias `+0x3C`, los nueve
contadores `+0x158..+0x178` y el recurso opcional `+0x1D4`. Las claves se toman
de los globals y no de la identidad del origen. Los strings declarados se
construyen vacíos; no se copia la cadena del origen. El modelo registra la lista
completa de escrituras y comprueba también los bytes que se conservan.

La copia escribe siempre `0x00F20C04/0x00F20C08` desde `0x0131BB34/0x012586DC`.
Es un efecto global observado incluso con un destino ajeno al vector. No se
deduce seguridad paralela de que los demás campos pertenezcan al destino.

## Append y alias dentro del vector

`0x004BEB50` distingue un origen en `[begin,end)` de un origen externo. Para
un origen interno calcula el índice y vuelve a obtener el puntero desde begin.
En ambos caminos llama al constructor de copia sobre end y avanza end en `0x278`.

Los casos directos cruzan tamaños anteriores 0, 1, 2, 5 y 8, uno o tres slots
libres, un origen externo o cada posición válida ya existente y tres patrones de
destino. Comprueban todo el rango, incluidos elementos anteriores y capacidad
sin usar. La capacidad y begin no cambian en este dominio. No se generaliza a
punteros interiores desalineados ni origen igual al destino.

## Wrappers sin coincidencia

Las dos entradas de transferencia recorren contenedores de 0, 1 o 3 elementos sin
encontrar el slot o la tupla buscados. Ejecutan realmente constructor temporal,
append, destructor temporal `0x00955AE0`, búsqueda de registro sin tablas y núcleo
de transferencia `0x005345A0`. El destructor no libera buffers porque son nulos.
No se sustituye ningún callee por un stub.

Los 324 casos cruzan ambos wrappers, tres tamaños de origen, cantidad cero/uno/todo,
dos relaciones de región y tres patrones de memoria. Los flags de tipo `+0x40`
están a cero, los vectores de origen vacíos y hay capacidad libre. La cantidad
cero sigue construyendo y añadiendo un elemento: no es un camino sin escrituras.
Se contrasta la aritmética con el modelo de [transferencia](POP-TRANSFER.md).

Durante el desarrollo se retiró una aserción no sustentada que suponía EAX igual
al nuevo elemento al retornar de los wrappers. Las rutinas constructor/copia/append
sí lo devuelven en estas pruebas; los wrappers ejecutan después el núcleo y no
tienen ese contrato de retorno. No se usa ese registro como identificador fiable.

## Reproducción y pendientes

```bash
source research/env.sh
python research/scripts/verify_pop_append.py
python research/scripts/verify_grounding.py
```

Reverify comprueba 20 instrucciones adicionales; los recibos se guardan en
`evidence/generated/pop-append/{claims.json,reverify.json,emulation.json}`.
El gate vincula fuentes y recibos por SHA-256.

La expansión `0x004BEDE0`, reservas/fallos de heap, distribuciones o catálogos
poblados, recurso opcional, singletons todavía no construidos, excepciones,
concurrencia y estado de una partida real siguen pendientes. El hook rechaza
las entradas de reserva y expansión: los resultados no las validan.

La [fase posterior de expansión nativa](POP-GROWTH.md) ejecuta reservas exitosas y
destrucción/copia del rango anterior con distribuciones vacías. No amplía por sí
sola los límites de los 594 casos de esta fase ni valida fallos de heap.
