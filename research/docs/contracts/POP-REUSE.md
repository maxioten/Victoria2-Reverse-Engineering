# Inicialización parcial y reutilización de slots de POP

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida `0x00400000`; RVA = VA − base. Este contrato amplía el
[núcleo de transferencia](POP-TRANSFER.md) a destinos vacíos y a los caminos de
reutilización de sus dos wrappers.

## Entradas ejecutadas y cobertura

**confirmed para 726 fixtures completos de Unicorn:**

| Entrada VA | Entradas observadas | Casos |
| --- | --- | --- |
| `0x00955A00` | ESI = destino, EDI = origen; RET sin argumentos | 24 directos de inicialización |
| `0x005345A0` | EAX = origen, cuatro argumentos del núcleo | 270 con destino inicialmente vacío |
| `0x00534810` | Tres argumentos: contenedor, origen, cantidad; RET 12 | 144 con slot de tamaño cero ya existente |
| `0x00534930` | Tres argumentos: contenedor, origen, cantidad; RET 12 | 288 con tupla coincidente ya existente |

Se ejecutan los cuerpos originales y los callees de copia, memmove, aritmética,
tamaño y región alcanzados. No se inyectan retornos ni resultados de stubs.
Se comparan los 65.536 bytes de la región de fixtures. Los registros no volátiles y
el stack se comprueban; los wrappers restauran el valor anterior sintético de FS:0.
No se prueba el desenrollado de excepciones.

## Qué hace la inicialización

La entrada `0x00955A00` es una **inicialización parcial**, no una copia completa ni un
borrado de todo el payload. En los casos declarados:

| Operación | Campos del destino |
| --- | --- |
| Copia dwords del origen | `+0x6C`, `+0x70`, `+0x78`, `+0xA0`, `+0x128`, `+0x12C` |
| Copia rangos de vectores | Descriptores `+0x7C`, `+0x8C`, `+0xA4`, `+0xB4` |
| Escribe dword cero | `+0x58`, `+0x5C`, `+0x118`, `+0x11C`, `+0x120`, `+0x124`, `+0x274`, `+0x1C8`, `+0x1CC`, `+0x134`, `+0x13C`, `+0x140`, `+0x144`, `+0x30`, `+0x34` |
| Escribe `0x8000` | `+0x130`, `+0x138` |
| Escribe un byte cero | `+0x38`, preservando los otros bytes del dword |

La comparación completa confirma que conserva otros campos, incluidos `+0x60`, el
puntero de tipo `+0x68`, el saldo de 64 bits en `+0x180` y los bytes no listados.
No se les atribuyen valores iniciales universales ni se supone que deban estar a cero
en una partida. La ruta de transferencia puede modificarlos después con sus propios
setters: es distinto del efecto de esta entrada aislada.

## Copia de rangos con capacidad existente

Los descriptores tienen begin/end/capacity de 32 bits en los caminos comprobados.
Los vectores en `+0x7C` y `+0xA4` se copian mediante `0x0043A750` y elementos de ocho
bytes; los de `+0x8C` y `+0xB4`, mediante `0x009BEEB0` y elementos de cuatro bytes.
Los callees internos alcanzados incluyen `0x0043AB30`, `0x007E72F0` y `0x00AAE480`.
Los tipos de elemento originales y su significado de gameplay no se declaran aquí.

El destino conserva capacidad y begin cuando tiene espacio suficiente, copia los
bytes del origen y ajusta end al nuevo rango lógico. Incluye crecimiento dentro de
capacidad, reducción y rangos vacíos. Los bytes que quedan fuera del nuevo rango
lógico no se borran: se comprueban explícitamente como parte de la región completa.
No se confunden con elementos todavía activos.

Los 24 casos directos cruzan cuatro longitudes de origen (0, 1, 2, 7), tres de destino
(0, 1, 5) y tamaños iniciales de objeto cero/17. La capacidad se prepara por encima
de ambas longitudes. Los demás grupos añaden perfiles de longitud `(0,0)`, `(3,5)` y
`(5,1)` para los cuatro vectores.

## Destino vacío y transferencia

Los 270 casos del núcleo llaman realmente a la inicialización cuando `destino+0x58`
es cero, y después ejecutan el resto de `0x005345A0`. El modelo conserva el saldo
previo del destino, copia y reinicia sólo los campos listados y aplica la aritmética
y contadores del contrato de transferencia. En particular, el setter de tamaño deja
`+0x5C` igual al nuevo tamaño cuando el anterior era cero.

Se prueban cuatro tamaños de origen, cantidades alrededor de cero y del tamaño de
origen, tres relaciones de región, dos flags y los tres perfiles de buffers. Las
dos banderas de tipo `+0x40` se mantienen a cero; no se activan los caminos adicionales
de estadísticas y jerarquías de propietario.

Los casos con cantidad cero también alcanzan la inicialización y las copias del
destino vacío. Por tanto, en este camino «cantidad cero» no equivale a una llamada
sin efectos: pueden cambiar atributos, rangos lógicos y campos reiniciados aunque
no se transfiera población.

## Selección y reutilización de los wrappers

`0x00534810` recorre el rango del contenedor en `+0x34/+0x38` con paso `0x278` y
selecciona el **primer slot con tamaño cero**. Copia el puntero de tipo desde el origen
antes de llamar al núcleo con flag cero. El recurso opcional `+0x1D4` es nulo en los
fixtures; la limpieza de uno no nulo sigue fuera de esta prueba.

`0x00534930` recorre `+0x44/+0x48` con el mismo paso y selecciona la **primera tupla
coincidente** de los campos `+0x68`, `+0x70`, `+0x6C`. Llama al núcleo con flag uno.
Se prueba el destino coincidente con tamaño cero y con tamaño diez.

Ambas matrices recorren las cuatro posiciones de un contenedor de cuatro payloads.
Hay coincidencias posteriores que deben permanecer intactas. Los slots anteriores
del segundo wrapper fallan por cada uno de los tres campos, para comprobar las tres
comparaciones. Se verifica que sólo cambia el seleccionado y que begin/end del
contenedor no avanzan: el camino de append no se ejecuta.

No se asignan aún nombres de cultura, religión o migración a las claves, ni se afirma
que los payloads sintéticos satisfagan todas las invariantes de un mundo cargado.

## Reproducción y fronteras pendientes

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_pop_reuse.py
```

Reverify contrasta 16 instrucciones adicionales. Recibos:
`evidence/generated/pop-reuse/{claims.json,reverify.json,emulation.json}`.
El modelo de aritmética compartido está en `scripts/pop_transfer_model.py`; los efectos
de inicialización se comparan por separado con copia literal de los rangos declarados.

Esta fase no valida el constructor completo `0x00954F40`, append ni expansión de
capacidad. La [fase posterior de construcción y append](POP-APPEND.md) ejecuta
constructor y wrappers completos con catálogos vacíos y capacidad libre. Una reserva
o fallo de heap, la limpieza del recurso opcional no nulo,
alias entre origen/destino, flags de tipo no cero, registros vivos, excepciones o
concurrencia. Esas ramas continúan abiertas aunque la ruta de reutilización completa
ya haya retornado correctamente en los casos probados.
