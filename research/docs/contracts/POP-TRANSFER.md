# Transferencia de cantidad, saldo y contadores entre POPs

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida `0x00400000`. Entrada núcleo VA `0x005345A0`, RVA `0x001345A0`.
«Origen», «destino», «región», «saldo» y «evento» son nombres operativos; no se atribuye
todavía una mecánica completa de migración o asimilación a estos callees.

## ABI y dominio ejecutado

**confirmed para 1.504 fixtures completos de Unicorn:** EAX contiene el origen y los
cuatro argumentos de pila son `(contenedor, destino, cantidad, flag)`. Termina con
`RET 0x10`, conserva EBX, ESI, EDI y EBP y deja la pila tras los cuatro argumentos.
La cantidad se puede sobrescribir en su slot de pila con el valor limitado.

Se usan objetos distintos, tamaño de origen entre cero y dos millones, tamaño inicial
del destino positivo y byte `contexto_tipo+0x40=0` en ambos. Se ejecutan los cuerpos
originales completos del núcleo y de sus callees alcanzados: dos setters de tamaño,
división signed64, producto modular64 y setter de región. No se sustituyen por stubs.

## Cantidad y tamaños

El núcleo limita la cantidad solicitada por arriba al tamaño del origen mediante
comparación signed32. No añade un límite inferior cero en este punto. Con `S` como
tamaño de origen, `D` destino y `A` cantidad ya limitada:

```text
A = min(signed32(cantidad), S)
destino.tamaño = clamp(signed32(D + A mod 2^32), 0, 2000000)
si S != 0:
    origen.tamaño = clamp(signed32(S - A mod 2^32), 0, 2000000)
```

Las actualizaciones reales pasan por `0x00955FD0`; aplican también las escrituras de
`+0x5C` y `+0x60` del [contrato de tamaño](POP-SIZE.md). Si el origen empieza a cero,
se omiten su cambio de tamaño y su transferencia de saldo, aunque el destino y su
contador ya se hayan procesado. Las cantidades negativas del banco son entradas
aritméticas sintéticas, no solicitudes observadas en una partida.

La cantidad cero tampoco provoca un retorno temprano: los setters todavía pueden
actualizar el tamaño anterior guardado y cambiar la región del destino. En el
[camino vacío](POP-REUSE.md) también se inicializan atributos y se copian rangos.

## Contadores: cantidad solicitada frente a tamaño efectivo

Elige un índice para el destino y otro para el origen, dentro de los nueve dwords
que comienzan en `+0x158`:

| Condición | Índice destino | Índice origen |
| --- | --- | --- |
| Región de origen nula, o su `+0x12C` coincide con `contenedor+0x20` | 1 | 8 |
| Región de origen no nula, identificadores distintos | 2 | 7 |
| Byte inferior del cuarto argumento distinto de cero | Conserva el anterior | 6 |

El destino suma `A`; el origen resta `A` sólo cuando `S!=0`. Son operaciones de 32 bits
con wrap. Los flags `0x00000100` y cero recorren la misma selección porque se consulta
un byte, mientras que `1` y `0xFF` activan la alternativa.

**Contraejemplo a interpretar el contador como variación efectiva:** con origen 5,
destino 1.999.999 y cantidad 5, el destino acaba en 2.000.000, pero su contador aumenta
en 5 y el origen pasa a cero. La variación efectiva del destino es uno. Este caso no
demuestra un fallo de la simulación: el contrato completo de los llamadores y de esos
acumuladores todavía no está cerrado.

## Saldo de 64 bits y redondeos

Si `S!=0`, lee el campo de 64 bits de `origen+0x180`. En el dominio probado, el modelo
bit a bit que coincide con la ejecución es:

```text
r = trunc_hacia_cero((A << 30) / (S << 15))
p = (r * saldo_origen_bits) mod 2^64
delta = arithmetic_shift_right(signed64(p), 15)
saldo_destino = max(0, signed64((saldo_destino_bits + delta) mod 2^64))
saldo_origen  = max(0, signed64((saldo_origen_bits  - delta) mod 2^64))
```

La división `0x00AC02A0` y el producto `0x00AC9F20` se ejecutan de verdad. El producto
se trunca a 64 bits **antes** del desplazamiento. Éste es aritmético: un resultado
negativo no equivale a dividir por 32.768 truncando hacia cero. Las sumas y restas de
saldos también envuelven antes de limitar a cero un resultado con signo negativo.
El C descompilado no debe convertirse directamente en operaciones signed con overflow
indefinido de un compilador nuevo.

El nombre «saldo» es **inferred**; no se establece aquí la unidad monetaria original.
Los patrones negativos o extremadamente grandes se usan para contrastar la aritmética,
sin asegurar que satisfagan las invariantes financieras de una partida.

## Cambio de región y marca auxiliar

Al final llama a `0x00955F20` con ESI apuntando al destino y la región del origen como
argumento. En los fixtures con flag de tipo cero, escribe esa región en `destino+0x64`.
Si la marca `destino+0x274` es no nula y tanto la región anterior como la nueva existen,
puede borrar la marca cuando sus dwords `+0x12C` difieren. Se prueban regiones nulas,
idénticas y diferentes. No se da un nombre de gameplay a esa marca.

El camino con `contexto_tipo+0x40!=0` puede llamar a las funciones de estadísticas y
propietario antes de cambiar de región. Está fuera de esta matriz; no se considera
que el setter sea una simple asignación en general.

## Wrappers del llamador: evidencia estática parcial

La actualización de POP llama a dos wrappers que alcanzan este núcleo:

| Wrapper VA | Lectura estática contrastada |
| --- | --- |
| `0x00534810` | Recorre begin/end en `contenedor+0x34/+0x38` con paso `0x278`, busca tamaño cero y reutiliza ese slot; puede limpiar el recurso `+0x1D4`; en su defecto alcanza creación/append. Llama al núcleo con flag cero |
| `0x00534930` | Recorre begin/end en `contenedor+0x44/+0x48` con paso `0x278`; compara los campos `+0x68`, `+0x70` y `+0x6C`; en su defecto alcanza creación/append. Llama al núcleo con flag uno |

No se atribuyen automáticamente a cultura, religión o categoría esos tres campos.
La coincidencia con stride de 632 bytes refuerza el vínculo con el payload CPop, pero
no sustituye la validación del constructor, copia o propiedad de los contenedores.
Ese banco inicial no ejecutaba los wrappers completos ni la inicialización del destino
vacío. La [ampliación de reutilización](POP-REUSE.md) añadió 726 casos de inicialización,
núcleo con destino vacío y recorridos completos de reutilización/coincidencia de ambos
wrappers. La creación, append y expansión de capacidad siguen abiertas.

## Reproducción, evidencia y límites

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_pop_transfer.py
bash research/scripts/query.sh 0x1345a0
```

Fuente del modelo explícito: `research/scripts/pop_transfer_model.py`. Reverify
comprueba 26 instrucciones del núcleo y de los wrappers. Los recibos están en
`evidence/generated/pop-transfer/{claims.json,reverify.json,emulation.json}`.
Se comparan los 65.536 bytes de la región de fixtures, se restringen las escrituras
a esa región y al stack y se comprueba la secuencia real de llamadas alcanzadas.

La matriz incluye 816 casos de cantidades y categorías, 216 de saldos límite,
216 de cantidades negativas y 256 casos pseudoaleatorios de semilla fija. No se
cubren alias entre origen y destino, reserva/copia de payloads completos, tipo con flag
no cero, excepciones, reentrada o concurrencia. El destino inicialmente vacío tiene
ahora un dominio separado en el contrato de reutilización. Tampoco se confirma
la conservación global de población o dinero a partir de esta sola primitiva.
