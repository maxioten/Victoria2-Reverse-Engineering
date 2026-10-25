# Fusión de un POP completo en un destino existente

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Los ensayos nativos
usan la imagen privada `0x30000000` con relocaciones declaradas.

**confirmed para los fixtures declarados:** `0x00964370` recibe destino en EDI,
fuente y flag en stack y retorna con RET 8. Se ejecutan sus cuerpos originales
de multiplicación `0x00AC9F20`, división `0x00AC02A0`, tamaño `0x00955FD0` y
saldo `0x0095A5F0`; no hay stubs de callees.

## Campo ponderado de 64 bits

Sean S y D los tamaños anteriores no negativos, y A/B las representaciones
de 64 bits de los campos fuente/destino `+0x128/+0x12C`. El modelo contrastado es:

```text
T = signed32(S + D)
P = low64((S << 15) * A) & 0xFFFFFFFFFFFF8000
Q = low64((D << 15) * B) & 0xFFFFFFFFFFFF8000
atributo_destino = T == 0 ? 0 : low64(trunc_signed(signed64(low64(P+Q)) / (T << 15)))
```

La división trunca hacia cero. El significado de ese atributo fuera de estas
operaciones sigue sin clasificarse; no se le atribuye un nombre de gameplay.
El wrap de los productos y su suma precede a la división. No se puede sustituir
por una media ponderada con precisión ilimitada en todo el dominio de bits.

El banco encuentra **1.530 fixtures** que contradicen esa sustitución. Por ejemplo,
S=0, D=17, A=0 y B=0x7FFFFFFFFFFFFFFF producen 0xFFFFFFFFFFFFFFFF; la media con
precisión ilimitada conservaría B. Son entradas sintéticas de frontera: no se
afirma que esos atributos aparezcan en una partida.

## Tamaño, eventos y saldo

El destino recibe tamaño `clamp(signed32(S+D),0,2000000)` mediante el setter original.
Su `+0x60` coincide con el tamaño bajo tipo `+0x40=0`. `+0x5C` recibe D, salvo D=0,
cuando recibe el tamaño nuevo. Se conserva el contrato previo del setter.

Con flag cero, el índice de evento es nueve y no se suma al array de eventos.
Con flag no cero es uno, o dos si ambas regiones existen y sus índices `+0x12C`
difieren. El contador de 32 bits `+0x158+4*índice` aumenta en S bruto con wrap,
incluso si el tamaño final se limita a dos millones.

El helper llama a `0x0095A5F0` con el saldo bruto de la fuente y ESI=2. Sean X/Y
los saldos fuente/destino interpretados con signo y R su suma modular de 64 bits:

1. Si Y no es negativo, X es positivo y R resulta negativo, el saldo queda en INT64_MAX.
2. En los demás casos se conserva R, salvo que sea negativo: entonces queda cero.
3. Independientemente del saldo limitado, `destino+0x1E8` y `+0x218` suman los
   bits brutos de X con wrap de 64 bits.

No es una suma con saturación simétrica. Por ejemplo, X=INT64_MIN e Y=-1 producen
INT64_MAX por wrap en la rama ordinaria. La fuente permanece íntegra en las llamadas
aisladas al helper; es el consumidor quien después vacía su slot.

## Ejecución completa del consumidor

**1.152 llamadas nativas completas a `0x004BA780`** buscan un destino existente
compatible en el bucket del tipo y ejecutan esta fusión por `0x004BA932`.
Hay tres slots de cola, uno positivo; el tipo no tiene límite de tamaño
(`+0x30=0xFFFFFFFF`) y coinciden tipo, cultura y religión. No se invoca al factory.
Se ejecuta también `0x0068DEA0`, su descriptor `0x00444F10` y las búsquedas originales
de árboles del registro de movimientos. Las claves numéricas de provincia son
iguales; el descriptor y árboles ya contienen la entrada requerida.

Se compara todo el destino de 648 bytes, los tres slots, listas, tipos, regiones,
árboles, descriptor, mundo y tablas de registro con las escrituras previstas.
La pasada final recorre tres buckets y conserva el destino positivo. No hay
HeapAlloc/HeapFree originales durante el consumidor. Después, el banco retira
el nodo fixture con el unlink original: una liberación de 648 bytes, con snapshot
completo previo. Los IDs genérico y dedicado permanecen intactos.

La matriz cruza cuatro parejas S/D `(1,0),(1000,17),(2000000,1999999),
(2000001,2000000)` × ocho parejas de atributos × seis parejas de saldos × índices
de región iguales/distintos × tres patrones. La posición positiva y el índice
de tipo se distribuyen entre 0/1/2 mediante índices de la matriz. No es el producto
cartesiano de posiciones y tipos. El nodo fixture comienza sin registro activo;
ambas tablas de identidad existen y se comprueban vacías antes/después.

## Evidencia, reproducción y fronteras

El verificador aislado cruza siete parejas de tamaños (incluido 0/0), seis
atributos por lado, cinco parejas de saldos y tres modos de evento: **3.780 casos**.
Compara los 65.536 bytes del arena, fuente intacta, ABI y FS:0. Reverify contrasta
20 instrucciones; el cálculo completo es evidencia dinámica aparte.

```bash
source research/env.sh
python research/scripts/verify_pop_merge.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Recibos: `pop-merge/{claims,reverify,emulation}.json`; evidencia nativa en
`native-growth/execution.json`, `entry: pop_consumer_merge`. El runner vuelve a
calcular atributo y saldo desde `scripts/pop_merge_model.py`, independiente del
modelo C del harness; el gate vincula esos modelos y recibos por hash.
La primera expectativa del nuevo verificador puso +0x5C al tamaño nuevo para D=1;
falló y se corrigió para respetar el contrato del setter ya contrastado.

El banco nativo combinado suma **5.223 casos, 26.124 reservas y 25.005 liberaciones**
con snapshot. La fase anterior se conserva en `baseline-consumer-new-node-4071/`.
Una fase posterior [de selección](POP-SELECTION.md) contrasta múltiples candidatos
y las pasadas de búsqueda en emulación. No se prueban aún estadísticas
de tipo `+0x40!=0`, otras claves o rotación/inserción de movimientos, recursos
opcionales, retiro interno de nodos vacíos, excepciones, concurrencia ni un tick real.
