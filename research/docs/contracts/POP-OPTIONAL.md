# Recurso opcional de POP: construcción y liberación

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Banco PE32 con imagen
privada en `0x30000000`, delta de relocación `0x2FC00000`.

**confirmed para 192 ciclos nativos nuevos:** al activar el byte de tipo `+0x39C`,
el constructor CPop `0x00954F40` reserva 256 bytes mediante el CRT original,
llama a `0x00954910` y guarda el puntero resultante en `POP+0x1D4`.
Después el destructor CPop `0x00955AE0` llama a `0x00955D40`, que libera el recurso.

La matriz conserva los catálogos A/B de tamaños 0/1/3/7, tres patrones de objeto y
reservas, y cuatro modos de caché de la [construcción sin recurso](POP-CONSTRUCTION.md).
Los singletons ya existen y los registros globales están ausentes. Los 192 ciclos
anteriores con el byte desactivado se mantienen como comparación de rama.

## Dos pools internos y un bloque de 256 bytes

La entrada `0x00954910` recibe el destino como argumento de stack, retorna con
RET 4 y devuelve ese destino en EAX. Construye dos subobjetos en offsets 0 y
`+0x58`, con esta vista operacional parcial:

| Offset relativo a cada pool | Efecto observado |
| --- | --- |
| `+0` | vtable preferida `0x00DFBDDC` |
| `+4` | dword `0x18D` |
| `+8..+0x47` | 64 bytes cero |
| `+0x48/+0x4C/+0x50` | begin/end/capacity de un vector de elementos de ocho bytes |

La RTTI local vincula esa vtable con `.?AVCGoodsPool@@`: TypeDescriptor en
`0x00F110BC`, CompleteObjectLocator en `0x00E4C794` y palabra anterior a la vtable
en `0x00DFBDD8`. Reverify contrasta nombre, locator y enlace. **confirmed** el
nombre RTTI de los pools; no identifica por sí solo el tipo original del bloque
completo de 256 bytes ni el significado de todos sus campos.

Ambos vectores empiezan con un elemento copiado literalmente de los ocho bytes
globales en `0x0125E448`. Se ejecutan el append `0x00423920`, su reserva y las
llamadas CRT originales; cada vector reserva ocho bytes en este dominio. Se cruzan
patrones cuyo valor global es cero, `0x0123456789ABCDEF` o `0xFFFFFFFFFFFFFFFF`.
Las reservas de ambos pools y del recurso son distintas mientras están vivas.

El recurso escribe `0x8000` en `+0xC8/+0xD0/+0xD8` y varios dwords cero. La
constante binary64 `16384.5`, en `0x00E45830`, se convierte mediante el original
`0x00B31C36` a `16384` con CW `0x037F`, almacenado en el campo de 64 bits `+0xE8`.
Se comparan los 256 bytes completos, incluidos los agujeros que conservan el patrón
de reserva; no se supone que todo el bloque comience a cero. El banco conserva el
estado FX del host como en los ciclos anteriores.

## Orden y snapshots antes de liberar

`0x00955D40` recibe ESI = recurso y RET sin argumentos. El camino contrastado:

1. libera el buffer del segundo pool, descriptor `recurso+0xA0`, y pone a cero su terna;
2. libera el buffer del primer pool, descriptor `recurso+0x48`, y pone a cero su terna;
3. libera el objeto de 256 bytes.

Se comprueban los ocho bytes de cada buffer antes de HeapFree y el bloque de 256
bytes después de borrar sus descriptores, antes de liberarlo. Los callbacks
reenvían a HeapFree real; no producen retornos ficticios. Después el destructor
CPop libera sus otros buffers en el orden del contrato de construcción.

La comparación completa del payload CPop confirma que el destructor no pone a
cero `POP+0x1D4` en ese camino: conserva el valor de un puntero cuya reserva ya
liberó. Esto describe bytes de un objeto destruido, no un puntero utilizable ni
una demostración de fallo en un objeto vivo.

## Cobertura y pendientes

Esta fase añade 1.728 reservas y 1.728 liberaciones originales. Al cerrar esta fase, el recibo combinado
contenía **846 casos**, **9.738 reservas**, **7.515 liberaciones** con
snapshot y **9.936 palabras de metadatos de catálogo** contrastadas. Sólo 192 casos
tienen el recurso opcional activado. Los anteriores están conservados con sus
fuentes en `native-growth/baseline-constructor-654/`.

Faltan copia de pools/recurso con datos, crecimiento de sus vectores por encima del
elemento inicial, significado del mapa de 64 bytes, construcción perezosa de
singletons, registro vivo, fallos de heap, excepciones y concurrencia. No se
atribuye semántica de producción o unidades económicas a los dwords por intuición.

## Reproducción

```bash
source research/env.sh
python research/scripts/verify_pop_optional.py
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Reverify contrasta 13 instrucciones y tres vínculos RTTI. Recibos estáticos:
`evidence/generated/pop-optional/`; nativos: `native-growth/execution.json`, con
`entry: constructor_lifecycle` y `optional_enabled: 1` en los casos nuevos. El gate
vincula fuentes y recibos por hashes; la evidencia nativa es previa, no una nueva
ejecución de Wine por cada gate.
