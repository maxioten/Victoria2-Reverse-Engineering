# Constructor con tipo y destrucción con catálogos

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA para base preferida `0x00400000`; RVA = VA − base. Imagen privada de runtime
`0x30000000`, delta de relocación `0x2FC00000`.

**confirmed para 192 ciclos nativos completos:** entrada `0x00954F40` con EDX = tipo
y un argumento de stack = destino, RET 4 y EAX = destino; después destructor
`0x00955AE0` con un argumento de stack y RET 4. Se ejecutan cuerpos y callees
originales con HeapAlloc/HeapFree reales, sin iniciar engine, TLS o una partida.

La matriz cruza longitudes independientes A/B de catálogo `(0,1,3,7)`, tres patrones
iniciales de objeto/reservas `(0,0x5A,0xFF)` y cuatro modos de caché. El constructor
se contrasta antes del destructor y el payload completo de 632 bytes se contrasta
de nuevo al terminar el ciclo. Cada buffer se contrasta antes de liberar.

## Distribuciones e identidad

El constructor toma las claves de los globals, instala la vtable de CPop, mantiene
el registro inactivo e inicializa los campos declarados en
[POP-APPEND](POP-APPEND.md). Conserva los agujeros del payload; no es memset de
632 bytes. Las claves y punteros de singleton son fixtures declarados.

Construye cuatro distribuciones mediante `0x004BE4F0`. Las de payload `+0x74/+0xC4`
toman la longitud del catálogo A; las de `+0x9C/+0xEC`, la de B. Cada una contiene
un vector de ocho bytes por elemento y otro de cuatro. Con catálogo vacío los
descriptores quedan nulos; con longitud positiva se comprueba reserva de exactamente
la longitud lógica solicitada y end igual a capacity.

Los vectores de ocho bytes se inicializan con pares de dwords cero. Los vectores
de cuatro reciben los metadatos del catálogo: A, campo de entrada `+8`, hacia
`+0x8C/+0xDC`; B, campo `+0x30`, hacia `+0xB4/+0x104`. Sus cabeceras, arrays y
entradas son distintos en los fixtures. El contenido completo de todos los buffers
se compara con el modelo, no sólo sus punteros o tamaños.

Esta fase aporta 1.152 reservas y 1.152 liberaciones originales, más 2.112 palabras
de metadatos contrastadas. Los 12 casos con ambos catálogos vacíos no reservan
buffers internos. Se comprueba también ese camino sin reservas.

## Cachés y estado x87

| Global | Si ya es no cero | Si es cero en estos fixtures |
| --- | --- | --- |
| `0x00F20C04` | conserva su valor | toma `0x0131BB34`, ya existente |
| `0x00F20C08` | conserva su valor | toma `0x012586DC` |

Los cuatro modos cruzan ambas cachés presentes/ausentes. No se construye el objeto
de `0x0131BB34`: ya existe. También existen los singletons `0x012587EC/0x0125880C`.
Su inicialización perezosa completa sigue fuera de este dominio.

Cada ciclo guarda el estado FX del host, ejecuta FNINIT y comprueba CW `0x037F`
y TOP cero después del constructor; después del destructor restaura el estado FX.
La conversión original `0x00B31C36` de la constante binary64 `3277.300048828125`
produce `3277`, almacenado en el campo de 64 bits `+0x128`. Se comprueba como parte
del payload. No se generaliza a otros controles ni a excepciones FPU sin máscara.

## Destrucción y límites

El destructor original libera los buffers no nulos en orden de offsets
`+0x104,+0xF4,+0xDC,+0xCC,+0xB4,+0xA4,+0x8C,+0x7C`. El callback comprueba contenido,
puntero y orden antes de llamar a HeapFree real. Al terminar, las ternas de esos
vectores están a cero, la vtable es la de la base persistente y los strings
declarados quedan vacíos. El modelo contrasta todos los bytes restantes también.
FS:0 nativo se conserva alrededor de ambas entradas.

El byte del tipo `+0x39C` está a cero, por lo que no se crea el recurso opcional
`+0x1D4` en los 192 casos de esta fase. La [ampliación opcional](POP-OPTIONAL.md)
ejecuta otros 192 con ese byte a uno. No hay referencias de regimientos y los registros globales están ausentes.
Faltan ese recurso opcional, singletons no construidos, registro vivo, errores de
reserva, excepciones, referencias externas y concurrencia. No se deduce seguridad
paralela de la construcción de objetos sintéticos independientes.

## Reproducción y recibo combinado

```bash
source research/env.sh
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

Al cerrar esta fase, el banco combinado contenía **654 casos**, **8.010 reservas**, **5.787 liberaciones**
con snapshot previo y **7.824 palabras de metadatos** contrastadas. Incluye los 462
casos anteriores de copia/append/expansión y los 192 ciclos nuevos; no todos prueban
el constructor con tipo. El recibo por caso lo distingue con
`entry: constructor_lifecycle`. Fuentes y recibos anteriores están conservados en
`native-growth/baseline-catalog-copy-462/`.

El gate enlaza por hash fuentes, loader, builder, runner, ejecutable y salida del
recibo nativo. Lo incorpora como evidencia previa y no vuelve a ejecutar Wine.
