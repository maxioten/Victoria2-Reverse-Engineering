# Llamadores de los vectores de POP y consumo por fases

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

Después de comprobar que la [expansión registrada](POP-REGISTERED-IDENTITY.md)
retira la identidad antigua en fixtures, se siguieron los llamadores del append.
**inferred:** los contenedores estudiados actúan como almacenamiento intermedio
de transferencias. Se documentan por separado las pruebas y lo que sigue abierto;
no se identifican con el almacén global de todos los POP.

## Referencias directas recuperadas

El snapshot convergido de Ghidra y las referencias del proyecto guardado enumeran:

| Destino | Sitios CALL directos |
| --- | --- |
| append `0x004BEB50` | `0x004BA6AA`, `0x00534892`, `0x005349C3` |
| wrapper `0x00534810`, vector `+0x34` | `0x00957FDF`, `0x00958394` |
| wrapper `0x00534930`, vector `+0x44` | `0x00958014` |
| wrapper `0x004BA430`, vector `+0x30C` | dos recursivos `0x004BA61C/0x004BA62F`; cuatro en `0x005091A0`: `0x00509A78`, `0x00509ACD`, `0x00509ED8`, `0x00509F24` |

Se contrastan independientemente los doce CALL con bytes del ejecutable. La lista
es **confirmed para esas referencias directas recuperadas**, no una demostración
de que no existan llamadas indirectas, cuerpos no recuperados u otros accesos.
Los tres CALL a los wrappers `+0x34/+0x44` pertenecen al cuerpo candidato de la
actualización programada `0x00957EA0`.

## Tipos y ruta de contexto

La RTTI vincula vtable `0x00DFFACC` con `CCountry` y `0x00DFD280` con `CProvince`.
Los nombres, locators y enlaces se contrastan por bytes. El constructor candidato
`0x004F6A10` escribe la primera vtable y pone a cero las ternas en `+0x34/+0x44`;
`0x004A84C0` escribe la segunda y pone a cero `+0x30C/+0x310/+0x314`.
**confirmed** esos stores y enlaces; **inferred** la atribución general de los
punteros operacionales de los llamadores a país/provincia en una partida real.

El fragmento original `0x00957EBE..0x00957EED` toma `POP+0x64`, lee el índice
`+0x12C` del objeto apuntado y selecciona una entrada desde el array `+4` del
objeto apuntado por global `0x012587E4`. Guarda ese contexto en el local `EBP-0x1C`.
Los dos primeros wrappers reciben el local como primer argumento. No se confunde
el global que contiene un puntero con la cabecera del array que se obtiene al
desreferenciarlo.

El wrapper `0x004BA430` recibe ECX = propietario del vector `+0x30C` y dos argumentos
`(origen,cantidad)`, RET 8. Selecciona el primer slot de tamaño cero, ajusta su tipo
y llama al núcleo `0x005345A0` con el contexto obtenido desde el índice `+0x12C`
del propietario y la misma tabla global. Tiene además una rama previa con llamadas
recursivas y lógica adicional que sigue fuera de la prueba dinámica de esta fase.

## Ejecuciones: función completa y fragmentos separados

**confirmed para 324 llamadas completas a `0x004BA430`:** tres índices de propietario
× tres índices de región de origen × cuatro posiciones reutilizables × tamaños de
origen 5/1000/2000000 × cantidades cero/uno/todo. Los flags de tipo son `+0x3D9=1`
y `+0x40=0`, el recurso opcional es nulo y los vectores copiados están vacíos.
El primero evita la rama previa; no se inventan sus resultados ni se parchea código.

Se ejecutan los callees reales de inicialización, transferencia, aritmética,
setters y copia. Se capturan en la entrada del núcleo sus cuatro argumentos y EAX.
Se comparan los 65.536 bytes de fixtures, fuente y destinos no seleccionados,
ternas del contenedor, stack, registros no volátiles y FS:0 sintético.

El payload del vector termina conservando en `+0x64` la región del origen, mientras
el contexto del núcleo procede del propietario de destino. Los contadores de
transferencia distinguen la igualdad de los índices conforme al modelo anterior.
Esto apoya la interpretación de payload intermedio; no basta por sí solo para
demostrar su aplicación posterior a un POP canónico.

En cada fixture se ejecutan también, **como experimentos separados**:

- la ruta de contexto mensual `0x00957EBE..0x00957EED`, hasta antes del primer test;
- el subgrafo de limpieza `0x004BAC60..0x004BAD00`, con tipo `+0x40=0`, que pone a cero `+0x60`, `+0x58` y el saldo `+0x180/+0x184`, y deja `+0x5C` con el tamaño anterior.

Se comparan sus efectos con la región completa. No son 972 ejecuciones completas
del engine: son 324 funciones completas y dos fragmentos por fixture. En particular,
`+0x3D9=1` provoca una salida mensual posterior que puede evitar transferencias;
la ejecución del prefijo no demuestra que el mismo fixture recorra un tick completo.

## Consumidor y orden del tick

La función candidata `0x004BA780` recorre el mismo descriptor `+0x30C/+0x310` a
paso `0x278`. Su cuerpo recuperado contiene selección/fusión, una llamada al
factory candidato `0x004B8D30`, inicialización `0x00955A00` y setter `0x00955FD0`,
antes del subgrafo que vacía tamaño/saldo del slot. **Sólo** ese subgrafo está
ejecutado aquí. Fases posteriores validan el [factory](POP-FACTORY.md) y la ruta
de nodo nuevo del [consumidor completo](POP-CONSUMER.md).
El pseudocódigo de Ghidra se conserva como representación auxiliar, no fuente original.

El [CFG diario acotado](../HALLAZGOS.md) permite el orden
`0x005091A0` en CALL `0x00685ED1` → consumidor `0x004BA780` en `0x00685F53` →
economía candidata `0x00489990` en `0x00685F7E`. Los bucles de país y consumidor
pueden saltarse. Es un resultado del modelo estático donde cada CALL opaco retorna;
no cubre reentrada, efectos de callees, excepciones ni todas las rutas del engine.

## Reproducción y fronteras

```bash
source research/env.sh
python research/scripts/verify_pop_vector_callers.py
python research/scripts/verify_grounding.py
```

Reverify contrasta 66 comprobaciones de instrucciones/RTTI. Recibos y contextos en
`evidence/generated/pop-vector-callers/`; consultas auxiliares
`queries/query_{ba430,ba780,1091a0,f6a10,a84c0}.txt`. El recibo enlaza el hash del
snapshot `ghidra-converged/calls.csv`. El gate enlaza fuentes y recibos generados.

Pendientes: otras ramas del consumidor/factory, rama recursiva, append/limpieza opcional
en este tercer wrapper, correspondencia de tipos en memoria de partida, límites
de tablas/índices, grafos externos de referencias y concurrencia. Las referencias
externas fijadas sugieren el nombre `Migration_Distribute`; aquí sigue siendo una
pista, no evidencia de todos sus efectos o de sus categorías de gameplay.
