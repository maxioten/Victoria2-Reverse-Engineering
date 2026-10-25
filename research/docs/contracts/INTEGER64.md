# Primitivas enteras de 64 bits

Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base VA preferida `0x00400000`.

| VA | RVA | Nombre del analizador, candidato | Operación comprobada |
| --- | --- | --- | --- |
| `0x00AC02A0` | `0x006C02A0` | `__alldiv` | División de patrones de 64 bits interpretados con signo, truncada hacia cero |
| `0x00AC9F20` | `0x006C9F20` | `__allmul` | Producto, conservando los 64 bits inferiores |

**confirmed en los casos declarados:** al entrar, los argumentos están en
`[ESP+4..ESP+11]` y `[ESP+12..ESP+19]`, en little endian. El resultado se devuelve
en EDX:EAX. Ambas entradas retiran los 16 bytes de argumentos mediante `RET 16`;
ESP final = ESP de entrada + 20, incluyendo la dirección de retorno.
Se comprueba preservación de EBX, ESI, EDI y EBP.

## División

El modelo operativo usa `q = abs(a) // abs(b)` y aplica el signo después, conservando
el patrón de 64 bits. Por tanto `−3 / 2` y `3 / −2` producen −1, no −2.
No es equivalente al operador `//` de Python para operandos de signos distintos.

Las magnitudes absolutas se escriben en los slots de argumentos de la pila cuando
los operandos son negativos. Aunque esos argumentos se retiren al retornar, su memoria
queda modificada y debe distinguirse de una función pura si se comparan estados de CPU.

El caso `INT64_MIN / −1` devuelve el patrón `0x8000000000000000` en el ejecutable
emulado. No se presupone el comportamiento de una expresión C nativa con overflow
con signo. El helper utiliza divisiones sin signo de 32 bits para construir el cociente.

Las pruebas cubren el camino con divisor de magnitud menor que 2^32 y el de divisor
grande, su bucle de normalización y la corrección final de una unidad al cociente.
Se observó esa corrección en nueve ejecuciones de la muestra.

Cinco divisiones por cero provocan una excepción de CPU en VA `0x00AC02EB` en Unicorn.
Cada observación de excepción usa una CPU emulada nueva, para evitar reutilizar estado
interno tras una excepción no atendida. No se ejecuta el manejo SEH del juego.

## Multiplicación

El producto se compara módulo 2^64. Los mismos patrones de bits permiten representar
operandos positivos, negativos o sin signo; no se deduce de esta primitiva cómo los
interpreta cada llamador. Los argumentos de pila quedan intactos.
Se cubren la ruta corta con ambas mitades altas a cero y la ruta con productos cruzados.

## Reproducción y alcance

`source research/env.sh`, después `python research/scripts/verify_integer_helpers.py`.
Se ejecutan las entradas originales completas sobre casos extremos, productos cruzados
y 2.048 pares pseudoaleatorios deterministas: 2.444 divisiones no nulas y 2.464 productos,
sin discrepancias. Se comparan resultado, argumentos tras la llamada, pila y registros
no volátiles. Reverify contrasta diez instrucciones estructurales.
Recibos: `evidence/generated/integer-helpers/{claims.json,reverify.json,emulation.json}`.

Estos helpers no introducen una escala fixed point por sí mismos. Los desplazamientos
y redondeos del llamador deben contrastarse por separado. Tampoco se validan aquí
flags, registros volátiles restantes, todas las entradas posibles ni comportamiento
del sistema operativo ante una excepción.

## Segunda ejecución, fuera de Unicorn

**confirmed para los mismos vectores:** se ejecutaron directamente las dos secuencias
originales en un proceso ELF32/i386 del host. El harness de ensamblador conserva su ABI
de pila, compara EDX:EAX con los valores calculados previamente por Python y comprueba
los contadores de 2.444 divisiones y 2.464 productos. Salió con código cero y sin
discrepancias. Las secuencias extraídas miden 170 y 52 bytes, respectivamente; sus
hashes y los del ejecutable, fixtures y harness se conservan en el recibo.

Reproducción: `python research/scripts/run_elf32_integer_probe.py` con el entorno cargado.
El filtro de syscalls del sandbox detuvo la primera ejecución con SIGSYS; la comprobación
válida se ejecutó fuera de ese filtro, sin cambiar el código aritmético. Recibo:
`evidence/generated/elf32-integer/execution.json` y stdout conservado.

Esto es una segunda ejecución de primitivas autocontenidas. No demuestra un runtime
Windows ni una partida. Tampoco compara el estado completo de registros o la memoria
de argumentos en ese harness; esas comprobaciones permanecen en el banco de Unicorn.

También se compiló un harness PE32 equivalente en `evidence/generated/native-integer/`.
Su ejecución bajo Wine 11.19 terminó con código 53 y `could not load kernel32.dll`,
después de inicializar parcialmente el prefijo aislado. En ese prefijo no aparecieron
las DLL básicas de SysWOW64, aunque están disponibles entre las DLL de Wine instaladas.
Se conserva como **fallo del entorno**, sin contarlo como prueba pasada ni refutación
de los cálculos. La ejecución i386 directa anterior sí pasó.

Actualización: se incorporaron al SysWOW64 del prefijo experimental las cuatro DLL
PE32 ausentes de la instalación local (ntdll, kernel32, kernelbase y ucrtbase), con
hashes en `native-integer/staged-wow64-builtins.json`. Se ejecutó con `WINEARCH=wow64`,
opción documentada por la versión instalada. El banco PE32 pasó los mismos 2.444
cocientes y 2.464 productos, con tamaño de puntero de cuatro bytes y salida cero.
Recibo válido: `evidence/generated/native-integer/execution.json`; los intentos fallidos
anteriores no se convierten retroactivamente en pruebas pasadas.
No se valida con esto el arranque del juego, el debugger o el resto de APIs de Windows.
