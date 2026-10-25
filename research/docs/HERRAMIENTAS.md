# Herramientas seleccionadas — 21 de octubre de 2026

Las releases se resolvieron mediante la API oficial de GitHub. Sus respuestas completas
están en `evidence/tool-releases/`; URLs, fechas y SHA-256 de los paquetes descargados,
en `toolchain.lock.json`. Se eligieron releases estables para la línea base.

| Herramienta | Uso | Estado de comprobación |
| --- | --- | --- |
| Ghidra 12.1.4 | Desensamblado, análisis, tipos y descompilación | Importación headless ejecutada sobre el binario; resultados y advertencias en el log |
| Temurin JDK 25.0.4.1 | Runtime local de Ghidra y JPype | Arranque real comprobado |
| PyGhidra 3.1.0 | Automatización de Ghidra desde Python | JVM y Ghidra 12.1.4 iniciados mediante el API |
| Rizin 0.9.1 | Segunda lectura del PE y consultas rápidas | Parseó el ejecutable como x86 de 32 bits |
| x32dbg 2026.05.27 | Depuración de Windows x86 | Paquete y PE32 verificados; sesión dinámica bajo Wine aún no validada |
| Capstone | Desensamblado independiente | Pruebas x86 y lectura de los CALL del juego |
| pefile y LIEF | Parsing PE independiente | Coinciden en image base y entry point |
| Unicorn 2.1.4 | Emular primitivas aisladas | Ejecución aritmética x86 comprobada |
| Frida 17.24.3 | Instrumentación dinámica futura | Importación y versión comprobadas; hooks de PE32 bajo Wine no validados |
| Z3 5.3.1 | Equivalencia de modelos explícitos | Identidad aritmética del calendario comprobada en el dominio declarado; no prueba todo el engine |
| reverify 0.11.0 | Verificación, refutación y ledger | 686 comprobaciones estáticas de CALL, calendario, RNG, POPs, registro, aritmética y RTTI, más controles negativos |
| MinGW x86 local | Construcción de wrappers y pequeños harnesses | DLL PE32 compilado; se conserva para experimentos |

El paquete Python de Capstone declara `5.0.9`, pero el motor nativo informa `5.0.7`.
El informe del entorno conserva ambas versiones. No se ocultó esa diferencia detrás
del número de versión del instalador.

Se investigaron también Cutter 2.5.0 y Capstone 6 Alpha. La instalación inicial usa
Ghidra como interfaz/decompilador y Capstone estable para reducir duplicación y
mantener una línea base. Los adaptadores MCP externos no son necesarios para el flujo
automatizado inicial: se usan CLI, PyGhidra y scripts locales verificables.

`reverify[angr]` no está instalado. Su campo `full_fidelity` describe los backends de
parsing/desensamblado/emulación; no implica que el backend semántico esté activo.

No se instalaron herramientas globalmente ni se modificó la configuración global
del asistente. `env.sh` configura rutas y cachés locales para este proyecto.

Wine 11.19 ejecutó el banco aritmético PE32 en `projects/wine-probe`, con
`WINEARCH=wow64` y cuatro DLL PE32 básicas incorporadas al SysWOW64 de ese prefijo
desde la instalación local. El manifiesto y el recibo están en
`evidence/generated/native-integer/`. Esto valida ese banco de consola; el arranque
del juego y x32dbg todavía no tienen validación dinámica en este entorno.

El mismo prefijo ejecutó después el banco combinado de vida de nodos POP y registro:
452 casos sintéticos, 81 HeapAlloc y 790 HeapFree originales exitosos, y 350
comparaciones previas a liberar.
La copia privada
del código recibe las relocaciones del cargador PE y diez escrituras de fixture
declaradas; véase [el contrato](contracts/NATIVE-POP.md). Esto tampoco inicia el motor.

Un banco independiente ejecutó el bloque original de conversión x87/SSE: 3.360 casos
con 56 entradas binary64 y 84 extended80, tres entradas de código, dos valores del selector y cuatro
modos emparejados de redondeo. Se contrastan anchura, resultados y estado flotante
en el [contrato numérico](contracts/FLOAT-CONVERSION.md). Incluye contraejemplos al
truncamiento incondicional y a ignorar la cuantización binary64. No valida todos los
patrones extendidos ni equivalencia de una actualización completa.

`scripts/find_callers.py <pe> <VA>` responde "quién llama a esta función" sin depender del
análisis de Ghidra ni de Rizin: escanea `E8`/`E9 rel32` en `.text` y punteros absolutos de 4
bytes alineados en las demás secciones (que suelen ser slots de vtable o tablas de dispatch).
Se usó para cerrar la cadena del job diario de IA; ver [AI-DAILY-JOB.md](AI-DAILY-JOB.md).
No modifica el binario ni requiere instalar nada.

`scripts/field_refs.py <pe> <disp-hex> [--kind byte|dword]` cuenta los accesos a un campo
`[reg+disp]` reconociendo las formas x86 sin SIB (`80/81/88/89/8A/8B/C6/C7/F6/F7`) en los tres
modos de direccionamiento: `mod=00` (disp 0), `mod=01` (disp8) y `mod=10` (disp32). Sirve para
separar lectores de escritores antes de atribuir semántica a un offset.

**Corrección de la primera versión**: sólo miraba `mod=10`, así que devolvía **0 sitios para
cualquier campo con offset menor que 0x80** — el compilador usa `disp8` en ese rango. Con
`[reg+0x31]` daba 0 y son 256 accesos; con `[reg+0x64]` daba 0 y son 2091. Los conteos publicados
antes de la corrección eran de campos ≥ 0x80 (`0x67C`, `0xAF8`, `0xBB8`, `0x7B4`, `0xBE8`), así
que no cambian.
**Límite importante**: no distingue tipos. El mismo desplazamiento puede pertenecer a clases
distintas; en el job de IA, `+0xBB8` aparece tanto sobre el país como sobre el mundo
(`0x0064BD2A` escribe `[world+0xBB8]`). Los resultados son candidatos, no identificaciones.

`scripts/disasm_fn.py <pe> <VA> [--out RUTA]` desensambla una función completa con Capstone
partiendo del entry de `functions.csv` y avisa si el último tramo no cierra el rango declarado.
Existe porque el desensamblado lineal de Rizin se desincroniza en varias funciones de este
binario (`FUN_00876240`, `FUN_0081e5b0`, `FUN_006874c0`): da menos llamadas y saltos de los que
hay y aparecen instrucciones imposibles. Los conteos publicados deben salir de Capstone;
Rizin sirve para leer tramos cortos.

**Resolver un vtable a nombre de clase (RTTI)**: `evidence/generated/rtti/inventory.json` contiene
1.500 locators consistentes con `decorated_name` y sus `vtables`. Para nombrar una vtable concreta:

```python
import json
d = json.load(open("evidence/generated/rtti/inventory.json"))
for x in d["consistent_locator_candidates"]:
    for v in x["vtables"]:
        if v["vtable_va"].lower() == "0xdfd280":
            print(x["decorated_name"], x["locator_va"])
```

Es el método que resolvió todo el bloque de IA (`CProvince`, `CCountry`, `CStaticModifier`,
`CFlags`, `CProvinceModifier`, `CUniqueUnitName`, `CSelectable`, `CEventScope`) y el que permitió
**corregir** dos atribuciones erróneas hechas por offset. Después del nombre, el constructor se
encuentra buscando quién escribe ese vptr como inmediato:

`C7 /0` con `mod=00`, `rm=reg` (`mov dword [reg], imm32`) para `this` recién alocado, y `mod=10`
(`mov dword [reg+disp], imm32`) para subobjetos embebidos.

Límite: 0.5 % de las tablas quedan fuera del inventario. `0x00E38B28` (el vptr del singleton de
`AI_FrameUpdate`) no tiene locator, así que no se puede nombrar por esta vía.
