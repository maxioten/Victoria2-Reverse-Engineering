# Vida de nodos de POP: ejecución PE32 aislada

Perfil: `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferida base `0x00400000`. Entrada investigada: VA `0x004BE8D0`, RVA `0x000BE8D0`.

El recibo actual combina **134 casos de POP/regimientos** descritos aquí,
[274 aislados del registro](OBJECT-REGISTRY.md), [41 ciclos registrados](REGISTRY-INSERTION.md)
y [tres pruebas del bloqueo](AUTOMATIC-IDS.md).
Total: 452 casos, 81 HeapAlloc originales, 790 HeapFree originales y 350 comparaciones
previas a liberar. Los contadores de las secciones siguientes se refieren a la fase
POP inicial de 134 casos; no incluyen los eventos de las fases posteriores.

## Preparación y direcciones

El harness PE32 se carga en `0x20000000`; reserva una copia privada de la imagen de
referencia en **base real `0x30000000`**, delta `0x2FC00000`. Aplica las 249.412
relocaciones `IMAGE_REL_BASED_HIGHLOW` de la tabla del PE. Las 1.240 entradas de tipo
ABSOLUTE son padding del formato. No ejecuta entry point, callbacks TLS ni
inicialización del motor. Las secciones ejecutables quedan RX y las restantes
reciben protección según sus características. El archivo de referencia no cambia.

La entrada ejecutada es, por tanto, VA real `0x300BE8D0`. Los CALL relativos conservan
su desplazamiento; los operandos absolutos sujetos a relocación reciben el delta del
cargador. «Código original» en este banco incluye estas relocaciones de carga,
no significa identidad de cada byte con la imagen en su base preferida.

Se declaran diez escrituras adicionales en la copia privada:

| VA preferida | VA real del banco | Fixture |
| --- | --- | --- |
| `0x00C8A070` | `0x3088A070` | IAT HeapFree: callback que registra y reenvía al HeapFree real |
| `0x00C8A05C` | `0x3088A05C` | IAT HeapAlloc: callback que registra y reenvía al HeapAlloc real, sólo rutas exitosas |
| `0x00F202E8` | `0x30B202E8` | Handle de un heap privado creado con HeapCreate |
| `0x01258A94` | `0x30E58A94` | Registro ausente, cero |
| `0x01258A98` | `0x30E58A98` | Registro ausente, cero |
| `0x012588E8` | `0x30E588E8` | Puntero a estado sintético: byte `+0xD1D=1`, `+0xD1C=0` |
| `0x00C8A188` | `0x3088A188` | IAT SwitchToThread: callback que registra y reenvía la cesión real |
| `0x01258A90` | `0x30E58A90` | Fixture de tipo automático, escritura de 16 bits |
| `0x01258A9C` | `0x30E58A9C` | Semilla del contador, escritura de 32 bits |
| `0x0131CA68` | `0x30F1CA68` | Byte de bloqueo y pruebas de adquisición controlada |

Las tablas permanecen ausentes en la primera fase POP; la fase independiente del
registro varía sus punteros a fixtures presentes/ausentes. Una tercera fase ejecuta
el alta y destructor de POP con ambas tablas presentes y contenedores propios vacíos.

La asignación en la base preferida había fallado con error 487: VirtualQuery encontró
reservas de Wine que se solapaban con el rango. No se liberaron esas reservas. El
diagnóstico queda registrado aquí; los primeros recibos canónicos se sobrescribieron
antes de incorporar los directorios de intentos. Se pasó a la carga con relocaciones.

## Dominio comprobado

**confirmed para 134 casos sintéticos:** seis llamadas con nodo nulo y 128 con nodos
válidos de listas de longitud uno o tres. Se prueba cada posición, marca de recorrido
activa/inactiva, cuatro perfiles de propiedad y cero, uno, dos o tres regimientos:

| Perfil | Recursos del nodo seleccionado |
| --- | --- |
| 0 | Cadenas internas, triples vacíos, objeto opcional nulo |
| 1 | Dos cadenas con buffer de heap y nueve buffers de triples |
| 2 | Objeto opcional `+0x1D4`, con buffers en sus triples `+0xA0` y `+0x48` |
| 3 | Recursos de los perfiles 1 y 2 combinados |

Los nodos se asignan con HeapAlloc y miden `0x288` bytes. Los buffers poseen memoria
válida del mismo heap. Cada perfil se combina con un vector `+0x3C..+0x40` de cero a
tres referencias a fixtures con la vtable validada de CRegiment. Si necesita ese vector,
el perfil 0 o 2 también reserva su buffer. El [enlace con regimientos](POP-REGIMENTS.md)
documenta el circuito y corrige el término provisional «observadores» de las primeras notas.

Cada fixture de regimiento ocupa 256 bytes para comprobar toda esa región; no se afirma
que sea el tamaño real de la clase. Tiene `+0x30=POP`, cadenas internas y `+0x74=0`.
El estado global sintético mide `0xD20` bytes y queda idéntico tras el banco. Sus dos
flags evitan la actualización de país/tipo y la aritmética especial REB; no se prueban
callbacks del ejército. Los registros de objetos están ausentes. Ningún objeto procede
de una partida real.

## Efectos observados

Se registraron **632 HeapFree reales exitosos** y **192 comparaciones completas justo
antes de liberar**: 64 nodos de 648 bytes, 32 objetos opcionales de 192 bytes y 96
regimientos sintéticos de 256 bytes.
No se lee memoria después de liberarla. El callback comprueba el heap, flags cero,
puntero, orden y que el contador de la lista aún no haya disminuido.

En la ruta inmediata, el orden para el perfil con todos los recursos es:

1. Regimientos referenciados, en el orden inicial del vector.
2. Buffer del objeto opcional en `+0xA0`, buffer en `+0x48`, objeto opcional.
3. Cadena del nodo en `+0x22C`.
4. Buffers del nodo en `+0x104`, `+0xF4`, `+0xDC`, `+0xCC`, `+0xB4`, `+0xA4`,
   `+0x8C`, `+0x7C` y `+0x3C`.
5. Cadena en `+0x14` y, finalmente, el nodo.

Los triples terminan a cero. Las cadenas quedan con longitud cero, capacidad 15 y
primer byte cero; no se presupone borrar el resto de su unión. El puntero `+0x1D4`
conserva su valor después de liberar el objeto opcional. La vtable del nodo termina
en el valor reubicado correspondiente a `0x00E3A544`.

Al retornar, la cabecera, cola, enlaces de vecinos y contador reflejan la eliminación.
Los nodos restantes se comparan byte por byte. La ruta diferida conserva la lista y
los recursos: sólo escribe uno en `+0x280`. El nodo nulo devuelve AL cero; los otros
casos devuelven AL uno. FS:0 conserva su valor anterior. HeapValidate pasa tras cada
caso y la limpieza del harness libera los fixtures que el código original no destruyó.
En los casos diferidos también se comparan los bytes de cada regimiento y del vector.
Antes de liberar cada regimiento se comprueba la reducción del rango lógico y el orden
de los que quedan. Antes de liberar el buffer del vector se comparan sus 32 bytes,
incluidas las referencias fuera del rango lógico que el código no borra.

## Reproducción y límites

Desde la raíz, cargar `research/env.sh` y ejecutar:

```bash
python research/scripts/build_native_pop_probe.py
python research/scripts/run_native_pop_probe.py
```

Se utilizó Wine 11.19, `WINEARCH=wow64`, prefijo aislado `research/projects/wine-probe`.
El banco se ejecutó fuera del filtro de syscalls del sandbox. Fuente propia:
`research/harnesses/native_pop_lifetime.c`. Recibos, hashes y casos:
`research/evidence/generated/native-pop/{build.json,execution.json,execution.stdout}`.
Las líneas base anteriores, fuentes y recibos están archivadas en
`native-pop/baseline-38-cases/`, `native-pop/baseline-134-cases/` y
`native-pop/baseline-328-cases/`, más `native-pop/baseline-413-cases/`. Los intentos nuevos
se conservan además en directorios `attempt-*`, con la fuente C y el header de casos
de registro utilizados. La puerta general
comprueba los hashes del recibo nativo existente; no repite Wine en cada ejecución.

Este resultado no cubre heaps inválidos, fallos de HeapFree, excepciones, tablas obtenidas de una partida,
actualización de país/tipo, callbacks de ejército, corrupción de enlaces ni concurrencia. Tampoco prueba el arranque
del motor o el wrapper virtual de CPop con flag de liberación activo. Es evidencia adicional
para el [contrato emulado](POP-LIFETIME.md), sin ampliar su dominio a una partida real.
