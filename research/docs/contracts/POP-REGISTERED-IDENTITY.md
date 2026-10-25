# Identidad registrada: copiar y reubicar CPop

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base. Banco nativo PE32 con imagen
privada en `0x30000000`, delta de relocación `0x2FC00000`.

**confirmed para 108 casos de copia y 108 de expansión registrada:** cada fixture
crea dos cabeceras de tabla controladas y vacías, y da de alta un CPop mediante el
cuerpo original `0x009C1390`. El nodo de registro de ocho bytes se reserva por el
CRT y HeapAlloc reales. No se simula la inserción escribiendo el enlace esperado.

La matriz cruza tipos de clave 0/0x1268/0x1269/0xFFFFFFFF, identificadores
17/0x80000000/0xFFFFFFFF, tablas de 1/3/7 buckets y tres patrones de reserva.
Cada tabla tiene a lo sumo una entrada; no se afirma cobertura de grafos con varios
objetos registrados ni de creación de tablas por el engine. El alta escribe la
clave del origen y su byte activo `+0x10=1`; se contrastan tabla, heads y enlace.

## Copia de un origen que permanece vivo

La copia completa `0x00955450` crea un destino con las dos palabras de clave
predeterminadas globales, no con la clave del origen. Su byte activo queda cero.
La comparación completa del payload comprueba ambos efectos. Los valores globales
de clave son fixtures diferentes de todas las claves de origen de esta matriz.

El handle fuente se resuelve mediante `0x00967F50` antes y después de la copia.
Sigue devolviendo el origen registrado. Al destruir el destino con `0x00955AE0`,
la tabla, heads, enlace y origen permanecen intactos: el destino no adquirió la
identidad registrada del origen. No hay reservas ni liberaciones durante esa
copia/destrucción porque los buffers están vacíos y el recurso opcional es nulo.

Después se destruye el origen registrado. El destructor retira y libera su enlace;
se comprueba head ya desvinculado y contador todavía uno dentro del callback,
seguido del decremento a cero. El payload destruido conserva los efectos de baja
ya contrastados: `+8 = identificador anterior`, `+0x0C = 0xFFFE`. El handle que
vuelve a resolver la clave anterior devuelve cero y almacena cero.

Cada uno de los 108 casos reserva/libera un enlace mediante llamadas originales.
Los objetos de esta rama usan almacenamiento de fixtures que no se libera por el
destructor: se contrasta su payload sin leer memoria liberada.

## Expansión de un vector con un elemento registrado

En los otros 108 casos el origen registrado ocupa el único elemento de un vector
de capacidad uno, reservado en heap. Se llama al append original `0x004BEB50` con
un objeto externo. La expansión reserva capacidad dos y copia ambos elementos con
el constructor selectivo habitual. Las copias tienen clave global predeterminada
y byte activo cero, como en la rama anterior.

Al destruir el elemento antiguo, la expansión retira su entrada del registro;
después libera el array antiguo y publica el nuevo descriptor. Se comparan el nodo
de registro antes de liberarlo, el payload destruido antes de liberar el array,
y todo el array nuevo. El descriptor todavía apunta al array antiguo durante las
dos liberaciones. Las tablas quedan vacías y siguen vacías al destruir las copias.

**confirmed en este fixture:** la referencia por clave anterior no se reasigna a
una copia. Dos variantes originales contrastan además el estado del handle:

| Entrada | Retorno tras expansión | Primer dword del handle |
| --- | --- | --- |
| `0x00967F10` | cero | conserva el puntero anterior, ya obsoleto |
| `0x00967F50` | cero | se actualiza a cero |

El banco nunca desreferencia el puntero antiguo después de liberar el array.
Comprueba resolución por clave, retorno y bytes de caché. El ejemplo refuta el
modelo de que esta expansión conserva automáticamente identidades y referencias
de objetos registrados. **No prueba** que el juego use normalmente este vector
para su almacén global de POP ni que ese movimiento sea una operación válida de
una partida. Se mantiene abierta esa cuestión de los llamadores.

Cada caso de expansión aporta dos reservas originales —enlace y array nuevo— y
dos liberaciones —enlace y array antiguo—. La limpieza final del array nuevo es
manual, después de ejecutar y contrastar los destructores de sus dos elementos.

## Alcance y recibos

Se comprueban las tablas completas, punteros y contenido de enlaces, registros de
identidad en el payload, handles, orden y contenido de liberación y FS:0 nativo.
Los buffers y catálogos están vacíos; no hay recurso opcional ni regimientos,
inicialización automática de ID, claves duplicadas, partida cargada o concurrencia.
Los handles de propietario están preparados para no resolver objetos ajenos en
esta matriz. No se extrapolan esas condiciones a cualquier objeto registrado.

La fase añade 216 casos, 324 reservas y 324 liberaciones originales. El banco
combinado suma al cerrarla **1.938 casos**, **13.218 reservas** y **10.947
liberaciones** con snapshot. Las fuentes y recibos anteriores están conservados
en `native-growth/baseline-combined-1722/`.

```bash
source research/env.sh
python research/scripts/build_native_growth_probe.py
python research/scripts/run_native_growth_probe.py
python research/scripts/verify_grounding.py
```

El recibo nativo usa `entry: registered_copy_lifecycle` o
`entry: registered_vector_growth`. Tres instrucciones de clave/byte activo de
CPop se añaden al verificador de registro; no se confunden esas comprobaciones de
bytes con la evidencia nativa del ciclo. El gate vincula fuentes y recibos por hash.
