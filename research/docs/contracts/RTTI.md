# RTTI y nombres de clases del ejecutable

Perfil SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
Base preferida VA `0x00400000`; RVA = VA − base.

`scripts/inventory_rtti.py` busca nombres decorados de clases, comprueba las palabras
anteriores del TypeDescriptor y sigue estructuras compatibles con el RTTI x86 de MSVC.
El esquema de 20 bytes del CompleteObjectLocator y los primeros 24 bytes del descriptor
de base se contrastaron con `RTTI4DataType` y `RTTI1DataType` de Ghidra 12.1.4 instalado.

El inventario recupera **1.519 candidatos a TypeDescriptor**, **1.500 candidatos
consistentes a CompleteObjectLocator** y **1.500 candidatos a vtable**. No es una medida
de cobertura completa: hay clases sin RTTI o sin una vtable localizada, métodos no
virtuales y rutas de herencia que necesitan análisis adicional. El número de entradas
ejecutables consecutivas de una vtable no certifica por sí solo su longitud completa.

## CPop

**confirmed, bytes y enlaces seleccionados:**

| Elemento | VA |
| --- | --- |
| TypeDescriptor | `0x00F11410` |
| Nombre literal | `.?AVCPop@@`, desde `0x00F11418` |
| CompleteObjectLocator | `0x00E67228` |
| ClassHierarchyDescriptor | `0x00E4D0C8` |
| Comienzo candidato de vtable | `0x00E36428` |

La palabra anterior a la vtable apunta al locator, que apunta al descriptor de nombre.
La vtable coincide con el valor escrito al comienzo de la rutina candidata a destructor
`0x00955AE0`. Esto vincula esa escritura con el nombre compilado `CPop`; no identifica
todos los efectos de la rutina ni sustituye la prueba de su comportamiento.

Los registros de la jerarquía contienen, en orden, `CPop` con dos bases contenidas,
`CReferenceObject` con una y `CPersistent` con cero. En estos tres registros el PMD leído
es `{mdisp=0,pdisp=-1,vdisp=0}` y los atributos son `0x40`. La relación de herencia se
interpreta a partir del esquema MSVC; el tamaño de esas clases no se deduce aquí.

## Especialización CDataSpread

El TypeDescriptor VA `0x00F11440` contiene literalmente:

```text
.?AV?$CDataSpread@V?$fixed_point@_J$0DA@$0P@@fpml@@H$0GE@@@
```

Su locator está en `0x00E4D104`, jerarquía en `0x00E4D118` y vtable candidata en
`0x00DFD2CC`. La jerarquía contiene esta especialización y `CPersistent`.
Los seis primeros punteros ejecutables consecutivos son `0x004BE9E0`, `0x009A29F0`,
`0x004BE5B0`, `0x009A2A90`, `0x004BE700` y `0x004010C0`.

**inferred:** el nombre decorado es compatible con la especialización de fixed point
de 64 bits, parámetros 48 y 15 y escala de distribución 100 de la referencia externa.
La rutina no virtual `0x004BE780` no aparece entre esos seis punteros; su contrato de
cálculo se prueba por separado en [distribución](DISTRIBUTION.md). No se asigna cada
llamador a una clase sólo porque tenga un vector con el mismo desplazamiento.

## Reproducción y límites

Cargar `research/env.sh` y ejecutar `python research/scripts/inventory_rtti.py`.
Seis checks de reverify comprueban los nombres, locators y palabras anteriores a las
dos vtables seleccionadas; quince checks adicionales contrastan el enlace con el
código de copia, destrucción y asignación de nodos. El resto del inventario son candidatos obtenidos por un
parser, no nuevos veredictos semánticos. Recibos:
`evidence/generated/rtti/{claims.json,reverify.json,selected.json,inventory.json}`.
Los límites de búsqueda de nombres, bases y slots se conservan en el inventario.

La investigación de referencias añadió CRegiment y CSubUnit a la selección: siete
checks de nombres/enlaces/slot y once de instrucciones del circuito de limpieza.
La selección actual suma **39 checks**. El [contrato de referencias](POP-REGIMENTS.md)
separa esa identidad compilada del tipo real de las instancias durante una partida.

El valor `0x00E3A544`, escrito después durante la limpieza, tiene cero en la palabra
anterior y no satisface este mismo enlace a locator. No se le asigna una clase a partir
de esa escritura sin evidencia adicional.

## Payload CPop y nodo contenedor

**confirmed, instrucciones:** el creador de nodos en `0x004BE140` solicita `0x288`
bytes, llama a `0x00955450` para copiar el payload y después escribe los enlaces en
`+0x278`, `+0x27C` y la marca en `+0x280`. La rutina de copia escribe la vtable CPop
en `0x009554A9` y alcanza un dword del payload en `+0x274`. El destructor de elementos
contiguos en `0x004BE320` avanza `0x278` bytes por elemento.

**inferred:** estos enlaces pertenecen a la extensión del nodo contenedor, después de
un payload CPop de 632 bytes; no deben mezclarse automáticamente con los campos de
la clase CPop. La asignación del nodo mide 648 bytes. Se conservan como desconocidos
los siete bytes posteriores a la marca, sin asegurar que sean todos padding ni atribuir
al nodo una declaración C++ original.

La primera entrada de la vtable CPop, `0x004A8230`, llama a `0x00955AE0` y sólo llama
al wrapper de liberación si el bit 0 del argumento de pila está activo. Eso conecta el
slot virtual con la limpieza ya investigada; la vida y propiedad de cada instancia
todavía se deben contrastar en sus llamadores.

La copia del payload prepara las regiones `+0x74` y `+0x9C` y llama a `0x00955980`.
Esta rutina escribe `0x00DFD2CC` en su destino, la vtable vinculada a la especialización
CDataSpread. Esto refuerza la atribución del tipo del contenedor, manteniendo pendiente
la semántica concreta de sus distribuciones.
