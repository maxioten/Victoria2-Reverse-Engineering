# Rutina de actualización seleccionada por fecha

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferida base `0x00400000`. Entrada `0x00957EA0`, RVA `0x00557EA0`.
La referencia externa la llama actualización mensual; el contrato previo de
[selección](POP-SCHEDULE.md) comprueba su filtro por fecha. No se ha trazado aquí
la frecuencia real sobre una partida.

## Cobertura estructural

**confirmed, decodificación acotada bajo el modelo declarado:** desde la entrada hasta
el único retorno normal `0x00958DEC` (`RET 8`), el grafo contiene:

| Medida | Resultado |
| --- | --- |
| Instrucciones alcanzables sintácticamente | 1.147 |
| Bytes cubiertos | 3.912 |
| Puntos de llamada | 71 |
| Llamadas directas | 65 |
| Llamadas indirectas | 6 |
| Operandos de memoria con escritura explícita señalada por Capstone | 185 |

El conteo de bytes coincide con el cuerpo candidato exportado por Ghidra, formado por
`0x00957EA0..0x00958358` y `0x00958360..0x00958DEE`. Los siete bytes entre rangos no se
incluyen por decodificación especulativa. Se comprueba que ninguna instrucción del
grafo se solapa con otra ni abandona el intervalo acotado.

Cada CALL se considera opaco y con retorno normal a la instrucción siguiente. No se
modelan excepciones, callbacks internos, cambios de flujo interprocedurales ni
factibilidad de las ramas. Las seis llamadas indirectas conservan su operando de
registro, sin inventar una clase o destino. Los 185 operandos no constituyen una lista
completa de escrituras: faltan efectos implícitos y todos los efectos de los callees.
Tampoco se atribuyen sus registros base a un objeto por coincidir el desplazamiento.

## Puntos del circuito observados

| Lugar VA | Evidencia local |
| --- | --- |
| `0x00957EC7` | Guarda ECX de entrada en EDI; el código posterior consulta campos del objeto y su contexto `+0x64/+0x68` |
| `0x00957EFC`, `0x00957F80` | Llamadas al refresco de handle ya investigado; el refresco puede escribir su puntero guardado |
| `0x00957FC0` | Flag de contexto `+0x3D9` puede saltar al epílogo después del trabajo inicial |
| `0x00957FDF`, `0x00958014`, `0x00958394` | Wrappers de [transferencia](POP-TRANSFER.md); el núcleo tiene pruebas acotadas y las rutas completas de los wrappers siguen abiertas |
| `0x009581E5` y otros cinco sitios | Llamadas indirectas, incluidas consultas de slot `+0x20` en varias rutas |
| `0x00958293`, `0x0095829B` | Escrituras con desplazamiento `+0x1438`, desde registros distintos; la segunda escribe `0xFFFFD8F0` |
| Diez sitios | Llamadas a la [primitiva de tamaño](POP-SIZE.md) `0x00955FD0` |
| `0x0095823F`, `0x00958563`, `0x00958571` | Llamadas a los helpers con instrucciones de conversión x87/entero |
| `0x00958DD0` | Suma en `[EDI+0x158]` antes del epílogo común |

Los diez sitios de cambio de tamaño están en `0x009584C8`, `0x009584EB`, `0x009587BE`,
`0x009587E1`, `0x00958A81`, `0x00958AA4`, `0x00958C3E`, `0x00958C4F`,
`0x00958C70` y `0x00958DC8`. La lista explícita permite distinguir las rutas que
alcanzan esa misma operación.

Las entradas `0x00B31C00` y `0x00B31C36` no se identifican como RNG. La primera puede
ejecutar `FSTP` y `CVTTSD2SI`; la segunda contiene `FISTP`, `FILD` y correcciones
posteriores. Son evidencia de conversión numérica dependiente de la ruta, no una
demostración de su equivalencia universal ni del modo de redondeo completo. Una
[prueba nativa posterior](FLOAT-CONVERSION.md) contrasta 3.360 conversiones acotadas y
documenta diferencias de anchura, cuantización y atajos de borde. Los
callees restantes todavía pueden consumir azar: no se afirma que la actualización
completa sea determinista o no use RNG.

El C de Ghidra advierte que no pudo seguir completamente el stack y elimina tres
bloques como inalcanzables durante la decompilación. Por eso ese C no se usa como
reconstrucción ejecutable ni como prueba de que las rutas matemáticas se puedan borrar.

## Reproducción y frontera

Con `research/env.sh` cargado desde la raíz:

```bash
python research/scripts/verify_pop_update.py
bash research/scripts/query.sh 0x557ea0
```

Reverify contrasta 23 instrucciones seleccionadas. Artefactos:
`evidence/generated/pop-update/{claims.json,reverify.json,cfg.json}`. El grafo enumera
todos los sitios de llamada y operandos explícitos de escritura; el query conserva
el cuerpo candidato y las advertencias del decompilador.

Pendientes: resolver destinos indirectos, alias y escrituras de todos los callees;
reproducir las ramas de migración/conversión con sus objetos y contextos; auditar x87,
azar y acumuladores; contrastar la actualización entera con una partida real. La
validación de una primitiva de tamaño no valida los 71 puntos de llamada ni autoriza
ejecutar esta rutina en paralelo.
