# Criterio de evidencia

El proyecto busca reconstruir conocimiento comprobable de Victoria II, no generar una
explicación plausible de todo el binario de una vez.

1. Formular una pregunta concreta y una hipótesis falsable.
2. Identificar el binario por SHA-256 y distinguir file offset, RVA y VA.
3. Extraer bytes, instrucciones, referencias y pseudocódigo con las herramientas.
4. Proponer afirmaciones con alcance explícito. Ejecutarlas mediante reverify cuando el
   tipo de afirmación lo permita; contrastarlas con una herramienta independiente.
5. Conservar recibo, versión, entradas, resultado, contraejemplo y preguntas abiertas.
6. Promover sólo la afirmación comprobada, sin extenderla a la semántica del sistema.

## Fuerza de los resultados

| Resultado | Qué permite afirmar | Qué no demuestra |
| --- | --- | --- |
| Bytes y destino CALL coincidentes | Existe esa instrucción directa en esa ubicación | Que los nombres tentativos de ambas funciones sean correctos |
| Función o arista recuperada por Ghidra | El analizador recuperó ese límite o referencia | Que un CFG heurístico sea completo, especialmente con llamadas indirectas |
| Pseudocódigo | Una representación del análisis de la herramienta | Fuente original, tipos correctos o ausencia de efectos laterales |
| Prueba dinámica | Comportamiento observado con esas entradas y estado | Comportamiento de todas las entradas ni equivalencia general |
| Emulación | Comportamiento del modelo de CPU con ese estado inicial | Comportamiento de APIs, heap, threads o dispositivos no modelados |
| Prueba Z3 | Equivalencia dentro de las expresiones y supuestos declarados | Que ese modelo represente todos los efectos de la rutina real |

Los estados locales son `confirmed`, `inferred` e `hypothesis`.
Los veredictos de reverify se guardan sin traducir `INCONCLUSIVE` o `INVALIDATED` a confirmado.
Sus notas de texto libre no son verificadas. El campo `grounded` o la puntuación de
información tampoco certifican la interpretación semántica de un sistema completo.

## Integración de reverify

`scripts/verify_claims.py` usa el API real, guarda recibos y actualiza `.reverify/ledger/`,
con el SHA-256 del binario como identidad. Ejecuta controles negativos: un destino CALL
deliberadamente erróneo debe dar `REFUTED` y su afirmación dependiente `INVALIDATED`.
La revisión del repositorio se guarda en el inventario del entorno.

El CLI `verify` por sí solo no persiste el ledger en esta revisión; por eso el wrapper
llama explícitamente a `Ledger.record()` y `Ledger.save()`.
No se activaron hooks de rollover ni se modificó la configuración global del asistente.
No se utilizan API keys ni se envía el binario a un modelo o servicio externo.

Capstone, Unicorn, LIEF y Z3 están activos. El backend semántico angr no se instaló:
reverify no puede certificar límites arbitrarios de función usando sólo su fallback.
Ghidra se utiliza para recuperar funciones/xrefs, etiquetando esos resultados como
derivados del analizador hasta contrastarlos. Esto se comprueba con un diagnóstico que
debe conservar `INCONCLUSIVE` cuando no existe un backend capaz de responder.

## Automatización con IA

La IA propone preguntas, scripts, tipos y nombres. Las herramientas aportan evidencia.
Antes de cerrar un bloque, guardar hechos verificados, refutaciones y preguntas abiertas
en archivos; no depender de una narración del chat. Al retomar, leer el ledger y los
artefactos citados, y comprobar el hash antes de reutilizar direcciones.
