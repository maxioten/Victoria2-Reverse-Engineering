# Evaluación de ponderación de opciones de eventos por la IA (`ai_chance`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## Función objetivo: `0x008AEB00` (`EventOption_EvaluateAIChance`)

La rutina `0x008AEB00` calcula el peso o probabilidad ponderada de una opción de evento para un país controlado por la IA.
Es invocada dos veces por cada opción elegible desde `Event_Fire` (`0x008A8120`):
1. `0x008A8268`: suma el peso total acumulado \(S = \sum w_i\) de todas las opciones.
2. `0x008A8325`: recorre las opciones acumulando pesos hasta que una tirada uniforme \(r \in [0, 99]\) es superada por el porcentaje acumulado.

Convención: `__stdcall` con 3 argumentos (12 bytes, `RET 0xC`):
- `[ebp + 0x08]`: puntero al bloque `ai_chance` de la opción (`option + 8`).
- `[ebp + 0x0C]`: puntero de salida de 32 bits con signo (`int *out`).
- `[ebp + 0x10]`: puntero al contexto/scope de ejecución del evento (`ctx`).
Devuelve en `EAX` el puntero de salida `[ebp + 0x0C]`.

## Estructura del bloque `ai_chance` (`option + 8`)

- `[this + 0x08]`: peso base entero `base_val` (escalado en milésimas / permille, habitualmente 1000 = 1.0).
- `[this + 0x0C]`: puntero al inicio del vector de modificadores (`modifier_vector`).
- `[this + 0x10]`: puntero al fin del vector de modificadores.
- `[this + 0x1C]`: multiplicador final `multiplier` (entero en milésimas, habitualmente 1000).

El número de modificadores es \((\text{fin} - \text{inicio}) / 4\) (`sar ecx, 2` en `0x008AEB15`).

### Estructura de cada modificador

- `[mod + 0x08]`: inicio del vector de condiciones/disparadores.
- `[mod + 0x0C]`: fin del vector de condiciones/disparadores.
- `[mod + 0x20]`: factor de multiplicación del modificador en milésimas con signo (`factor`).

Para cada condición:
- Invoca el método virtual `[cond_vtable + 0x18]` con convención `__thiscall`, `RET 4`, pasando `ctx`.
- **Cortocircuito en falso (`0x008AEB61..0x008AEB63`)**: Si cualquier condición devuelve `AL == 0`, se omite inmediatamente el modificador completo.
- Si todas las condiciones son verdaderas:
  \[
  v_{k+1} = \left\lfloor \frac{v_k \times \text{factor}}{1000} \right\rfloor
  \]
  Calculado con `imul` de 64 bits y división por 1000 vía `0x00AC02A0` (`__alldiv`).
- **Cortocircuito en cero o negativo (`0x008AEB8D..0x008AEB8F`)**: Si \(v_{k+1} \le 0\), la rutina interrumpe inmediatamente el bucle de modificadores restantes (`jle 0x8aeb9d`).

### Fase de multiplicador (`0x008AEBA3`)

Al concluir los modificadores (o si el vector de modificadores está vacío):
\[
*out = \left\lfloor \frac{\text{multiplier} \times v}{1000} \right\rfloor
\]
Almacena el resultado en `*[ebp + 0x0C]` y retorna dicho puntero en `EAX`.

## Verificación empírica

* **Reverify**: 33 afirmaciones de bytes, instrucciones y los dos sitios CALL en `Event_Fire` verificadas.
* **Controles negativos**: comprobación de rechazo de objetivo CALL erróneo con invalidación en cascada dependiente.
* **Unicorn Engine**: 97 fixtures emulados con el código máquina original cubriendo casos sin modificadores, con modificadores verdaderos y falsos, condiciones múltiples (todas verdaderas, una falsa, todas falsas), acumulación compuesta, cortocircuito en 0 y valores negativos, con **0 discrepancias** frente a `ai_chance_model.py`.
