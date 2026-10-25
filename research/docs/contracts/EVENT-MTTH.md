# Probabilidad diaria de eventos a partir de MTTH (Mean Time To Happen)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## Función objetivo: `0x008AE380` (`Event_ComputeMTTHProbability`)

La rutina `0x008AE380` calcula la probabilidad diaria de disparo de un evento a partir de su bloque MTTH.
Es invocada desde el escaneo diario de eventos (`EventManager_DailyScan` en `0x008A7CD0`):
- `0x008A7E05`: primer pase de eventos (eventos de país).
- `0x008A7FE6`: segundo pase de eventos (eventos provinciales).

Convención observada: `__stdcall` con 3 argumentos en la pila (12 bytes, `RET 0xC`):
1. `[ebp + 0x08]`: puntero al bloque MTTH (`event + 0xC0`).
2. `[ebp + 0x0C]`: puntero al contexto/scope (país o provincia) pasado a los disparadores de modificadores.
3. `[ebp + 0x10]`: multiplicador de modo o escala de tiempo (`mode`, habitualmente 1).

## Estructura del bloque MTTH

En el objeto MTTH:
- `[this + 0x08]`: valor base del MTTH almacenado en **milisegundos-día / milésimas de día** (\(\text{días} \times 1000\)).
- `[this + 0x0C]`: puntero de inicio del vector de modificadores condicionales.
- `[this + 0x10]`: puntero de fin del vector de modificadores condicionales.

El número de modificadores es \((\text{fin} - \text{inicio}) / 4\) (`sar esi, 2` en `0x008AE395`).
Para cada modificador:
- Se evalúa su método virtual disparador `[vtable + 0x18]` pasando el contexto (`__thiscall`, `ret 4`).
- Si retorna `AL != 0`, se lee el factor en milésimas en `[mod + 0x20]`.
- Se aplica mediante aritmética SSE y CRT:
  \[
  \text{factor\_flotante} = \frac{\text{factor}}{1000.0} + 0.0005
  \]
  Donde \(1000.0\) es el `double` en `0x00E45660` y \(0.0005\) es el `double` de redondeo en `0x00E45840`.
  Se multiplica \(\text{MTTH} \times \text{round}(\text{factor})\) y se divide por 1000 mediante `0x00AC02A0` (`__alldiv`).

## Fórmula de conversión a probabilidad diaria

Una vez procesados los modificadores (o si el vector está vacío), el valor resultante \(\text{ebx}\) representa el MTTH efectivo en milésimas de día.
La rutina ejecuta la conversión en `0x008AE433..0x008AE488`:

1. Se divide \(\text{ebx}\) por 1000 mediante multiplicación por constante mágica (`0x10624DD3` seguido de `sar edx, 6` y corrección de signo):
   \[
   \text{días} = \lfloor \text{ebx} / 1000 \rfloor
   \]
2. **Cota inferior de días (MTTH \(\le 1\) día)**:
   Si \(\text{ebx} \le 1000\) (\(\text{días} \le 1\)), la probabilidad diaria es directamente el 100%:
   \[
   P = 1.000.000 \quad (\text{partes por millón})
   \]
3. **Cálculo ordinario (MTTH \(> 1\) día)**:
   Se multiplica `mode` por \(1.000.000\) y se divide entre los días enteros:
   \[
   P = \left\lfloor \frac{\text{mode} \times 1.000.000}{\text{días}} \right\rfloor
   \]
4. **Acotación (Clamping)**:
   - Si \(P > 1.000.000\), se acota a \(1.000.000\).
   - Si \(P \le 0\), se acota a \(1\) (mínimo 1 en un millón, asegurando que un evento habilitado con MTTH muy grande nunca tenga probabilidad 0 absoluta).

## Conexión con el generador de números aleatorios (RNG)

Tras obtener \(P \in [1, 1.000.000]\), el llamador `EventManager_DailyScan` en `0x008A7E3C` extrae un entero aleatorio del generador Mersenne Twister en `0x00F0ECF0` (contrastado en el contrato [RNG](RNG.md)). Si el valor extraído (\(\text{roll} \pmod{1.000.000}\)) es menor que \(P\), el evento se dispara.

## Verificación empírica

* **Reverify**: 44 afirmaciones de bytes, instrucciones y sitios CALL verificadas.
* **Controles negativos**: rechazo comprobado de constantes falsas con cascada de invalidación dependiente.
* **Unicorn Engine**: 602 fixtures emulados cubriendo valores de MTTH desde 0 hasta 2.000.000 de días, fracciones de milésimas de día, modos de 1 a 100, con 0 discrepancias frente a `mtth_model.py`.
