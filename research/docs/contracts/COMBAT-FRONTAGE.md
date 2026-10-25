# Contrato: Determinación de Ancho de Frente de Combate (`CCombat::CalculateFrontage`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059C520..0x0059C624` (261 bytes, 89 instrucciones).
- **Puntos de llamada identificados (xrefs):**
  - Despliegue de regimientos tácticos: `0x0059ACE8`, `0x0059B19C`, `0x0059B9BD`.
  - Renderizado de interfaz y tooltip de batalla: `0x00786601`, `0x00786A56`, `0x0082B1C0`.
- **Convención de llamada:** `__stdcall` con argumento `pCombat` en la pila (`[esp + 4]`), retorno en `eax` con el número entero de regimientos/columnas en el frente, epílogo `ret 4`.

## 2. Descripción Funcional
Calcula el ancho máximo de la línea de combate (frente táctico) disponible en una batalla terrestre en función del avance tecnológico de los participantes y el terreno provincial:

1. **Inicialización de Frente Base:**
   - Inicializa el frente mínimo tentativo en $30,000$ milésimas ($30.0$ unidades de combate, `0x7530`).
   - Lee el frente base global configurado en el gestor de *defines* (`0x012586DC` $\to$ offset `+0x20` $\to$ offset `+0x0C`, típicamente $30,000$).

2. **Iteración de Países Participantes (Bando Atacante y Defensor):**
   - Recorre el vector de países en el bando atacante (`[pCombat + 0x10]`, offsets de iterador `+0x34` a `+0x38`, tuplas de 8 bytes con `country_id` en `+0x04`).
   - Para cada país $i$:
     - Obtiene la estructura de modificadores tecnológicos en `[country_i + 0xBCC]`.
     - Lee el modificador de frente tecnológico en `+0x38` ($\Delta_{\text{tech}} \le 0$).
     - Calcula el frente efectivo del país:
       $$\text{frontage}_i = \text{base\_frontage} + \Delta_{\text{tech}}$$
     - Aplica piso inferior de tecnología: $\text{frontage}_i = \max(2000, \text{frontage}_i)$ ($2.0$ unidades de combate).
     - Actualiza el mínimo global del combate: $\text{min\_frontage} = \min(\text{min\_frontage}, \text{frontage}_i)$.
   - Recorre el vector de países del bando defensor (`[pCombat + 0x14]`) aplicando exactamente la misma lógica de mínimo y clamping.
   - **Regla Victoria II:** El ancho de frente lo impone el participante con mayor nivel tecnológico (menor frente).

3. **Modificación por Terreno Provincial:**
   - Accede a la provincia de combate en `[pCombat + 0x18]`.
   - Lee la definición de terreno en `[province + 0x5C]` $\to$ modificador en `+0x14` $\to$ modificador de frente en `+0x94` ($\Delta_{\text{terrain}}$ en milésimas, e.g. $-500$ para $-50\%$).
   - Aplica el escalado de terreno en aritmética de 64 bits con llamada a `_alldiv` (`0x00AC02A0`):
     $$\text{scaled} = \left\lfloor \frac{\text{min\_frontage} \times (1000 + \Delta_{\text{terrain}})}{1000} \right\rfloor$$
   - Aplica piso absoluto post-terreno:
     $$\text{effective} = \max(2000, \text{scaled})$$

4. **Conversión a Columnas de Despliegue:**
   - Convierte el valor en milésimas a número entero de regimientos desplegables mediante multiplicación mágica optimizada por el compilador:
     $$\text{magic} = \text{0x10624DD3} \quad (\approx 274877907)$$
     $$\text{slots} = (\text{effective} \times \text{magic}) \gg 38 = \left\lfloor \frac{\text{effective}}{1000} \right\rfloor$$
   - Retorna `slots` en `eax` (e.g. valores enteros típicos entre 2 y 30).

## 3. Criterio de Evidencia y Verificación
- Catálogo de 89 afirmaciones Reverify cubriendo cada instrucción de `0x0059C520..0x0059C624`.
- Afirmaciones de llamadas externas relativas (`_alldiv` en `0x00AC02A0`).
- Afirmación de punto de llamada de integración táctica en `0x0059B19C`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética con 0 discrepancias frente a `combat_frontage_model.py`.
