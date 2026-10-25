# Contrato: Compuerta de Financiación con Margen de Reserva del 110% en Proyectos de Construcción (`CBuildingProject::UpdateFundingStatus`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Dirección VA:** `0x004A4EB0..0x004A4F2E` (127 bytes, 51 instrucciones)
- **Símbolo inferido:** `CBuildingProject::UpdateFundingStatus` (evaluador de necesidad de financiación de proyectos de construcción industrial e infraestructura)
- **Constante flotante de buffer:** `0x00E45BA0` (`36045.30078125` $\to 36045$, razón $36045 / 32768 \approx 1.100006$)
- **Llamadores confirmados:**
  - `0x004A4FED` en `CBuildingProject::UpdateProgressAndFunding`
  - `0x004A5005` en `CBuildingProject::UpdateProgressAndFunding`
  - `0x005887A6` en `CCountry::DailyInvestmentTick`

---

## 2. Convención de Llamada y Estructura del Objeto
- **Convención:** `thiscall` con puntero `this` recibido en el registro `esi`.
- **Estructura del Proyecto (`CBuildingProject`):**
  - `+0x60` (DWORD): Parte baja (bits 0..31) de los fondos invertidos acumulados (punto fijo 15 bits).
  - `+0x64` (DWORD): Parte alta con signo (bits 32..63) de los fondos invertidos acumulados.
  - `+0x7C` (DWORD): Etapa o estado del proyecto (`stage`):
    - `0`: Fase inicial / preparación de obra.
    - `1`: Fase de aprovisionamiento de materiales.
    - `2`: Fase intermedia bloqueada / espera.
    - `3`: Fase de construcción activa / ampliación.
    - `4`: Proyecto finalizado o clausurado.
  - `+0x80` (BYTE): Indicador booleano de necesidad de fondos (`needs_funding`):
    - `1`: El proyecto requiere fondos adicionales (abierto a inversión de capitalistas o subsidio estatal).
    - `0`: El proyecto tiene cubierto su requerimiento (suficiencia financiera o clausura).

---

## 3. Comportamiento y Algoritmo Exacto

1. **Discriminación de etapa del proyecto (`stage = [esi + 0x7C]`):**
   - Si `stage < 0` o `stage == 2` o `stage >= 4`:
     - Salta a la rama terminal rápida `0x004A4F1E`.
     - Si `stage == 4` (proyecto completado): asigna `needs_funding = 0`.
     - Si `stage != 4` (etapas anómalas o etapa 2): asigna `needs_funding = 1`.
   - Si `stage \in {0, 1, 3}` (etapas activas con demanda de capital):
     - Continúa en la ruta de cálculo métrico con buffer en `0x004A4EC8`.

2. **Cálculo del umbral de reserva del 110%:**
   - Invoca a `0x004A5020(this, &cost_out)` para recuperar el costo base total requerido ($C$, entero de 64 bits).
   - Carga la constante de doble precisión en `0x00E45BA0` ($36045.30078125$) y la trunca a entero de 64 bits mediante `_ftol2` (`0x00B31C36`), obteniendo el multiplicador exacto $36045$.
   - Multiplica el costo base por $36045$ invocando `_allmul` (`0x00AC9F20`):
     $$\text{raw\_prod} = C \times 36045$$
   - Escala el producto dividiendo por el factor de punto fijo $2^{15} = 32768$ mediante desplazamiento aritmético a la derecha:
     $$\text{threshold} = \text{raw\_prod} \gg 15$$
     Esto impone un colchón financiero estricto del $+10.00\%$ sobre el costo base de la obra.

3. **Comparación lexicográfica de 64 bits:**
   - Compara con signo la dword alta: `cmp [esi + 0x64], edx`.
     - Si `high > edx`: fondos suficientes $\to$ salta a `0x004A4F11` (`needs_funding = 0`).
     - Si `high < edx`: fondos insuficientes $\to$ salta a `0x004A4F01` (`needs_funding = 1`).
     - Si `high == edx`: compara sin signo la dword baja `cmp [esi + 0x60], eax`.
       - Si `low >= eax`: fondos suficientes $\to$ `needs_funding = 0`.
       - Si `low < eax`: fondos insuficientes $\to$ `needs_funding = 1`.

4. **Escritura del estado:**
   - Escribe el byte resultante en `[esi + 0x80]` y retorna con `eax \in {0, 1}`.

---

## 4. Garantías de Evidencia
- **Reverify:** 54 afirmaciones formales sobre el flujo de control, llamadas a `0x004A5020`, `_ftol2`, `_allmul`, accesos a offsets `+0x60`, `+0x64`, `+0x7C`, `+0x80` y la constante en `0x00E45BA0`.
- **Control Negativo e Invalidación en Cascada:**
  - Control negativo con offset incorrecto o constante truncada refutado (`REFUTED`).
  - Claim dependiente invalidado (`INVALIDATED`).
- **Emulación Dinámica con Unicorn:**
  - 130+ fixtures cubriendo todas las etapas ($-1, 0, 1, 2, 3, 4, 5$), fondos negativos, exactamente iguales al umbral, umbral $\pm 1$, desbordamiento de 32 bits en fondos, y costos nulos o extremos.
  - 0 discrepancias frente a `project_buffer_model.py`.
