# Contrato: Posicionamiento y Factor de Fuerza en Combate Naval (`CNavalCombat::CalculateForceRatio`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x005AB710..0x005AB75F` (80 bytes, 29 instrucciones).
- **Vtable slot 6 (`+0x18`):**
  - `0x00E02450`: Entrada en la tabla de métodos virtuales de `CNavalCombat` (`0x00E02438 + 0x18`).
- **Convención de llamada:** `__thiscall` con `ecx = pNavalCombat`, argumento en pila `[esp + 4] = int *out_ratio`. Retorno en `eax` con el puntero `out_ratio`, epílogo `ret 4`.

---

## 2. Estructura de Memoria y Offsets

### Objeto `CNavalCombat`
- `+0x00`: Puntero a vtable (`0x00E02438`)
- `+0x18`: Puntero a la provincia marítima de combate `pProvince` (`CProvince*`)

### Objeto `CProvince` (Zona Marítima)
- `+0x114`: Penalización de congestión / posicionamiento de zona marítima (`sea_zone_penalty`, int32 en milésimas)

---

## 3. Formulación Algorítmica y Matemática

A diferencia del combate terrestre (`CLandCombat`, que calcula la masa proporcional de infantería/caballería en milésimas), el combate naval sobrescribe polimórficamente el slot 6 (`+0x18`) para derivar la efectividad de posicionamiento de la flota a partir de las restricciones de la zona marítima:

1. **Lectura y Discretización:**
   Lee la penalización de la provincia marítima $P_{\text{sea}}$ en `[pProvince + 0x114]`.
   Aplica división entera por 1000 optimizada por compilador con el multiplicador mágico $\text{0x10624DD3}$ y desplazamiento aritmético:
   $$Q = \left\lfloor \frac{P_{\text{sea}}}{1000} \right\rfloor$$
   $$\text{truncated} = Q \times 1000$$

2. **Cómputo del Margen Operativo:**
   Resta la penalización truncada a la base operativa máxima de 100,000 milésimas ($100.0\%$ con 3 órdenes de precisión):
   $$\Delta = 100,000 - \text{truncated}$$

3. **Escalado de Precisión de 64 bits:**
   Multiplica $\Delta$ por 1000 mediante llamada al helper de CRT `_allmul` (`0x00AC9F20`):
   $$\text{prod} = \Delta \times 1000$$
   Divide entre la base 100,000 mediante llamada al helper de CRT `_alldiv` (`0x00AC02A0`):
   $$\text{ratio} = \left\lfloor \frac{\text{prod}}{100,000} \right\rfloor = \left\lfloor \frac{(100,000 - \text{truncated}) \times 1000}{100,000} \right\rfloor$$

4. **Escritura y Retorno:**
   Almacena `*out_ratio = ratio` y retorna el puntero de salida en `eax`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las 29 instrucciones en PE32 de `0x005AB710..0x005AB75F`.
- Verificación de slot de vtable (`bytes_at`) en `CNavalCombat` (`0x00E02450`).
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo zona despejada ($P=0$), penalizaciones medias (20%, 50%), saturación total (100%) y sobrecargas negativas/positivas con 0 discrepancias frente a `naval_combat_ratio_model.py`.
