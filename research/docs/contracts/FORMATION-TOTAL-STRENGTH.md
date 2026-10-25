# Contrato: Determinación Polimórfica de Fuerza Total de Formación Militar (`CArmy::CalculateTotalStrength` y `CNavy::CalculateTotalStrength`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Direcciones de las rutinas:**
  - `CArmy::CalculateTotalStrength`: `0x005D61A0..0x005D61F8` (89 bytes, 29 instrucciones).
  - `CNavy::CalculateTotalStrength`: `0x005D91D0..0x005D91E5` (21 bytes, 9 instrucciones).
- **Vtables (Slot 10 / `+0x28`):**
  - `0x00DF88F4`: Entrada en la tabla virtual de `CArmy` (`0x00DF88CC + 0x28`) que apunta a `0x005D61A0`.
  - `0x00E02FF4`: Entrada en la tabla virtual de `CNavy` (`0x00E02FCC + 0x28`) que apunta a `0x005D91D0`.
- **Llamadores identificados:**
  - `0x0059C48C` y `0x0059C49A` en `CCombat::CalculateAttackerStrengthRatio` (`0x0059C460`), invocados polimórficamente sobre el atacante (`pCombat + 0x10`) y el defensor (`pCombat + 0x14`).
- **Convención de llamada:** `__thiscall` con `ecx = this` (`CArmy*` o `CNavy*`), argumento en pila `[ebp + 8] = int32* out_strength`. Epílogo `ret 4`. Retorna en `eax` el puntero `out_strength`.

---

## 2. Estructura de Memoria y Offsets

### Formación Terrestre (`CArmy`)
- `+0x00`: Puntero a vtable (`0x00DF88CC`)
- `+0x38`: Puntero al primer nodo de la lista enlazada de subunidades (`SubUnitNode*`)
  - `node + 0x00`: `data` (`CRegiment*`)
  - `node + 0x08`: `next` (`SubUnitNode*`, `NULL` al final de la lista)

### Subunidad Terrestre (`CRegiment`)
- `+0x00`: Puntero a vtable (`0x00DF8884`)
- `+0x3C`: Fuerza / Efectivos actuales del regimiento (`regiment->strength`, int32, típicamente en rango $[0, 3000]$)

### Formación Naval (`CNavy`)
- `+0x00`: Puntero a vtable (`0x00E02FCC`)
- `+0x40`: Recuento total de buques de guerra (`ship_count`, int32)

---

## 3. Formulación Algorítmica y Matemática

### 1. Formación Terrestre (`CArmy::CalculateTotalStrength`)
1. **Inicialización en punto flotante:**
   Evalúa el parámetro de inicialización en `0x00E45840` ($0.0005$) escalado por `0x00E45660` ($1000.0$):
   $$\text{init\_val} = \left\lfloor 0.0005 \times 1000.0 \right\rfloor = \left\lfloor 0.5 \right\rfloor = 0$$
   Escribe $0$ en la dirección de salida: `*out_strength = 0`.
2. **Acumulación lineal por lista enlazada:**
   Recorre los nodos de la lista en `[pArmy + 0x38]`:
   Para cada nodo $i$:
   $$\text{*out\_strength} \mathrel{+}= \text{node}_i\text{->regiment->strength}$$
3. **Retorno de puntero:**
   Retorna `eax = out_strength`.

### 2. Formación Naval (`CNavy::CalculateTotalStrength`)
1. **Ponderación demográfica naval:**
   Para armonizar la fuerza de los buques navales con el orden de magnitud de los regimientos terrestres (donde 1 regimiento estándar equivale a $1,000$ hombres):
   $$\text{*out\_strength} = \text{ship\_count} \times 1000$$
   mediante instrucción x86 `imul ecx, ecx, 0x3e8`.
2. **Retorno de puntero:**
   Retorna `eax = out_strength`.

---

## 4. Criterio de Evidencia y Verificación
- Verificación estática con Reverify sobre todas las instrucciones en PE32 de `0x005D61A0..0x005D61F8` y `0x005D91D0..0x005D91E5`.
- Verificación de slots de vtables en `CArmy` (`0x00DF88F4`) y `CNavy` (`0x00E02FF4`).
- Verificación de constantes flotantes en `0x00E45840` y `0x00E45660`.
- Control negativo en target offset desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética, cubriendo ejércitos vacíos, regimientos individuales, múltiples regimientos heterogéneos, armadas vacías, flotas medianas y masivas con 0 discrepancias frente a `formation_total_strength_model.py`.
