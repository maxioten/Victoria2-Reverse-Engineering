# Contrato Semántico: Consumo y Saturación de Cuotas de Promoción y Empleo (`CPromotionQuotaManager::ConsumeCapacity`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x004D1020..0x004D119E` (`CPromotionQuotaManager::ConsumeCapacity`, 321 bytes)
- **Llamador verificado:** `0x00958486` en `CPop::Update` (`0x00957EA0`).
- **Subsistema:** Demografía / Movilidad Social, Promoción y Asignación de Empleo en Fábricas y Estratos.

---

## 2. Convención de Llamada y Estructuras de Datos
- **Firma:** `void __thiscall CPromotionQuotaManager::ConsumeCapacity(uint32_t target_key, int32_t* inout_requested_amount)`
- **Registros y Pila:**
  - `EAX`: puntero a la instancia `CPromotionQuotaManager` (`this`).
    - `[manager + 0x60]`: puntero a la lista de cuotas de promoción (`target_list*`).
      - `[target_list + 0xF0]`: inicio del vector de entradas (`entries_begin`).
      - `[target_list + 0xF4]`: fin del vector de entradas (`entries_end`).
      - `[target_list + 0x130]`: raíz del árbol de indexación (`std::_Tree*`).
      - `[target_list + 0x13C]`: arreglo de contadores provinciales.
      - `[target_list + 0x224]`: puntero al siguiente gestor encadenado (`next_manager*`).
  - `[ebp + 8]`: clave / puntero del estrato o empleo destino (`target_key`: uint32).
  - `[ebp + 0xC]`: puntero al remanente de población solicitada (`inout_requested_amount`: int32*).
  - Retorno: `void` (`ret 8`).
- **Estructura de entrada en el vector (`stride = 16` bytes):**
  - `[entry + 0x08]`: identificador/puntero del destino (`target_key` / `target_obj*`).
  - `[entry + 0x0C]`: capacidad disponible restante (`available_capacity`: int32).

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Condiciones de Guarda
Si `manager->target_list == NULL` o si la cantidad solicitada `*inout_requested_amount \le 0`, la rutina finaliza inmediatamente sin consumir población:
$$\text{consumed} = 0$$

### 3.2. Búsqueda y Consumo de Capacidad
1. **Recorrido del vector de destinos:**
   Calcula el número de entradas disponibles:
   $$\text{count} = (\text{entries\_end} - \text{entries\_begin}) \gg 4$$
   Itera linealmente (`stride = 16` bytes).
2. **Comparación de destino:**
   Compara la clave de cada entrada con `target_key` (`cmp ebx, [ebp + 8]`).
3. **Clamping por cuota disponible:**
   Al encontrar el destino:
   $$\text{avail} = \text{entry.available\_capacity}$$
   $$\text{req} = *\text{inout\_requested\_amount}$$
   $$\text{consumed} = \min(\text{req}, \text{avail})$$
4. **Deducción conservativa:**
   - Actualiza el remanente de la población:
     $$*\text{inout\_requested\_amount} = \text{req} - \text{consumed}$$
   - Deduce la capacidad consumida del destino:
     $$\text{entry.available\_capacity} = \text{entry.available\_capacity} - \text{consumed}$$
   - Deduce de la cuota global del estrato o fábrica:
     $$\text{target\_obj.quota} = \text{target\_obj.quota} - \text{consumed}$$
5. **Saturación y Desactivación de Destino:**
   Si la capacidad restante llega a cero o menos (`entry.available_capacity \le 0`), el motor desvincula la entrada del árbol de búsqueda en `[target_list + 0x130]` y la elimina del vector vía `0x004F2760`, impidiendo que posteriores POPs intenten promocionarse a un empleo o estrato ya saturado.

---

## 4. Evidencia y Reproducción
- **Suite de verificación:** `research/scripts/verify_promotion_quota.py`
- **Modelo de referencia:** `research/scripts/promotion_quota_model.py`
- **Artefactos generados:** `research/evidence/generated/promotion-quota/`
  - `claims.json`: 43 afirmaciones formales de instrucciones, saltos y llamadas.
  - `reverify.json`: veredicto `VERIFIED` en las 43 afirmaciones.
  - `negative-controls.json`: control erróneo `REFUTED` y cascada `INVALIDATED`.
  - `emulation.json`: 106 fixtures ejecutados en Unicorn con 0 discrepancias.
- **Reproducción:**
  ```bash
  source research/env.sh
  python research/scripts/verify_promotion_quota.py
  ```
