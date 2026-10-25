# Contrato Formal: Actualización de Tamaño y Clamping de POPs (CPop::SetSize)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00955FD0..0x00956054` (`CPop::SetSize`, 133 bytes)
- **Llamadores confirmados:**
  - `0x009584C8` (promoción: deducción de POP origen)
  - `0x009584EB` (promoción: incremento en POP destino)
  - `0x009587BE` (asimilación cultural: deducción de POP origen)
  - `0x009587E1` (asimilación cultural: incremento en POP destino)
  - `0x00958A81` (conversión religiosa: deducción de POP origen)
  - `0x00958AA4` (conversión religiosa: incremento en POP destino)

---

## 1. Convención de Llamada y Firma

- **Convención:** Mixta con paso en registros:
  - `ESI`: puntero a la instancia `CPop` (`this`).
  - `EAX`: nuevo tamaño objetivo de población (`int32 new_size`).
- **Retorno:** void (EAX, ECX, EDX volátiles; EBX, ESI, EDI preservados según ABI x86 stdcall/cdecl).
- **Stack frame:** 8 bytes locales (`[ebp - 4]` aloja la variable local `int32 delta`).

---

## 2. Lógica Algorítmica y Cotas Numéricas

1. **Clamping de Rango Absoluto de Población:**
   $$\text{clamped} = \begin{cases} 
   0 & \text{si } \text{new\_size} < 0 \\
   2,000,000 & \text{si } \text{new\_size} > 2,000,000 \ (0\text{x}1E8480) \\
   \text{new\_size} & \text{en otro caso}
   \end{cases}$$
   *Evidencia:* Las instrucciones `0x00955FDA test edi, edi; jns ...; xor edi, edi` y `0x00955FE2 cmp edi, 0x1e8480; jle ...; mov edi, 0x1e8480` acotan el tamaño admisible de un POP individual entre $0$ y $2,000,000$ habitantes.

2. **Bifurcación por Tipo de Estrato (`pop_type->flag_40`):**
   - El descriptor de tipo reside en `pop_type = [esi + 0x68]`.
   - Si `pop_type->flag_40 == 0`:
     - El POP no participa en la gestión de cuotas ni genera desbordamientos salientes.
     - Se actualiza directamente `[esi + 0x60] = clamped`.
     - Salta a la fase de actualización del historial.
   - Si `pop_type->flag_40 != 0`:
     - Se compara `clamped` contra el tamaño base previo `[esi + 0x60]`.
     - Si $\text{clamped} \ge \text{tracked\_size}$ (crecimiento o estabilidad): no hay población saliente; salta a la fase de historial.
     - Si $\text{clamped} < \text{tracked\_size}$ (disminución):
       - Se calcula $\Delta = \text{tracked\_size} - \text{clamped}$.
       - Se invoca `0x004EE550(&delta, table_entry, this)` para registrar la salida provincial.
       - Se invoca `0x004D1020(this, &delta, this->province->quota_manager)` para consumir las cuotas de absorción correspondientes.

3. **Rotación del Historial de Población:**
   - Guarda el tamaño previo: $\text{prev} = [esi + 0x58]$.
   - Desplaza el historial de dos días:
     $$[esi + 0x5C] = \text{prev}$$
     $$[esi + 0x58] = \text{clamped}$$
   - **Caso Base de Nacimiento / Primer Día:**
     - Si $\text{prev} == 0$, el POP no tiene historial previo y se fija:
       $$[esi + 0x5C] = \text{clamped}$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 36 aserciones de código binario contra `base-game/v2game.exe`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo exacto en Python `pop_set_size_model.py` contra la ejecución de los 133 bytes nativos.
   - 100+ combinaciones de casos límite (negativo, cero, cota máxima 2,000,000, desbordamiento, flag_40 habilitado/deshabilitado, primer día vs histórico).
