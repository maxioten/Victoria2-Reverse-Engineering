# Contrato Semántico: Producción Industrial y Consumo de Insumos de Fábricas

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x004DD470..0x004DD5D0` (`CProductionType::ProduceGoods`)
- **Llamadores verificados:**
  - `0x004F3560` en `CStateBuilding::Produce` (fábricas de estados industriales).
  - `0x00484573` en el bucle de producción de mercado.
  - `0x004F18A7`, `0x004F1CA1` en el mantenimiento y balance de fábricas estatales.
- **Subsistema:** Economía / Producción Industrial y Consumo de Insumos.

---

## 2. Convención de Llamada y Estructuras
- **Firma:** `void CProductionType::ProduceGoods(this=EAX, CGoodsPool* market_pool, int goods_id, int max_res, int level, int64_t efficiency_modifier)`
- **Registros y Argumentos:**
  - `EAX`: puntero al descriptor de producción (`CProductionType`).
    - `[eax + 0x20..0x27]`: `base_output` (int64 en punto fijo, escala 32768).
    - `[eax + 0x30..0x37]`: `throughput_modifier` (int64 en punto fijo, escala 32768).
  - `[ebp + 0x08]`: puntero al pool de bienes de la fábrica o provincia.
  - `[ebp + 0x0C]`: identificador del bien producido (`goods_id`).
  - `[ebp + 0x14]`: nivel entero de la fábrica (`factory_level`: int32).
  - `[ebp + 0x18..0x1F]`: modificador de eficiencia de insumos (`efficiency_modifier`: int64).

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Cálculo de Producción Bruta (`effective_output`)
1. Multiplicación de salida base por rendimiento de trabajadores:
   $$\text{step}_1 = \text{FixedPoint\_Multiply}(\text{base\_output}, \text{throughput\_modifier})$$
   Operación x86:
   ```assembly
   0x004DD489: call 0xac9f20  ; FixedPoint_Multiply
   0x004DD49A: shrd ecx, esi, 0xf
   0x004DD4A3: sar  esi, 0xf
   ```
2. Escala por el nivel de la fábrica:
   El nivel entero `level` se promueve a 64 bits con signo (`cdq`) y se escala a punto fijo mediante desplazamiento a la izquierda de 15 bits (`shld edx, eax, 0xf; shl eax, 0xf`):
   $$\text{effective\_output} = \text{FixedPoint\_Multiply}(\text{step}_1, \text{level} \ll 15)$$

### 3.2. Inyección al Mercado
En `0x004DD4C9`, el total producido se añade a la oferta del mercado mundial mediante:
$$\text{CGoodsPool::AddSupply}(\text{goods\_id}, \text{effective\_output})$$

### 3.3. Consumo de Insumos (`effective_input`)
El motor recorre el arreglo de insumos requeridos definidos en `production_types.txt` (`0x004DD4F0..0x004DD5A1`):
Para cada insumo $i$:
1. Si el requerimiento base $\text{input\_base}_i \ne 0$:
   $$\text{step}_{\text{inp}} = \text{FixedPoint\_Multiply}(\text{input\_base}_i, \text{efficiency\_modifier})$$
2. Se escala por el total producido:
   $$\text{input\_consumed}_i = \text{FixedPoint\_Multiply}(\text{step}_{\text{inp}}, \text{effective\_output})$$
3. El insumo consumido se resta del inventario de la fábrica y se suma a la demanda del mercado de dicho bien:
   $$\text{factory\_inventory}_i \mathrel{-}= \text{input\_consumed}_i$$

---

## 4. Grounding y Evidencia
- 28 afirmaciones reverify sobre las instrucciones de multiplicación en punto fijo (`0x00AC9F20`), desplazamientos aritméticos (`shld`, `shrd`, `sar`), llamadas a `CGoodsPool` y bucle de insumos.
- Control negativo erróneo `REFUTED` y cascada `INVALIDATED`.
- Batería de fixtures emulada en Unicorn con 0 discrepancias frente a `factory_production_model.py`.
