# Contrato Formal: Transferencia Demográfica y Umbral Mínimo de POPs (POP-TRANSFER-THRESHOLD)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutinas objeto:**
  - Canal de Promoción: `0x009584A6..0x009584FB` en `CPop::Update`
  - Canal de Asimilación Cultural: `0x0095879C..0x009587F1` en `CPop::Update`
  - Canal de Conversión Religiosa: `0x00958A5F..0x00958AB4` en `CPop::Update`
- **Rutina auxiliar acoplada:** `0x00955FD0` (`CPop::SetSize`)

---

## 1. Mapeo de Registros y Estructura en Memoria

| Parámetro / Entidad | Registro / Offset | Descripción |
|---|---|---|
| `source_pop` | `EDI` (`CPop*`) | Instancia del POP emisor/origen |
| `target_pop` | `ESI` (`CPop*`) | Instancia del POP receptor/destino |
| `source_size` | `EBX` (`[edi + 0x58]`) | Población base previa del POP origen |
| `pop_type` | `EDX` (`[edi + 0x68]`) | Descriptor del estrato demográfico |
| `min_survival_threshold` | `[pop_type + 0x3C8]` | Umbral mínimo para evitar micro-POPs |
| `slot_delta` | `[edi + 0x190/0x194/0x198]` | Cantidad calculada para el canal |
| `stat_accumulator` | `[pop + 0x164 / 0x16C]` | Acumulador de cambio neto del POP |

---

## 2. Lógica Algorítmica y Umbral de Supervivencia

1. **Evaluación de Remanente Poblacional:**
   $$\text{rem} = \text{source\_size} - \text{requested\_delta}$$
2. **Clamping por Umbral Mínimo (Absorción Forzada de Micro-POPs):**
   $$\text{effective\_delta} = \begin{cases}
   \text{source\_size} & \text{si } \text{rem} < \text{pop\_type.min\_threshold} \ ([\text{edx} + 0\text{x}3\text{C8}]) \\
   \text{requested\_delta} & \text{en otro caso}
   \end{cases}$$
   *Razón de diseño del motor:* Si la salida demográfica dejase un remanente menor al umbral mínimo
   del tipo de estrato (típicamente $10$ a $100$ habitantes), el juego absorbe la totalidad de la población
   hacia el destino, extinguiendo el POP origen para evitar la proliferación descontrolada de micro-POPs inviables.

3. **Deducción en POP Origen:**
   $$\text{new\_source\_size} = \text{source\_size} - \text{effective\_delta}$$
   $$\text{CPop::SetSize}(\text{source\_pop}, \text{new\_source\_size})$$
   $$\text{source\_pop.accumulator} += (\text{new\_source\_size} - \text{source\_size})$$

4. **Incremento en POP Destino:**
   $$\text{target\_old\_size} = \text{target\_pop.size}$$
   $$\text{new\_target\_size} = \text{target\_old\_size} + \text{effective\_delta}$$
   $$\text{CPop::SetSize}(\text{target\_pop}, \text{new\_target\_size})$$
   $$\text{target\_pop.accumulator} += (\text{clamped\_target\_size} - \text{target\_old\_size})$$

5. **Conservación de la Masa:**
   A menos que el POP destino sature la cota absoluta del motor ($2,000,000$ habitantes),
   el decremento en el origen iguala exactamente el incremento en el destino:
   $$\Delta_{\text{source}} + \Delta_{\text{target}} = 0$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 48 aserciones de código binario contra los 3 canales en `base-game/v2game.exe`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `pop_transfer_threshold_model.py` contra el fragmento binario de los 3 canales.
   - Fixtures que cubren remanente superior al umbral, remanente inferior al umbral (absorción total forzada), igualdad exacta, destino en 0, y saturación en $2,000,000$.
