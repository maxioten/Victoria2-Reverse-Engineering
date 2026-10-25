# Contrato Formal: Despachador de Modificadores Provinciales y de Líder (PROVINCE-MODIFIER-DISPATCH)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x004D3FF5..0x004D4067` en `CProvince::UpdateModifiers` (VA base `0x004D3BB0`)
- **Tabla de saltos canónica:** `0x004D41F0..0x004D4210` (8 punteros de 32 bits)

---

## 1. Convención de Registros y Mapeo de Jump Table

| Parámetro | Registro / Offset | Descripción |
|---|---|---|
| `receiver_obj` | `ESI` (`[esi + 0x280]`) | Objeto acumulador de modificador |
| `source_obj` | `ECX` (`[ecx + 0x30]`) | Objeto emisor de modificadores |
| `modifier_raw` | `[edx + 0x1404]` | Tipo de modificador numérico (1 a 8) |
| `jump_table` | `0x004D41F0` | Tabla de saltos indexada por `(modifier_raw - 1)` |

### Entradas de la Tabla de Saltos (`0x004D41F0`):

| Índice | Destino RVA | Dirección VA | Campo Leído | Descripción |
|---|---|---|---|---|
| 0 | `0x000D400B` | `0x004D400B` | `[table + 0x524]` | Modificador slot 0 |
| 1 | `0x000D4016` | `0x004D4016` | `[table + 0x528]` | `attrition_mod` (Desgaste/Atrito) |
| 2 | `0x000D4021` | `0x004D4021` | `[table + 0x52C]` | Modificador slot 2 |
| 3 | `0x000D402C` | `0x004D402C` | `[table + 0x530]` | Modificador slot 3 |
| 4 | `0x000D4037` | `0x004D4037` | `[table + 0x534]` | Modificador slot 4 |
| 5 | `0x000D4042` | `0x004D4042` | `[table + 0x538]` | Modificador slot 5 |
| 6 | `0x000D404D` | `0x004D404D` | `[table + 0x53C]` | Modificador slot 6 |
| 7 | `0x000D4058` | `0x004D4058` | `[table + 0x540]` | Modificador slot 7 |

---

## 2. Lógica Algorítmica y Acumulación

1. **Decodificación del Índice de Modificador:**
   $$\text{idx} = \text{modifier\_type} - 1$$
2. **Guarda de Límites:**
   Si $\text{unsigned}(\text{idx}) > 7$, salta a `0x004D4067` sin alterar el acumulador.
3. **Despacho Indirecto e Indexación de Tabla:**
   Salta a $\text{jump\_table}[\text{idx}]$, donde lee `[source->table + 0x524 + idx * 4]`.
4. **Acumulación Aditiva:**
   $$[esi + 0\text{x}280] = [esi + 0\text{x}280] + \text{slot\_value}$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 35 aserciones de instrucciones binarias y entradas de la tabla de saltos contra `base-game/v2game.exe`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo formal en Python `province_modifier_dispatch_model.py` contra la ejecución nativa de los 8 caminos del switch y casos fuera de rango.
   - Fixtures exhaustivos cubriendo índices $0..7$, valores fuera de rango ($< 1$, $> 8$), y valores positivos/negativos de cada slot de modificador.
