# Contrato Formal: Cálculo Nacional de Infraestructura y Gasto Provincial (CCountry::CalculateNationalInfrastructure)

- **Binario objetivo:** `base-game/v2game.exe`
- **SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x00530C70..0x00530E3B` (`CCountry::CalculateNationalInfrastructure`, 460 bytes)
- **Llamador confirmado:**
  - `0x00538063` (despachador de subsistemas de gasto nacional en `0x00538040`)

---

## 1. Convención de Llamada y Estructura en Memoria

- **Convención:** x86 stdcall:
  - `[ebp + 8]`: puntero a la instancia nacional (`CCountry* country`).
- **Retorno:** void (`ret 4`).
- **Campos actualizados en `CCountry`:**
  - `[country + 0x1A0]`: parte baja de 32 bits del total nacional de infraestructura.
  - `[country + 0x1A4]`: parte alta de 32 bits con signo del total nacional de infraestructura.

---

## 2. Lógica Algorítmica y Etapas de Cálculo

### Etapa 1: Agregación de Unidades Provinciales
Itera secuencialmente sobre el vector de provincias del país (`[country + 0x9D8]` a `[country + 0x9DC]`):
$$\text{total\_units} = \sum_{p \in \text{provinces}} \text{GetProvinceUnits}(p)$$
donde `GetProvinceUnits` (`0x004B8870`) devuelve la capacidad o unidades de infraestructura de cada provincia.

### Etapa 2: Normalización Tecnológica de Edificios/Infraestructura
Itera sobre la lista de entradas activas en `[0x125FDD8]`.
Para cada entrada válida (`flag_39 != 0`):
1. **Factor de inversión / costo tecnológico:**
   $$\text{norm}_1 = \left\lfloor \frac{(\text{val}_{0x234} + \text{val}_{0x230}) \ll 30}{32,768,000} \right\rfloor$$
2. **Factor de modificador de escala:**
   $$\text{norm}_2 = \left\lfloor \frac{\text{val}_{0x238} \ll 30}{32,768,000} \right\rfloor$$
3. **Ponderación:**
   $$\text{term}_i = (\text{norm}_1 \times \text{norm}_2) \gg 15$$
   $$\text{sum\_terms} += \text{term}_i, \quad \text{valid\_count} += 1$$

### Etapa 3: Promedio Ponderado Tecnológico
Si $\text{valid\_count} > 0$:
$$\text{avg\_mod} = \left\lfloor \frac{\text{sum\_terms}}{\text{valid\_count}} \right\rfloor$$
Si $\text{valid\_count} == 0$, se utiliza el valor por defecto cargado en la inicialización (0).

### Etapa 4: Multiplicación Agregada y Bono Base Nacional
Combina las unidades provinciales con el modificador tecnológico medio y agrega el bono base nacional de `[country + 0xBDC]`:
$$\text{prod} = \left\lfloor \frac{(\text{total\_units} \ll 15) \times \text{avg\_mod}}{32,768} \right\rfloor$$
$$[country + 0\text{x}1\text{A0}:0\text{x}1\text{A4}] = \text{prod} + (\text{base\_bonus} \ll 15)$$

---

## 3. Criterio de Verificación

1. **Reverify Estático:**
   - 45 aserciones de instrucciones de código binario contra `base-game/v2game.exe`.
   - Control negativo contra objetivo erróneo con veredicto `REFUTED`.
   - Control dependiente con invalidación formal `INVALIDATED`.
2. **Emulación Dinámica en Unicorn:**
   - Contrastación del modelo exacto en Python `country_infrastructure_model.py` contra la ejecución de los 460 bytes nativos en Unicorn.
   - Fixtures que cubren provincias vacías, provincias múltiples con diversas unidades, entradas tecnológicas activas/inactivas, y bonos base nacionales.
