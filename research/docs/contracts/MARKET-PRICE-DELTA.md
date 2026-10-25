# Dinámica y acotación del paso diario de precios de mercado (`Market_PriceDelta`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## 1. Bloque objetivo: `0x00482B4E..0x00482C40` dentro de `0x00482930`

En la actualización diaria de la economía de mercado (`0x00482930`), el motor calcula el ajuste diario de precio para cada tipo de bien en función de la oferta y la demanda agregadas.

## 2. Relación de Oferta / Demanda y Elasticidad

1. **Razón de mercado (`0x00482B4E..0x00482B58`)**:
   - Lee `supply` en `[ebx + 0x218 + idx*8]` y `demand` en `[ebx + 0x50 + idx*8]`.
   - Si `demand <= 0`, no se modifica el precio del bien.
   - Si `demand > 0`, escala la oferta al punto fijo de $2^{15}=32768$:
     \[
     \text{ratio} = \left\lfloor \frac{\text{supply} \times 32768}{\text{demand}} \right\rfloor
     \]
     Calculado mediante desplazamiento de 64 bits `shld/shl 0xF` y división con `0x00AC02A0` (`__alldiv`).
2. **Curva de sensibilidad (`0x00482610`)**:
   - Mapea el ratio de oferta/demanda a través de una función escalonada por tramos de 800 bytes (`0x00482610..0x0048292B`), obteniendo el multiplicador de elasticidad `sensitivity`.
3. **Precio objetivo (`0x00482B74..0x00482B96`)**:
   - Multiplica el precio base `base_price = [good + 0x30]` por la elasticidad con `0x00AC9F20` (`__allmul`) y divide por 32768:
     \[
     \text{target\_price} = \left\lfloor \frac{\text{base\_price} \times \text{sensitivity}}{32768} \right\rfloor
     \]

## 3. Acotación de la variación máxima diaria (Regla del 1% diario)

En `0x00482B96..0x00482C36`:
- El motor limita la volatilidad del mercado prohibiendo variaciones diarias mayores a un paso máximo `max_step`.
- `max_step` está almacenado en la variable global `[0x0125B9E0..0x0125B9E4]`, inicializada en `0x00BD2DC0` cargando el double `328.17999267578125` en `0x00E458F8`:
  \[
  \text{max\_step} = \lfloor 0.01 \times 32768 + 0.5 \rfloor = 328 \ (\approx 1\% \text{ diario})
  \]
- Si \(\text{target\_price} - \text{current\_price} < -\text{max\_step}\):
  \[
  \Delta = -\text{max\_step} = -328
  \]
  Calculado con `neg edx; adc ecx, 0; neg ecx` en `0x00482BE6`.
- Si \(\text{target\_price} - \text{current\_price} > \text{max\_step}\):
  \[
  \Delta = +\text{max\_step} = +328
  \]
- En caso contrario:
  \[
  \Delta = \text{target\_price} - \text{current\_price}
  \]
- El nuevo precio intermedio \(\text{current\_price} + \Delta\) pasa a continuación al mecanismo de clamping absoluto \([0.2\times, 5.0\times]\) especificado en `PRICE-CLAMP.md`.

## 4. Verificación empírica

* **Reverify**: 31 afirmaciones de bytes, constantes flotantes e instrucciones para la inicialización en `0x00BD2DC0` y el bloque de acotación en `0x00482B96..0x00482C40`.
* **Controles negativos**: comprobación de refutación e invalidación dependiente frente a umbrales erróneos.
* **Unicorn Engine**: 150 fixtures dinámicos emulados con el código máquina nativo PE32 contrastados contra `market_price_delta_model.py` con **0 discrepancias**.
