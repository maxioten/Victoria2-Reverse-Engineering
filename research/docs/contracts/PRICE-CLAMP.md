# Acotación de precios en el mercado mundial (Price Clamping)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## Constantes y representación de punto fijo

Los precios en el motor de economía utilizan punto fijo con factor de escala \(2^{15} = 32768\).
Las cotas mínima y máxima de precio relativo para cada mercancía están definidas por constantes de tipo `double` (IEEE 754 de 64 bits):

| Constante | VA | Hexadecimal | Valor almacenado | Significado aritmético |
| --- | --- | --- | --- | --- |
| `kPriceMinFactor` | `0x00E45C30` | `000000a0199ab940` | `6554.10009765625` | \(0.2 \times 32768 + 0.5 = 6553.6 + 0.5\) |
| `kPriceMaxFactor` | `0x00E45C28` | `0000000004000441` | `163840.5` | \(5.0 \times 32768 + 0.5 = 163840.0 + 0.5\) |

El \(+0.5\) actúa como sesgo de redondeo antes de la conversión que trunca hacia cero en el helper CRT `0x00B31C36`:
- `trunc(6554.10009765625) = 6554` (factor mínimo entero)
- `trunc(163840.5) = 163840` (factor máximo entero, exactamente \(5 \times 32768\))

> [!WARNING]
> Un mod que intente modificar las cotas mínimas o máximas escribiendo directamente `0.1` o `10.0` como `double` en esas direcciones reducirá los límites por un factor de 32.768, colapsando el mercado. Los valores deben calcularse como \(\text{factor} \times 32768 + 0.5\).

## Circuito de cálculo en `0x00482930`

La función `0x00482930` es la rutina de actualización de precios del mercado, llamada desde:
- `0x00489BA6`: dentro de la actualización diaria de economía (`Economy_Update` / `0x00489990`).
- `0x0068BF4A`: dentro de la inicialización / recarga completa (`EconomyManager_UpdateFull` / `0x0068BF00`).

Para cada bien (con precio base `base_price` de 64 bits en `[eax + 0x30]`), el bloque `0x00482C46..0x00482D1E`:
1. Carga `kPriceMinFactor` en ST(0) (`0x00482C46: fld qword ptr [0xe45c30]`).
2. Suma el cambio de oferta/demanda al precio anterior (`0x00482C6A..0x00482C7E: add eax, [..]; adc edi, [..]`), almacenando el precio bruto en `[edi:[ebp - 0x20]]`.
3. Convierte `kPriceMinFactor` a entero de 64 bits mediante `0x00B31C36`.
4. Multiplica `(base_price * 6554)` mediante `0x00AC9F20` (`__allmul`).
5. Desplaza 15 bits a la derecha (`shrd eax, ebx, 0xf; sar ebx, 0xf`), obteniendo `min_price`.
6. Carga `kPriceMaxFactor` en ST(0) (`0x00482CA1: fld qword ptr [0xe45c28]`).
7. Convierte a entero de 64 bits y multiplica `(base_price * 163840)` mediante `0x00AC9F20`.
8. Desplaza 15 bits a la derecha (`shrd eax, edx, 0xf; sar edx, 0xf`), obteniendo `max_price`.
9. Compara el precio bruto con signo de 64 bits:
   - Si `price < min_price`: fija `price = min_price`, almacena en `[ebp - 0x20]`, y salta a `0x00482CF6`.
   - Si `price > max_price`: fija `price = max_price`, almacena en `[ebp - 0x20]`, y cae a `0x00482CF6`.
   - Si `min_price <= price <= max_price`: no modifica el precio y salta directamente a `0x00482D1E`.
10. La ruta de cota alcanzada (`0x00482CF6..0x00482D19`) registra el evento llamando a `0x0047DA50`.

## Verificación empírica

* **Reverify**: 36 afirmaciones comprobadas (bytes exactos de constantes, sitios CALL, mnemónicos y operandos).
* **Controles negativos**: una dirección de constante falsa resulta en `REFUTED` y propaga `INVALIDATED` al dependiente.
* **Unicorn Engine**: 228 fixtures emulados con el código de máquina original PE32 de `v2game.exe` cubriendo 12 precios base distintos (de 0.1 a 1000.0) y casos de borde (cero, negativos, `min-1`, `min`, `min+1`, intermedio, `max-1`, `max`, `max+1`, valores grandes de 64 bits), con 0 discrepancias frente a `price_clamp_model.py`.
