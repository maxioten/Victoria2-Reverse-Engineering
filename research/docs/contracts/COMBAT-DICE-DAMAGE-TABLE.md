# Contrato: Tabla Universal de Daño por Tirada de Combate (`CCombat::LookupDiceDamage`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x00594230..0x005944A9` (634 bytes, 144 instrucciones).
- **Puntos de llamada identificados (xrefs):**
  - Combate Naval: `0x005979C9`, `0x00597C82`.
  - Combate Terrestre: `0x0059A973` (en `CLandCombatant::ExecuteRegimentAttack`).
- **Convención de llamada:** Registro `eax` con la tirada efectiva modificada (`roll`), registro `edi` con el puntero de salida (`out_damage_ptr`), retorno en `eax` con el puntero `edi`, epílogo `ret`.

## 2. Descripción Funcional
Calcula el factor base de bajas infligidas por un regimiento o buque en función del resultado efectivo de la tirada táctica (dado $0..9$ más bonificadores de líder y terreno):

1. **Transformación y acotación estricta de índice:**
   - La rutina recibe la tirada efectiva en `eax` y aplica un desplazamiento de $+2$:
     $$\text{raw\_index} = \text{roll} + 2$$
   - Aplica clamping rígido al intervalo discreto $[0, 17]$ ($18$ niveles de efectividad posibles):
     $$\text{index} = \min(17, \max(0, \text{raw\_index}))$$
   - Correspondencia: tirada efectiva desde $\le -2$ (índice 0) hasta $\ge +15$ (índice 17).

2. **Inicialización perezosa (*lazy initialization*):**
   - Comprueba el flag de inicialización en `[0x013F1BB8] & 1`.
   - Si no está inicializado:
     - Convierte de flotante IEEE 754 a entero de 32 bits los 18 valores almacenados en `.rdata` (`0x00E45A58` a `0x00E45A18`) mediante llamadas a `floor` (`0x00401000`) y `_ftol2` (`0x00B31C00`).
     - Almacena los 18 enteros en el vector global `0x013F1B70..0x013F1BB4`.
     - Marca `[0x013F1BB8] |= 1`.
   - Si ya está inicializado:
     - Ejecuta la ruta rápida leyendo directamente `0x013F1B70 + index * 4`.

3. **Curva Progresiva de Daño por Tirada:**
   Los 18 valores exactos del motor son:
   | Índice | Tirada Efectiva | Valor de Daño | Delta respecto al anterior |
   | :---: | :---: | :---: | :---: |
   | 0 | $\le -2$ | **20** | — |
   | 1 | -1 | **40** | +20 |
   | 2 | 0 | **60** | +20 |
   | 3 | 1 | **80** | +20 |
   | 4 | 2 | **100** | +20 |
   | 5 | 3 | **120** | +20 |
   | 6 | 4 | **160** | +40 |
   | 7 | 5 | **200** | +40 |
   | 8 | 6 | **250** | +50 |
   | 9 | 7 | **300** | +50 |
   | 10 | 8 | **350** | +50 |
   | 11 | 9 | **400** | +50 |
   | 12 | 10 | **450** | +50 |
   | 13 | 11 | **500** | +50 |
   | 14 | 12 | **600** | +100 |
   | 15 | 13 | **700** | +100 |
   | 16 | 14 | **800** | +100 |
   | 17 | $\ge 15$ | **900** | +100 |

   *Estructura matemática:* Crecimiento por tramos con aceleración en tiradas altas (+20 en tiradas pésimas, +40 en medias-bajas, +50 en medias-altas, +100 en tiradas críticas superiores).

4. Escribe el valor en `*[edi]` y retorna `eax = edi`.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 144 afirmaciones Reverify cubriendo cada instrucción de `0x00594230..0x005944A9`.
- Afirmaciones de los 3 puntos de llamada en combate terrestre y naval (`0x005979C9`, `0x00597C82`, `0x0059A973`).
- Afirmaciones `bytes_at` de las 18 constantes flotantes IEEE 754 en `.rdata`.
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn verificando tanto el camino en frío de inicialización como el camino en caliente, con 0 discrepancias frente a `combat_dice_damage_model.py`.
