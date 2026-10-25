# Contrato: Ejecución del Ataque de Regimiento y Cómputo de Bajas (`CLandCombatant::ExecuteRegimentAttack`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la rutina:** `0x0059A8E0..0x0059ACAF` (464 bytes, 143 instrucciones).
- **Puntos de llamada identificados (xrefs):**
  - `0x0059AD3A` en el bucle principal de combate diario (`CLandCombatant::DailyCombatPhase`) para regimientos de primera línea.
  - `0x0059AD63` en el bucle principal de combate diario para regimientos de segunda línea (artillería con `support > 0`).
- **Convención de llamada:**
  - Registro `ecx`: puntero al regimiento atacante (`this` = `CRegiment*`).
  - Registro `eax`: tirada efectiva del líder / combate (`leader_dice_roll`).
  - Pila:
    - `[esp + 4]`: puntero al combatiente atacante (`CLandCombatant* pAttackerCombatant`).
    - `[esp + 8]`: puntero al combatiente objetivo (`CLandCombatant* pTargetCombatant`).
    - `[esp + 12]`: columna táctica del atacante (`col`, 0..29).
    - `[esp + 16]`: factor de soporte (`support_factor`, 1000 = 100% en primera línea, o atributo `support` de unidad en segunda línea).
  - Epílogo: `ret 0x10` (limpieza de 16 bytes de la pila).

## 2. Descripción Funcional y Flujo de Ejecución
La rutina constituye el núcleo ejecutor del daño de combate en Victoria II. Modela el ciclo diario de ataque de una subunidad individual:

1. **Validación de Operatividad del Ejército:**
   - Comprueba que el regimiento posea un ejército asociado (`[pRegiment + 0x74] != NULL`).
   - Comprueba la bandera de actividad del ejército (`[pArmy + 0xA4] != 0`). Si falla, la rutina aborta sin efectos.

2. **Adquisición de Objetivo Táctico:**
   - Extrae el alcance de maniobra del regimiento:
     $$\text{maneuver} = \lfloor \text{[pType + 0x240]} / 1000 \rfloor \quad (\text{división mágica } 0x10624DD3)$$
   - Invoca a `CLandCombatant::FindTargetRegiment` (`0x0059B610`).
   - Si no se encuentra blanco operativo (`pTarget == NULL`):
     - Limpia los identificadores de objetivo en el atacante: `[pRegiment + 0x7C] = 0`, `[pRegiment + 0x80] = 0`.
     - Retorna sin infligir daño.

3. **Selección de Estadística de Ataque por Fase de Combate:**
   - Consulta la fase de combate en el combatiente atacante (`[pAttackerCombatant + 0x18]`):
     - Si `phase != 0` (Fase de Fuego): selecciona ataque de fuego `[pType + 0x230]`.
     - Si `phase == 0` (Fase de Choque): selecciona ataque de choque `[pType + 0x234]`.

4. **Consulta a la Tabla de Daño por Tirada de Combate:**
   - Suma el modificador de terreno/líder en `[pAttackerCombatant + 0x30]` a la tirada del dado:
     $$\text{effective\_roll} = \text{leader\_dice\_roll} + \text{dice\_modifier}$$
   - Invoca a `CCombat::LookupDiceDamage` (`0x00594230`), obteniendo el daño base discreto según la tabla de 18 niveles ($20$ a $900$).

5. **Multiplicador de Ataque y Escala por Fuerza y Soporte:**
   - Escala por la estadística de ataque y constante `BASE_CASUALTY_MODIFIER` ($100$ en `0x0125F5C8`):
     $$\text{attack\_mult} = 1000 + \left\lfloor \frac{100 \times \text{attack\_stat}}{1000} \right\rfloor$$
   - Aplica el factor de soporte táctico (1000 en vanguardia, 500 en apoyo de artillería):
     $$\text{supp\_damage} = \left\lfloor \frac{\text{dice\_damage} \times \text{support\_factor}}{1000} \right\rfloor$$
   - Escala por fuerza actual del regimiento atacante (`[pRegiment + 0x3C]`):
     $$\text{damage} = \left\lfloor \frac{\text{supp\_damage} \times \text{attack\_mult} \times \text{strength}}{1,000,000} \right\rfloor$$

6. **Reducción por Fortificaciones Provinciales y Reconocimiento:**
   - Si la provincia está controlada por el atacante, el daño no sufre penalización por fuerte.
   - En territorio hostil o contra rebeldes ("REB"), si existe fuerte:
     - Calcula el reconocimiento máximo y la proporción de unidades de ingenieros en el ejército atacante (`0x005CCDB0` y `0x005CCDF0`).
     - Reduce el nivel del fuerte según el reconocimiento efectivo:
       $$\text{effective\_fort} = \max\left(0, \text{fort\_level} - \lfloor \text{effective\_recon} / 1000 \rfloor\right)$$
     - Aplica el divisor de fortificación:
       $$\text{fort\_divisor} = 1000 + \text{effective\_fort} \times 100 \implies \text{damage} = \left\lfloor \frac{\text{damage} \times 1000}{\text{fort\_divisor}} \right\rfloor$$

7. **Mitigación por Tácticas del Regimiento Defensor:**
   - Lee el valor de tácticas defensivas del objetivo (`[pTarget + 0x34]`) y `BASE_TACTICS_DAMAGE_MODIFIER` ($10$ en `0x0125F594`):
     $$\text{tactics\_factor} = 1000 + \left\lfloor \frac{\text{target\_tactics} \times 10}{1000} \right\rfloor$$
     $$\text{damage} = \left\lfloor \frac{\text{damage} \times 1000}{\text{tactics\_factor}} \right\rfloor$$

8. **Atenuación por Defensa de Unidad y Tácticas Militares Nacionales:**
   - Para bajas en hombres: multiplica por 10 y atenúa por la defensa de la unidad defensora (`[pTargetType + 0x238]`):
     $$\text{strength\_casualties} = \left\lfloor \frac{(\text{damage} \times 10) \times 1000}{\text{target\_defense}} \right\rfloor \quad (\text{o } \text{damage} \times 10 \text{ si defensa} = 0)$$
   - Para pérdida de organización: atenúa por el bono tecnológico nacional de tácticas (`[target\_country + 0xBCC]->0x70`):
     $$\text{org\_damage} = \left\lfloor \frac{\text{damage} \times 1000}{1000 + \text{tech\_tactics}} \right\rfloor \quad (\text{o } \text{damage} \text{ si bono} = 0)$$

9. **Escala Final y Acumulación Diaria en el Regimiento Objetivo:**
   - Aplica el factor global `BASE_MORALE_DAMAGE_MODIFIER` ($200$ en `0x0125F578`):
     $$\Delta\text{casualties} = \left\lfloor \frac{\text{strength\_casualties} \times 200}{1000} \right\rfloor = \left\lfloor \frac{\text{strength\_casualties}}{5} \right\rfloor$$
     $$\Delta\text{org\_loss} = \left\lfloor \frac{\text{org\_damage} \times 200}{1000} \right\rfloor = \left\lfloor \frac{\text{org\_damage}}{5} \right\rfloor$$
   - Acumula los daños directamente en el regimiento objetivo para su aplicación en el fin de turno:
     - `[pTarget + 0x70] +=` $\Delta\text{casualties}$
     - `[pTarget + 0x6C] +=` $\Delta\text{org\_loss}$

## 3. Criterio de Evidencia y Verificación
- Catálogo de afirmaciones Reverify cubriendo cada instrucción de `0x0059A8E0..0x0059ACAF`.
- Afirmaciones de los puntos de llamada en `0x0059AD3A` y `0x0059AD63`.
- Control negativo contrastado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en memoria sintética verificando todas las ramas (unidad nula, sin blanco, fases fuego/choque, soporte vanguardia/retaguardia, impacto de fuertes e ingenieros, defensa y tácticas) con 0 discrepancias frente a `combat_regiment_attack_model.py`.
