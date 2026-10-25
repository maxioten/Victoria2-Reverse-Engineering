# Contrato: Cálculo de Moral Media y Organización de Ejércitos (`CUnit::CalculateAverageMorale`)

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe` (SHA-256: `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`).
- **Dirección de la función:** `0x005C8DC0..0x005C8F08` (329 bytes, 113 instrucciones).
- **Vtables asociadas:**
  - `CArmy`: slot 37 en `0x00DF8960` (vtable base `0x00DF88CC`, offset `+0x94`).
  - `CNavy`: slot 37 en `0x00E03060` (vtable base `0x00E02FCC`, offset `+0x94`).
  - `CUnit`: slot 37 en `0x00E02F98` (vtable base `0x00E02F04`, offset `+0x94`).
- **Convención de llamada:** `__thiscall` con puntero `this` en `ecx` (`CUnit*`), argumento de salida `out_morale` en `[esp + 4]`, retorno de puntero en `eax` (`out_morale`), epílogo `ret 4`.

## 2. Descripción Funcional
Calcula la moral promedio y organización agregada de una unidad compuesta (ejército terrestre o armada naval):
1. **Inicialización en punto flotante:**
   Evalúa $0.0005 \times 1000.0 = 0.5$, aplicando `floor` y truncamiento a entero de 32 bits, inicializando `*out_morale = 0`.
2. **Acumulación de moral base de subunidades:**
   Si la lista enlazada de regimientos/barcos `[this + 0x38]` no está vacía, recorre secuencialmente los nodos (`node->next` en `+0x8`), sumando la moral base de cada tipo de subunidad (`[subunit->type + 0xB4]`):
   $$\text{sum\_base} = \sum_{i=1}^{N} \text{regiment}_i\text{->base\_morale}$$
3. **Normalización por recuento (`count = [this + 0x40]`):**
   Si `count > 0`, normaliza mediante aritmética entera de 64 bits con `_allmul` y `_alldiv`:
   $$\text{avg\_base} = \left\lfloor \frac{\text{sum\_base} \times 1000}{\text{count} \times 1000} \right\rfloor = \left\lfloor \frac{\text{sum\_base}}{\text{count}} \right\rfloor$$
4. **Bonificación doctrinal del partido político gobernante:**
   - Si `this->IsNavy()` (`vtable[14]` / `+0x38` retorna `true`):
     recupera el país propietario (`[0x12587E4]->countries[this->country_id]`), su partido gobernante (`[country + 0xA60]`) y el modificador naval `doctrine = [party + 0x68]`.
   - Si `this->IsArmy()` (`vtable[15]` / `+0x3C` retorna `true`):
     recupera el modificador militar terrestre `doctrine = [party + 0x70]`.
   - Si se identificó doctrina, aplica factor multiplicativo en milésimas:
     $$\text{morale} \leftarrow \left\lfloor \frac{\text{morale} \times (\text{doctrine} + 1000)}{1000} \right\rfloor$$
5. **Bonificación de líder asignado:**
   Si la unidad tiene un general o almirante (`leader = [this + 0xD8] != NULL`):
   recupera el rasgo en `[leader + 0x48]` y su bono en `leader_bonus = [modifier + 0x20]`.
   Aplica factor multiplicativo en milésimas:
   $$\text{morale} \leftarrow \left\lfloor \frac{\text{morale} \times (\text{leader\_bonus} + 1000)}{1000} \right\rfloor$$
6. Escribe el valor final en `*out_morale` y retorna el puntero.

## 3. Criterio de Evidencia y Verificación
- Catálogo de 113 afirmaciones Reverify cubriendo cada instrucción, saltos relativos, offsets de estructura y constantes (`0x00E45840`, `0x00E45660`, `0x012587E4`).
- Control negativo en target desfasado (`REFUTED`).
- Cascada de invalidación dependiente (`INVALIDATED`).
- Emulación dinámica con Unicorn en un espacio de memoria sintético con 0 discrepancias frente a `army_average_morale_model.py`.
