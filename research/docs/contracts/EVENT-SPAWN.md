# Despacho y encolado de eventos (`CCountryEventEffect::Execute`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## 1. Función objetivo: `0x0088D370` (`CCountryEventEffect::Execute`)

La rutina `0x0088D370` es el método virtual (`vtable[11]` / `+0x2C` en `0x00E2B43C`) de la clase `CCountryEventEffect` (`.?AVCCountryEventEffect@@`).
Se invoca cuando un efecto de script ejecuta una orden del tipo `country_event = { id = <ID> days = <DELAY> }`.

Convención de llamada: `__thiscall` con 2 argumentos (`RET 8`):
- `ECX`: puntero a `this` (`CCountryEventEffect*`).
- `[ebp + 0x08]`: puntero al ámbito de ejecución (`CScriptScope*` o contexto de script).
- `[ebp + 0x0C]`: segundo argumento de contexto.

## 2. Generación aleatoria de instancia (LCG MSVC de 2 pasos)

En `0x0088D37F..0x0088D3B0`:
1. Lee la semilla aleatoria local del ámbito en `[scope + 0x40]`.
2. Aplica dos pasos del generador congruencial lineal estándar:
   \[
   s_1 = (s_0 \times 214013 + 2531011) \pmod{2^{32}}
   \]
   \[
   s_2 = (s_1 \times 214013 + 2531011) \pmod{2^{32}}
   \]
3. Almacena la nueva semilla \(s_2\) en `[scope + 0x40]`.
4. Extrae los 15 bits altos de cada paso:
   \[
   r_1 = (s_1 \gg 16) \ \& \ \text{0x7FFF} \in [0, 32767]
   \]
   \[
   r_2 = (s_2 \gg 16) \ \& \ \text{0x7FFF} \in [0, 32767]
   \]
5. Calcula `roll` multiplicando ambos factores: \(\text{roll} = r_1 \times r_2 \in [0, 1073676289]\).
6. Pasa `roll` a `0x008A8650` para inicializar el contenedor de instancia de evento en la pila.

## 3. Resolución en el Registro de Objetos

En `0x0088D3EE..0x0088D40D`:
1. Consulta el registro global de objetos en `[0x01258A98]`. Si es nulo (`JE 0x88D456`), aborta la ejecución de forma segura.
2. Configura en la pila la clave de búsqueda de 64 bits:
   - `key.type = 0x27` (39 = tipo Objeto Evento de País).
   - `key.id = [this + 0x20]` (identificador numérico del evento).
3. Invoca `0x009C1D40` (`CObjectRegistry::Lookup`).
4. Si el evento no está registrado (retorna 0), aborta inmediatamente sin disparar.

## 4. Bifurcación Inmediata vs. Diferida

En `0x0088D413`:
- Lee el retraso en días: `delay = [this + 0x24]`.
- Evalúa `test ebx, ebx; jg 0x88d439`:

### Caso A: Disparo Inmediato (`delay <= 0`)
1. Prepara el contexto de ejecución mediante `0x008A6620`.
2. Invoca directamente `0x008A8120` (`CCountryEvent::Fire`), pasando el puntero al evento en `ECX` y el contexto de ejecución en la pila.
3. Concluye y retorna mediante `RET 8` en `0x0088D436`.

### Caso B: Encolado Diferido (`delay > 0`, salto a `0x0088D439`)
1. Lee `g_CountryManager` en `[0x012587E4]`.
2. Accede a la tabla de punteros a países en `[g_CountryManager + 4]`.
3. Lee el índice de país destinatario copiado en la pila (`[esp + 0x34]`, correspondiente al campo de destino `[scope + 0x0C]`).
4. Obtiene el puntero al país destino: `country = table[target_index]`.
5. Invoca `0x00540A70` (`CCountry::AddDelayedEvent`):
   - Argumentos: `(country, event_ptr, &temp_event_instance, delay)`.
   - `0x00540A70` instancia un objeto de 88 bytes (`push 0x58; call malloc`) con RTTI `CDelayedEvent` (`.?AVCDelayedEvent@@`, vtable `0x00E2C858`), tipo `0x18D` en `+0x04`, puntero de evento en `+0x08`, temporizador de días restantes en `+0x54`, y lo añade al vector del país en `country + 0x68`.

## 5. Verificación empírica

* **Reverify**: 37 afirmaciones de bytes, slots de vtable de `CCountryEventEffect` y `CProvinceEventEffect`, y llamadas en `0x0088D370` y `0x00540A70`.
* **Controles negativos**: comprobación de refutación e invalidación dependiente frente a llamadas espurias.
* **Unicorn Engine**: 66 fixtures dinámicos ejecutados sobre el código máquina nativo cubriendo eventos nulos en registro, despacho inmediato (`delay = 0, -1, -10`), despacho diferido (`delay = 1, 7, 30, 365`), con verificación exacta de la actualización de la semilla LCG en el scope y parámetros de llamada.
