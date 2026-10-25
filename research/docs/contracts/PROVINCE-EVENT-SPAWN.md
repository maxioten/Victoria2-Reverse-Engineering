# Despacho y encolado de eventos provinciales (`CProvinceEventEffect::Execute`)

Perfil `base-game/v2game.exe`, SHA-256
`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`.
VA preferidas para base `0x00400000`; RVA = VA − base.

## 1. Función objetivo: `0x0088D6B0` (`CProvinceEventEffect::Execute`)

La rutina `0x0088D6B0` es el método virtual (`vtable[11]` / `+0x2C` en `0x00E2B474`) de la clase `CProvinceEventEffect` (`.?AVCProvinceEventEffect@@`).
Se invoca cuando un efecto de script ejecuta una orden del tipo `province_event = { id = <ID> days = <DELAY> }`.

Convención de llamada: `__thiscall` con 2 argumentos (`RET 8`):
- `ECX`: puntero a `this` (`CProvinceEventEffect*`).
- `[ebp + 0x08]`: puntero al ámbito de ejecución (`CScriptScope*` o contexto de script).
- `[ebp + 0x0C]`: segundo argumento de contexto.

## 2. Generación aleatoria de instancia (LCG MSVC de 2 pasos)

En `0x0088D6BD..0x0088D6EF`:
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
5. Calcula `roll` multiplicando ambos factores: \(\text{roll} = r_1 \times r_2\).
6. Pasa `roll` a `0x008A8650` para inicializar el contenedor de instancia de evento en la pila.

## 3. Resolución en el Registro de Objetos

En `0x0088D723..0x0088D745`:
1. Consulta el registro global de objetos en `[0x01258A98]`. Si es nulo (`JE 0x88D790`), aborta la ejecución de forma segura.
2. Configura en la pila la clave de búsqueda de 64 bits:
   - `key.type = 0x27` (39 = tipo Objeto Evento).
   - `key.id = [this + 0x20]` (identificador numérico del evento).
3. Invoca `0x009C1D40` (`CObjectRegistry::Lookup`).
4. Si el evento no está registrado (retorna 0), aborta inmediatamente sin disparar.

## 4. Bifurcación Inmediata vs. Diferida

En `0x0088D74B`:
- Lee el retraso en días: `delay = [this + 0x24]`.
- Evalúa `test edi, edi; jg 0x88d770`:

### Caso A: Disparo Inmediato (`delay <= 0`)
1. Prepara el contexto de ejecución mediante `0x008A6620`.
2. Invoca directamente `0x008A8120` (`Event_Fire`), pasando el puntero al evento en `ECX` y el contexto de ejecución en la pila.
3. Retorna mediante `RET 8` en `0x0088D76D`.

### Caso B: Encolado Diferido (`delay > 0`, salto a `0x0088D770`)
1. Lee `g_ProvinceManager` en `[0x012588E8]`.
2. Accede a la tabla de punteros a provincias en `[g_ProvinceManager + 0xACC]`.
3. Lee el índice/identificador de provincia destinataria copiado en la pila (`[esp + 0x28]`, correspondiente al campo de destino `[scope + 0x10]`).
4. Obtiene el puntero a la provincia destino: `province = table[prov_id]`.
5. Invoca `0x004B1FC0` (`CProvince::AddDelayedEvent`):
   - Argumentos: `(province, event_ptr, &temp_event_instance, delay)`.
   - `0x004B1FC0` instancia un objeto de 88 bytes (`push 0x58; call malloc`) con RTTI `CDelayedEvent` (`.?AVCDelayedEvent@@`, vtable `0x00E2C858`), tipo `0x18D` en `+0x04`, puntero de evento en `+0x08`, temporizador de días restantes en `+0x54`, y lo añade al vector de la provincia en `province + 0x384`.

## 5. Verificación empírica

* **Reverify**: 34 afirmaciones de bytes, vtables e instrucciones en `0x0088D6B0` y `0x004B1FC0`.
* **Controles negativos**: comprobación de refutación e invalidación dependiente.
* **Unicorn Engine**: 66 fixtures dinámicos emulados con 0 discrepancias frente a `province_event_spawn_model.py`.
