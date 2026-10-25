# Tick diario: secuencia de fases

Estado: **en curso**. Documenta el orden de llamadas de `FUN_006859c0` obtenido del listado
Capstone completo y verificado por sus 122 `call`. No hay contrato ni emulación para este bloque.

- Binario: `../base-game/v2game.exe`, SHA-256
  `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- Base preferida `0x00400000`.

## Tamaño y forma

`FUN_006859c0` va de `0x006859C0` a `0x006874BA`: **6906 bytes, 1958 instrucciones, 122 llamadas
directas y 43 saltos hacia atrás**. El listado está en
`evidence/generated/ai-job/FUN_006859c0.capstone.asm`.

Es el tick diario completo: no es una función de despacho, ejecuta las fases en línea.

## Hallazgo: el frame se dibuja 11 veces por día

`UpdateTimeThrottle` (`0x00685620`) aparece **11 veces** en el cuerpo del día, intercalado entre
fases. No se llama una vez al final: se llama entre bloques.

Eso explica el 28 % de tiempo de pared que el perfil de muestreo atribuía
a `UpdateTimeThrottle` → `App_ProcessMessagePumpAndUpdate`: el motor dibuja para mantener la UI
viva en cada corte entre fases, no una sola vez por día.

Otros destinos repetidos: `0x00AC02A0` (helper aritmético de 64 bits) **15 veces**,
`0x00AAE9AF` (alloc) 11, `0x00AAE91B` (free) 10, `0x0041A160` 6, `0x0096DD80` 5.

### Los 11 sitios son la misma ruta (verificado)

Los once sitios siguen el mismo patrón: terminan un bucle de fase (`cmp` + `jl` al inicio del
bucle), cargan el argumento (`mov edi, ebx`) y llaman al throttle. **No hay ningún `cmp` de
velocidad de juego ni bandera que los condicione**; están todos en la ruta secuencial del día.

| sitio | instrucción previa |
| --- | --- |
| `0x00685B64` | `mov edi, ebx` (tras `cmp esi,edx` / `jl`) |
| `0x00685C33` | `mov edi, ebx` (tras `call 0x508590`) |
| `0x00685ED8` | `mov edi, ebx` (tras `call 0x5091A0`) |
| `0x00685EF3` | `mov edi, ebx` (tras `cmp esi,ecx` / `jl`) |
| `0x00685F1C` | `mov edi, ebx` (tras `cmp esi,[ebp-0x30]` / `jl`) |
| `0x00685F6E` | `mov edi, ebx` (tras `cmp esi,eax` / `jl`) |
| `0x00685F83` | `call 0x489990` (`Economy_Update`) |
| `0x00685FEF` | `mov edi, ebx` (tras escribir `byte [0x1258A66]`) |
| `0x0068601D` | `mov edi, ebx` (tras `cmp edi,ecx` / `jl`) |
| `0x00686125` | `mov edi, ebx` (tras `cmp eax,ecx` / `jl`) |
| `0x00686247` | `mov edi, ebx` (tras `call 0x0042A130`) |

O sea: el motor dibuja **al terminar cada fase**, siempre, en partidas de un jugador. No hay
camino alternativo que lo desactive.

## Secuencia de fases (sin alloc/free ni throttle)

| sitio | destino | nota |
| --- | --- | --- |
| `0x006859DD` | `0x00AB10F0` | apertura |
| `0x006859E9` | `0x006840F0` | — |
| `0x00685A05` | `0x0093C980` | — |
| `0x00685A2F` | `0x0041A160` | aparece 6 veces en el día |
| `0x00685A40` | `0x00423700` | — |
| `0x00685A6D` | `0x0096F7C0` | — |
| `0x00685AB9` | `0x0051FB60` | fase de país |
| `0x00685B09` | `0x004B9C60` | fase de POPs |
| `0x00685B49` | `0x004B1A10` | fase de POPs |
| `0x00685BAD` | `0x009B7700` | **regeneración del MT19937** (contrato [RNG](contracts/RNG.md)) |
| `0x00685C2C` | `0x00508590` | `Country_PrePass` |
| `0x00685CBE` | `0x0096DD80` | aparece 5 veces |
| `0x00685E86` | `0x0068F3F0` | — |
| `0x00685ED1` | `0x005091A0` | `Country_DailyUpdate` |
| `0x00685F0F` | `0x004F5BF0` | — |
| `0x00685F53` | `0x004BA780` | — |
| `0x00685F7E` | `0x00489990` | `Economy_Update` |
| `0x00685F96` | `0x005B5180` | — |
| `0x00685FD6` | `0x0068F4C0` | — |
| `0x00686009` | `0x005417D0` | — |
| `0x00686066` | `0x004E1E20` | — |
| `0x0068608D` | `0x004E5B50` | — |
| `0x00686194` | `0x00AB231D` | — |
| `0x0068619F` | `0x009B7670` | **inicialización del MT19937 con semilla** |
| `0x006861C9` | `0x008A6680` | — |
| `0x006861E8` | `0x008A7CD0` | `EventManager` |
| `0x00686228` | `0x004D3BB0` | — |
| `0x00686240` | `0x0042A130` | — |
| `0x0068636D` | `0x0068D250` | — |
| `0x00686426` | `0x0043A880` | dos veces seguidas |
| `0x00686748` | `0x00523880` | — |
| `0x006867AD` | `0x004F5100` | — |
| `0x006868A9` | `0x0096BB70` | — |
| `0x00686D0E` | `0x00B31C36` | — |
| `0x006871FB` | `0x0068E390` | fase de **guerra**: su único literal es `WAR_GAIN_GW_STATUS` |
| `0x00687200` | `0x00683CE0` | — |
| `0x00687226` | `0x00457A20` | — |
| `0x006872A9` | `0x0046ACB0` | — |
| `0x006872CF` | `0x00457B00` | tres veces |
| `0x00687303` | `0x0046AFA0` | — |
| `0x0068732E` | `0x00457B00` | — |
| `0x00687362` | `0x0046B1A0` | — |
| `0x00687388` | `0x00457B00` | — |
| `0x006873D8` | `0x00409350` | — |
| `0x006873F2` | `0x00459930` | — |
| `0x00687440` | `0x00409350` | — |
| `0x0068744D` | `0x009C7290` | — |
| `0x0068749D` | `0x00457CA0` | última llamada del día |

Dos hechos que se desprenden del orden y que conviene no perder de vista al leer el resto del
repositorio:

1. El **MT19937 se regenera y se vuelve a sembrar dentro del mismo día** (`0x009B7700` en
   `0x00685BAD` y `0x009B7670` en `0x0068619F`), antes y después de las fases de país y economía.
2. La **economía** (`0x00489990`) corre **después** de `Country_DailyUpdate` y antes del bloque de
   eventos, no al principio.

## Qué falta

- Nombrar las fases sin identificar. Se intentó por literales de cadena y **no rinde**: de las 15
  funciones grandes de la secuencia, sólo `0x0068E390` tiene una cadena propia
  (`WAR_GAIN_GW_STATUS`, fase de guerra). El resto son cálculo sin literales. Para nombrarlas hay
  que mirar qué campos del mundo escriben (`[ebx+0xAE0]`, `+0xAD0`, `+0xBCC`, `+0xB24`, `+0xB9C`) y
  cruzarlos con los contratos existentes, o instrumentar.
- Medir cuánto pesa cada fase **con** el throttle incluido, para separar simulación de dibujo.
- Confirmar si en multijugador o en modo observador el throttle se comporta igual (la estática
  muestra una sola ruta, pero no cubre modos que el binario activa por banderas).

## Reproducir

```bash
cd research
source env.sh
python3 scripts/disasm_fn.py ../base-game/v2game.exe 0x006859c0
grep -c "call 0x685620" evidence/generated/ai-job/FUN_006859c0.capstone.asm   # 11
```
