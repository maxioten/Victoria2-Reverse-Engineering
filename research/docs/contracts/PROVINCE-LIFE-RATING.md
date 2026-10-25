# Contrato Semántico: Cálculo y Acotación de Life Rating Provincial Efectivo

## 1. Identificación y Alcance
- **Binario:** `base-game/v2game.exe`
- **Hash SHA-256:** `62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`
- **Rutina objeto:** `0x004B9BD0..0x004B9C5F` (`CProvince::CalculateEffectiveLifeRating`)
- **Llamador verificado:** `0x004B1DC4` en `CProvince::DailyUpdate` (`0x004B1A10`).
- **Subsistema:** Demografía y Provincias / Condiciones de Vida y Capacidad de Crecimiento.

---

## 2. Convención de Llamada y Estructuras
- **Firma:** `CFixedPoint* __thiscall CProvince::CalculateEffectiveLifeRating(CFixedPoint* out_effective)`
- **Registros:**
  - `ECX`: puntero a la instancia `CProvince` (`this`).
    - `[ecx + 0x1A4]`: `base_life_rating` (entero de 32 bits, e.g. 10 a 35).
    - `[ecx + 0x9C]`: puntero al país propietario/controlador (`CCountry*`).
      - `[country + 0x260]`: modificador de tecnología médica/salud (`health_tech_modifier`: int32 en milésimas).
  - `ESI`: puntero al struct de retorno `CFixedPoint` (8 bytes).
  - Retorno: `EAX = ESI`.

---

## 3. Comportamiento Matemático y Algoritmo

### 3.1. Promoción a Punto Fijo
El valor entero `base_life_rating` se escala a punto fijo de 15 bits fraccionarios:
$$\text{life\_rating\_fp} = \text{base\_life\_rating} \times 32768$$
```assembly
0x004B9BD1: mov  eax, dword ptr [ecx + 0x1a4]
0x004B9BD7: cdq  
0x004B9BD8: shld edx, eax, 0xf
0x004B9BDC: shl  eax, 0xf
0x004B9BDF: mov  dword ptr [esi], eax
0x004B9BED: mov  dword ptr [esi + 4], edx
```

### 3.2. Escala del Modificador Tecnológico
El modificador de salud `[country + 0x260]` (expresado en milésimas) se promueve a 64 bits con desplazamiento de 30 bits a la izquierda y se divide por `0x01F40000` ($1000 \times 32768 = 32,768,000$):
$$\text{tech\_scaled} = \left\lfloor \frac{\text{health\_tech} \times 2^{30}}{32,768,000} \right\rfloor$$
A dicho valor se le suma la base unitaria $1.0$ ($0x8000 = 32768$):
$$\text{tech\_factor} = 32768 + \text{tech\_scaled}$$

### 3.3. Multiplicación de Punto Fijo
El Life Rating base se multiplica por el factor de tecnología mediante `0x00AC9F20` (`FixedPoint_Multiply`) y se normaliza con desplazamiento aritmético a la derecha:
$$\text{raw\_effective} = \text{FixedPoint\_Multiply}(\text{life\_rating\_fp}, \text{tech\_factor})$$

### 3.4. Acotación Estricta al Techo de 40.0 (`0x00140000`)
El motor impone dos límites estrictos:
1. **Límite inferior:** Si $\text{raw\_effective} < 0$, se clampa a $0$.
2. **Límite superior:** Si $\text{raw\_effective} > 0x00140000$ ($40.0 \times 32768 = 1,310,720$), el motor ejecuta:
```assembly
0x004B9C47: cmp dword ptr [esi], 0x140000
0x004B9C4D: jbe 0x4b9c5c
0x004B9C4F: mov dword ptr [esi], 0x140000
0x004B9C55: mov dword ptr [esi + 4], 0
```
**Regla empírica comprobada:** Ningún nivel de tecnología médica, invención o bonificación provincial puede permitir que una provincia supere el valor efectivo de $40.0$ de Life Rating en Victoria II.

---

## 4. Grounding y Evidencia
- 26 afirmaciones reverify sobre instrucciones de escala, división `_alldiv`, multiplicación `FixedPoint_Multiply` y comparaciones de clamping a `0x140000`.
- Control negativo erróneo `REFUTED` y cascada `INVALIDATED`.
- Fixtures dinámicos en Unicorn con 0 discrepancias frente a `province_life_rating_model.py`.
