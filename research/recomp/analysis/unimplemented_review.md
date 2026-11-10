# Revisión de funciones con UNIMPLEMENTED

Veredicto conservador: `data-like (probable)` significa que parece dato y no tiene llamadores, no que esté probado.

| Función | Tamaño | Callers | Data refs | Prólogo | UNIMPL | Veredicto |
|---|---:|---:|---:|---|---:|---|
| `sub_004FF000` | 171 | 0 | 1 | no | 5 | data-like (probable) |
| `sub_009C12D0` | 102 | 66 | 0 | sí | 1 | code-reachable, pause benign |
| `sub_00A18000` | 247 | 0 | 1 | no | 1 | data-like (probable) |
| `sub_00A6B230` | 104 | 1 | 0 | sí | 1 | code-reachable, pause benign |
| `sub_00A6B650` | 60 | 1 | 0 | sí | 1 | code-reachable, pause benign |
| `sub_00A6B690` | 60 | 1 | 0 | sí | 1 | code-reachable, pause benign |
| `sub_00A9F4B2` | 7086 | 0 | 0 | no | 7 | data-like (probable) |
| `sub_00AA05AA` | 2742 | 0 | 0 | no | 134 | data-like (probable) |
| `sub_00AA3A49` | 1119 | 0 | 0 | no | 6 | data-like (probable) |
| `sub_00AA4416` | 1199 | 0 | 0 | no | 30 | data-like (probable) |
| `sub_00AA4FF8` | 8 | 0 | 0 | no | 1 | data-like (probable) |
| `sub_00AA5000` | 79 | 0 | 1 | no | 6 | data-like (probable) |
| `sub_00AA323E` | 3178 | 0 | 0 | no | 6 | data-like (probable), alias de sub_00AA3A49 |

## Detalle

### `sub_004FF000` — data-like (probable)

- Entry kind: `start`; size 171; callers 0 []
- Data refs en la imagen: 1; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `11111111111111111111111111111111`; prólogo: no
- Primeras instrucciones: `adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx; adc dword ptr [ecx], edx`
- Byte stats: {'zero_pct': 5.8, 'x11_pct': 68.4, 'cc_pct': 0.0, 'printable_pct': 7.0, 'entropy': 2.2}; instrucciones raras: 5
- UNIMPLEMENTED: {'fisttp': 4, 'pavgb': 1}

### `sub_009C12D0` — code-reachable, pause benign

- Entry kind: `start`; size 102; callers 66 ['0x0057B560', '0x0057B640', '0x0057D1B0', '0x005E3A60', '0x006B8960']
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `558bec83ec0c578bf8897df88b55f8b1`; prólogo: sí
- Primeras instrucciones: `push ebp; mov ebp, esp; sub esp, 0xc; push edi; mov edi, eax; mov dword ptr [ebp - 8], edi; mov edx, dword ptr [ebp - 8]; mov cl, 1`
- Byte stats: {'zero_pct': 7.8, 'x11_pct': 1.0, 'cc_pct': 0.0, 'printable_pct': 22.5, 'entropy': 5.24}; instrucciones raras: 1
- UNIMPLEMENTED: {'pause': 1}

### `sub_00A18000` — data-like (probable)

- Entry kind: `start`; size 247; callers 0 []
- Data refs en la imagen: 1; palabras pointer-like en primeros 64 B: 1
- Primeros bytes: `cd7fa100000b0b0b0b0b0b0b0b0b0b0b`; prólogo: no
- Primeras instrucciones: `int 0x7f; mov eax, dword ptr [0xb0b0000]; or ecx, dword ptr [ebx]; or ecx, dword ptr [ebx]; or ecx, dword ptr [ebx]; or ecx, dword ptr [ebx]; or ecx, dword ptr [ebx]; or ecx, dword ptr [ebx]`
- Byte stats: {'zero_pct': 0.8, 'x11_pct': 0.0, 'cc_pct': 0.8, 'printable_pct': 0.0, 'entropy': 0.63}; instrucciones raras: 1
- UNIMPLEMENTED: {'int': 1}

### `sub_00A6B230` — code-reachable, pause benign

- Entry kind: `start`; size 104; callers 1 ['0x00A6A9F0']
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `558bec83ec0c538b1d9ca5c80057bf01`; prólogo: sí
- Primeras instrucciones: `push ebp; mov ebp, esp; sub esp, 0xc; push ebx; mov ebx, dword ptr [0xc8a59c]; push edi; mov edi, 1; mov dword ptr [ebp - 4], edi`
- Byte stats: {'zero_pct': 10.6, 'x11_pct': 1.0, 'cc_pct': 0.0, 'printable_pct': 19.2, 'entropy': 5.36}; instrucciones raras: 1
- UNIMPLEMENTED: {'pause': 1}

### `sub_00A6B650` — code-reachable, pause benign

- Entry kind: `start`; size 60; callers 1 ['0x00A6B2A0']
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `558bec538b5d088b0356be0100000089`; prólogo: sí
- Primeras instrucciones: `push ebp; mov ebp, esp; push ebx; mov ebx, dword ptr [ebp + 8]; mov eax, dword ptr [ebx]; push esi; mov esi, 1; mov dword ptr [ebp + 8], esi`
- Byte stats: {'zero_pct': 6.7, 'x11_pct': 1.7, 'cc_pct': 0.0, 'printable_pct': 26.7, 'entropy': 5.03}; instrucciones raras: 1
- UNIMPLEMENTED: {'pause': 1}

### `sub_00A6B690` — code-reachable, pause benign

- Entry kind: `start`; size 60; callers 1 ['0x00A6B2A0']
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `558bec538b5d088b0356be0100000089`; prólogo: sí
- Primeras instrucciones: `push ebp; mov ebp, esp; push ebx; mov ebx, dword ptr [ebp + 8]; mov eax, dword ptr [ebx]; push esi; mov esi, 1; mov dword ptr [ebp + 8], esi`
- Byte stats: {'zero_pct': 6.7, 'x11_pct': 1.7, 'cc_pct': 0.0, 'printable_pct': 26.7, 'entropy': 5.03}; instrucciones raras: 1
- UNIMPLEMENTED: {'pause': 1}

### `sub_00A9F4B2` — data-like (probable)

- Entry kind: `start`; size 7086; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `a900cd43a900d743a900e143a900eb43`; prólogo: no
- Primeras instrucciones: `test eax, 0xa943cd00; add bh, dl; inc ebx; test eax, 0xa943e100; add bl, ch; inc ebx; test eax, 0xa943f500; add bh, bh`
- Byte stats: {'zero_pct': 23.2, 'x11_pct': 0.0, 'cc_pct': 0.0, 'printable_pct': 26.4, 'entropy': 4.66}; instrucciones raras: 0
- UNIMPLEMENTED: {'daa': 2, 'das': 1, 'aaa': 1, 'aas': 1, 'bound': 2}

### `sub_00AA05AA` — data-like (probable)

- Entry kind: `alias`; size 2742; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `a90035aea9003faea90049aea90053ae`; prólogo: no
- Primeras instrucciones: `test eax, 0xa9ae3500; add byte ptr [edi], bh; scasb al, byte ptr es:[edi]; test eax, 0xa9ae4900; add byte ptr [ebx - 0x52], dl; test eax, 0xa9ae5d00; add byte ptr [edi - 0x52], ah; test eax, 0xa9ae7100`
- Byte stats: {'zero_pct': 25.0, 'x11_pct': 0.2, 'cc_pct': 0.0, 'printable_pct': 7.0, 'entropy': 4.02}; instrucciones raras: 0
- UNIMPLEMENTED: {'aad': 128, 'daa': 1, 'das': 1, 'aaa': 1, 'aas': 1, 'bound': 1, 'lcall': 1}

### `sub_00AA3A49` — data-like (probable)

- Entry kind: `alias`; size 1119; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `baa90028baa90032baa9003cbaa90046`; prólogo: no
- Primeras instrucciones: `mov edx, 0xba2800a9; test eax, 0xa9ba3200; add byte ptr [edx + edi*4], bh; test eax, 0xa9ba4600; add byte ptr [eax - 0x46], dl; test eax, 0xa9ba5a00; add byte ptr [edx + edi*4 - 0x57], ah; add byte ptr [esi - 0x46], ch`
- Byte stats: {'zero_pct': 25.2, 'x11_pct': 0.0, 'cc_pct': 0.2, 'printable_pct': 9.4, 'entropy': 4.31}; instrucciones raras: 0
- UNIMPLEMENTED: {'daa': 1, 'das': 1, 'aaa': 1, 'aas': 1, 'bound': 1, 'lcall': 1}

### `sub_00AA4416` — data-like (probable)

- Entry kind: `start`; size 1199; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `a900c8d0a900d2d0a900dcd0a900e6d0`; prólogo: no
- Primeras instrucciones: `test eax, 0xa9d0c800; add dl, dl; shr byte ptr [ecx - 0x562f2400], 1; add dh, ah; shr byte ptr [ecx - 0x562f1000], 1; add dl, bh; shr byte ptr [ecx - 0x562efc00], 1; add byte ptr [esi + 0xe00a9d6], al`
- Byte stats: {'zero_pct': 25.2, 'x11_pct': 0.0, 'cc_pct': 0.2, 'printable_pct': 9.4, 'entropy': 4.32}; instrucciones raras: 17
- UNIMPLEMENTED: {'aam': 12, 'aad': 12, 'salc': 6}

### `sub_00AA4FF8` — data-like (probable)

- Entry kind: `alias`; size 8; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 2
- Primeros bytes: `45eaa9004feaa900`; prólogo: no
- Primeras instrucciones: `inc ebp; ljmp 0xa9:0xea4f00a9`
- Byte stats: {'zero_pct': 25.0, 'x11_pct': 0.0, 'cc_pct': 0.0, 'printable_pct': 25.0, 'entropy': 2.25}; instrucciones raras: 1
- UNIMPLEMENTED: {'ljmp': 1}

### `sub_00AA5000` — data-like (probable)

- Entry kind: `start`; size 79; callers 0 []
- Data refs en la imagen: 1; palabras pointer-like en primeros 64 B: 16
- Primeros bytes: `59eaa90063eaa9006deaa90077eaa900`; prólogo: no
- Primeras instrucciones: `pop ecx; ljmp 0xa9:0xea6300a9; insd dword ptr es:[edi], dx; ljmp 0xa9:0xea7700a9; sub edx, 0xea8b00a9; test eax, 0xa9ea9500; add byte ptr [edi - 0x56ff5616], bl; ljmp 0xa9:0xeab300a9`
- Byte stats: {'zero_pct': 24.1, 'x11_pct': 0.0, 'cc_pct': 0.0, 'printable_pct': 5.1, 'entropy': 3.17}; instrucciones raras: 6
- UNIMPLEMENTED: {'ljmp': 5, 'insd': 1}

### `sub_00AA323E` — data-like (probable), alias de sub_00AA3A49

- Entry kind: `start`; size 3178; callers 0 []
- Data refs en la imagen: 0; palabras pointer-like en primeros 64 B: 0
- Primeros bytes: `baa90028baa90032baa9003cbaa90046`; prólogo: no
- Primeras instrucciones: `mov edx, 0xba2800a9; test eax, 0xa9ba3200; add byte ptr [edx + edi*4], bh; test eax, 0xa9ba4600; add byte ptr [eax - 0x46], dl; test eax, 0xa9ba5a00; add byte ptr [edx + edi*4 - 0x57], ah; add byte ptr [esi - 0x46], ch`
- Byte stats: {'zero_pct': 25.2, 'x11_pct': 0.0, 'cc_pct': 0.2, 'printable_pct': 9.4, 'entropy': 4.31}; instrucciones raras: 0
- UNIMPLEMENTED: {'daa': 1, 'das': 1, 'aaa': 1, 'aas': 1, 'bound': 1, 'lcall': 1}

