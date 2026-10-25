# Alcance de esta publicación

Se publican fuentes de modelos, verificadores, harnesses, scripts Ghidra, contratos
con direcciones y límites, dependencias y versiones de herramientas. Se conserva
el contenido anterior del repositorio en sus directorios originales.

No se incluyen el ejecutable ni otros archivos del juego, partidas, proyectos
Ghidra, exportaciones extensas de pseudocódigo/desensamblado, recibos generados,
ledgers locales, runtimes descargados o configuración personal de apagado.
Los enlaces a `evidence/generated/` describen salidas locales que debe regenerar
quien reproduzca los ensayos; no son archivos distribuidos con el repositorio.

## Estado de validación

[validation-summary.json](../validation-summary.json) resume el último gate local:
89 verificadores, estado registrado PASS y resultados nativos asociados. Los
sources del gate se contrastaron con sus hashes antes de preparar esta publicación.
No se presenta como una ejecución nueva de CI. Los ensayos nativos almacenados
indican `fresh_execution_this_gate: false`: el gate contrasta sus fuentes y recibos,
pero no vuelve a ejecutar Wine por consultar ese resultado.

El banco nativo de crecimiento/lifecycle registra 9.897 casos, con 31.116 reservas
y 29.997 liberaciones originales. Sus dominios, los fixtures y las exclusiones
están documentados en los contratos. Nada de esto demuestra el motor completo,
una mejora de tick speed o seguridad para paralelizar sus recorridos.

## Preparación local

Se requiere una copia propia de `v2game.exe` con SHA-256:

`62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648`

Colocarla en `base-game/v2game.exe`, fuera de Git. VA preferida = RVA + `0x00400000`;
las direcciones de runtime dependen de la base real. No modificar esa referencia.

Crear un entorno Python local y usar las dependencias fijadas:

```bash
python3 -m venv research/.venv
research/.venv/bin/python -m pip install -r research/requirements.lock
source research/env.sh
python research/scripts/doctor.py
python research/scripts/inventory.py
python research/scripts/verify_claims.py
```

Reverify se fija al commit `f32ea84ccd6bb2aff90eca711ccfdbf04e6b8923` del
[repositorio original](https://github.com/2akouwu/reverify). La URL local de su
instalación de desarrollo se reemplazó por esa referencia Git portable. No se
incluyen fuentes de dependencias de terceros.

`toolchain.lock.json` registra tags, URLs oficiales y SHA-256 de los assets usados.
Las herramientas deben instalarse en los directorios relativos esperados por
`env.sh`, o adaptar esas rutas al entorno propio. Los ejecutables de herramientas
no están incluidos. `fetch_metadata.py` consulta releases actuales y
`download_tools.py` puede actualizar el lock: no constituyen por sí solos una
reinstalación de las versiones históricas fijadas.

El gate completo y varios verificadores requieren también snapshots Ghidra y
artefactos previos descritos en cada contrato. Revisar `scripts/analyze.sh`,
`repair_return_flow.py`, los exportadores de `ghidra_scripts/` y las notas del
proyecto antes de regenerarlos. No se promete que un checkout limpio ejecute el
gate completo sin preparar esos requisitos. Los probes nativos requieren Wine
PE32/WoW64 y, para compilarlos, el toolchain MinGW local configurado.

Los resultados deben conservar las etiquetas `confirmed`, `inferred`,
`hypothesis`, `INCONCLUSIVE` e `INVALIDATED` según su evidencia. Un nombre de
función o una representación C de Ghidra no es código fuente original recuperado.
