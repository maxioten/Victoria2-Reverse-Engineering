# Investigación de Victoria II

Fuentes y contratos del laboratorio. Ver [alcance de la publicación](docs/PUBLICATION.md)
y [resumen local de validación](validation-summary.json).

```bash
source env.sh
python scripts/doctor.py
python scripts/inventory.py
python scripts/verify_claims.py
```

Para reproducir juntas las verificaciones de reverify, sus controles negativos y las
pruebas aisladas de emulación y calendario:

```bash
source env.sh
python scripts/verify_grounding.py
```

El resumen con hashes de los recibos queda en `evidence/generated/grounding-gate.json`.
Un resultado correcto sólo cubre las afirmaciones y entradas declaradas en cada recibo;
no certifica toda la semántica del motor.

Los hechos persistentes de reverify están en `.reverify/ledger/`.
El estado del primer análisis de Ghidra está en `evidence/generated/ghidra/status.json`.
Consultar ese archivo y los logs antes de afirmar que el análisis terminó.
Las evidencias generadas no se incluyen en Git; permanecen locales.

Los [hallazgos contrastados](docs/HALLAZGOS.md) explican alcance, contraejemplos y
reproducción. Los nombres y diagramas externos se revisan contra el binario.

La última exportación completa de cuerpos auditada tras guardar y reabrir está en
`evidence/generated/ghidra-converged/`. Los nombres y comentarios añadidos después
residen en el proyecto de Ghidra y en los recibos de `analysis-annotations/`; ese CSV
no pretende reflejar todas las anotaciones recientes. El primer análisis y las pasadas intermedias
se conservan para comparación. Contratos: [RNG](docs/contracts/RNG.md),
[recorrido de POPs](docs/contracts/POP-SCHEDULE.md) y
[ciclo de vida de POPs](docs/contracts/POP-LIFETIME.md).

Otros contratos contrastados: [registro de objetos](docs/contracts/OBJECT-REGISTRY.md)
y [primitivas enteras de 64 bits](docs/contracts/INTEGER64.md).
También están documentadas la [normalización de distribuciones](docs/contracts/DISTRIBUTION.md)
y las [clases y enlaces RTTI](docs/contracts/RTTI.md), con campos desconocidos explícitos.
El [banco nativo de nodos POP](docs/contracts/NATIVE-POP.md) comprueba limpieza y
liberaciones reales en un proceso PE32 aislado con fixtures sintéticos.
También se documenta el [circuito de referencias a regimientos](docs/contracts/POP-REGIMENTS.md)
y sus ramas con efectos fuera del POP.
El [alta en el registro](docs/contracts/REGISTRY-INSERTION.md) incluye cinco ciclos
nativos de alta, búsqueda y destrucción de un POP registrado con tablas sintéticas.
La ampliación de [identificadores automáticos y bloqueo](docs/contracts/AUTOMATIC-IDS.md)
añade 36 ciclos y contención controlada del helper de adquisición original.
El [mapa de actualización de POP](docs/contracts/POP-UPDATE.md) cubre el grafo normal
de 71 llamadas; la [primitiva de tamaño](docs/contracts/POP-SIZE.md) tiene 1.362 fixtures
que ejecutan sus callees originales en los dominios declarados.
El [banco de conversión x87/SSE](docs/contracts/FLOAT-CONVERSION.md) añade 3.360
observaciones nativas, incluidas entradas extended80 y contraejemplos de redondeo y anchura.
La [transferencia entre POPs](docs/contracts/POP-TRANSFER.md) tiene 1.504 casos del
núcleo completo, con contadores, saldo modular y cambios de región contrastados.
La [inicialización y reutilización](docs/contracts/POP-REUSE.md) añade 726 casos de
copia con capacidad existente y caminos completos de los wrappers.
La [construcción y append](docs/contracts/POP-APPEND.md) añade 594 casos, incluidos
324 recorridos completos de los wrappers cuando deben añadir un elemento, con
constructor, copia, destructor temporal y transferencia originales. Esos casos
usan capacidad libre y catálogos vacíos.
La [expansión del vector](docs/contracts/POP-GROWTH.md) se ejecuta además en 462
fixtures nativos con HeapAlloc/HeapFree reales, copia selectiva y destructores de
los elementos anteriores. Incluye 120 casos con buffers internos poblados y
216 de [reconstrucción de metadatos desde catálogos](docs/contracts/POP-CATALOG-COPY.md);
584 fixtures acotan la selección original de capacidad. Otros 192 ciclos nativos de
[construcción y destrucción](docs/contracts/POP-CONSTRUCTION.md) contrastan catálogos
poblados, inicialización de buffers y presencia/ausencia de cachés. El banco nativo
incluye además 192 ciclos del [recurso opcional](docs/contracts/POP-OPTIONAL.md),
con dos pools vinculados a `CGoodsPool` por RTTI. El banco nativo combinado suma
846 casos de esas fases. La [copia de pools con datos](docs/contracts/GOODS-POOL-COPY.md)
añade 540 fixtures emulados y 480 nativos, con crecimiento real y primer elemento
del destino conservado o creado en cero. El banco nativo combinado suma 1.326 casos
de esas fases. La [copia desde CPop con recurso fuente](docs/contracts/POP-OPTIONAL-COPY.md)
añade 180 secuencias nativas completas: asigna el primer pool y reconstruye el
segundo y los campos restantes. La ampliación combinada añade 216 copias/destrucciones
con ese recurso y distribuciones/catálogos poblados. El banco de esas fases suma 1.722 casos. Otros 216 casos de [identidad registrada](docs/contracts/POP-REGISTERED-IDENTITY.md)
contrastan alta, copia, expansión, baja y handles originales. El banco suma 1.938
casos; grafos de referencias de una partida, fallos de reserva y concurrencia siguen abiertos.
El [factory de nodos registrados](docs/contracts/POP-FACTORY.md) añade 1.053 ciclos
de creación y retirada originales, con nodos de 648 bytes, enlaces e identificador
dedicado contrastados. Incluye 648 ciclos con catálogos poblados: buffers
del temporal y de la copia comprobados antes de liberar. Al cerrar esa ampliación,
el banco nativo combinado sumaba 2.991 casos.
Los [llamadores y consumo por fases](docs/contracts/POP-VECTOR-CALLERS.md) añaden
324 llamadas completas al tercer wrapper y fragmentos separados de contexto/limpieza,
con tipos RTTI y sitios CALL contrastados. El [consumidor completo](docs/contracts/POP-CONSUMER.md) tiene 1.080 llamadas
nativas por la ruta que crea un nodo y registra el movimiento en árboles existentes.
La [fusión](docs/contracts/POP-MERGE.md) añade 3.780 llamadas aisladas al helper
y 1.152 consumidores nativos completos con un destino compatible existente.
Al cerrar esa fase, el banco nativo sumaba 5.223 casos; otras claves, integración
del selector y un tick real
siguen abiertos.
La [selección entre candidatos](docs/contracts/POP-SELECTION.md) añade 305 consumidores
completos emulados y 447 prefijos sin coincidencia. Contrasta prioridad de pasadas,
orden de lista y los cuatro sitios de fusión originales. La
[elección de tipo posterior](docs/contracts/POP-FACTORY-SELECTION.md) añade 1.536
consumidores nativos completos: conserva la última entrada elegible, no la mínima.
El [selector interno](docs/contracts/FACTORY-INTERNAL-SELECTOR.md) añade 2.178
llamadas nativas completas con ambas ramas virtuales: conserva el primero entre
solicitado y alternativo presente en las filas. Otros 960 factories completos
contrastan su integración, con 216 cambios de tipo y bucket. El banco nativo suma
9.897 casos.
La [acotación de precios del mercado](docs/contracts/PRICE-CLAMP.md) añade 36
afirmaciones reverify sobre constantes y lógica de clamping, con 228 fixtures
emulados de la rutina original PE32 sin discrepancias.
El [cálculo de probabilidad por MTTH](docs/contracts/EVENT-MTTH.md) añade 44
afirmaciones reverify sobre constantes, llamadas y ramas del escaneo de eventos,
con 602 fixtures emulados del cálculo original sin discrepancias.
La [ponderación de opciones de IA](docs/contracts/EVENT-AI-CHANCE.md) añade 33
afirmaciones reverify sobre modificadores, cortocircuitos y llamadas en Event_Fire,
con 97 fixtures emulados del cálculo original sin discrepancias.
El [despacho y encolado de eventos](docs/contracts/EVENT-SPAWN.md) añade 37
afirmaciones reverify sobre vtables, LCG de 2 pasos y bifurcación inmediata/diferida,
con 66 fixtures emulados de `CCountryEventEffect::Execute` sin discrepancias.
El [consumo diario de eventos diferidos](docs/contracts/EVENT-DELAYED-TICK.md) añade 27
afirmaciones reverify sobre el recorrido de la cola del país, decremento y disparo,
con 37 series de fixtures emulados de `CCountry::DailyUpdate` sin discrepancias.
El [despacho provincial de eventos](docs/contracts/PROVINCE-EVENT-SPAWN.md) añade 36
afirmaciones reverify sobre vtables, LCG y encolado en `province + 0x384`,
con 66 fixtures emulados de `CProvinceEventEffect::Execute` sin discrepancias.
El [consumo diario de eventos provinciales diferidos](docs/contracts/PROVINCE-EVENT-DELAYED-TICK.md)
añade 25 afirmaciones reverify sobre el recorrido del vector provincial, decremento y
corrimiento in-situ, con 21 series de fixtures emulados sin discrepancias.
La [dinámica de precios y acotación diaria](docs/contracts/MARKET-PRICE-DELTA.md) añade 19
afirmaciones reverify sobre la constante de 1%, zona muerta de histéresis y paso diario,
con 67 fixtures emulados sin discrepancias.
La [curva de sensibilidad de precios](docs/contracts/MARKET-SENSITIVITY-CURVE.md) añade 38
afirmaciones reverify sobre los 13 tramos discretos y fallback sub-lineal por raíz cuadrada,
con 286 fixtures emulados de la rutina PE32 sin discrepancias.
La [producción industrial y consumo de insumos](docs/contracts/FACTORY-PRODUCTION.md) añade 34
afirmaciones reverify sobre el cálculo de output por nivel y throughput, y el consumo de inputs,
con 150 fixtures emulados sin discrepancias.
El [cálculo de life rating provincial](docs/contracts/PROVINCE-LIFE-RATING.md) añade 29
afirmaciones reverify sobre el escalado por tecnologías de salud y el clamping estricto a 40.0,
con 199 fixtures emulados sin discrepancias.
La [recaudación impositiva e ingresos nacionales](docs/contracts/COUNTRY-TAX-REVENUE.md) añade 44
afirmaciones reverify sobre el cálculo de impuestos a los tres estratos sociales y normalización por 32,768,000,
con 141 fixtures emulados sin discrepancias.
El [modificador administrativo del gasto nacional](docs/contracts/COUNTRY-ADMIN-MODIFIER.md) añade 35
afirmaciones reverify sobre el escalado tecnológico a 30 bits y la selección de políticas gubernamentales,
con 272 fixtures emulados sin discrepancias.
La [doble acotación y fijación de aranceles nacionales](docs/contracts/COUNTRY-TARIFF-CLAMP.md) añade 45
afirmaciones reverify sobre el clamping estricto (piso y techo) según la política económica del gobierno,
con 350 fixtures emulados sin discrepancias.
El [consumo y saturación de cuotas de promoción](docs/contracts/PROMOTION-QUOTA.md) añade 43
afirmaciones reverify sobre el clamping por capacidad disponible de fábrica/estrato y desvinculación de nodos saturados,
con 106 fixtures emulados sin discrepancias.
La [actualización de tamaño, clamping y disparo de cuotas de POPs](docs/contracts/POP-SET-SIZE.md) añade 57
afirmaciones reverify sobre el clamping estricto [0, 2,000,000], la rotación del historial demográfico y
el enlace directo con las cuotas de absorción provincial, con 1,218 fixtures emulados sin discrepancias.
La [transferencia demográfica y absorción por umbral mínimo](docs/contracts/POP-TRANSFER-THRESHOLD.md) añade 72
afirmaciones reverify sobre los 3 canales de transición demográfica (promoción, asimilación y conversión),
la absorción forzada de micro-POPs y la conservación de masa poblacional, con 111 fixtures emulados sin discrepancias.
La [agregación de financiación y gasto por categoría](docs/contracts/COUNTRY-CATEGORY-SPENDING.md) añade 95
afirmaciones reverify sobre la agregación ponderada de 4 canales de gasto con escalado a 15 bits
y clamping inferior estricto a cero, con 158 fixtures emulados sin discrepancias.
La [agregación nacional de infraestructura y tecnología](docs/contracts/COUNTRY-INFRASTRUCTURE-MODIFIER.md) añade 49
afirmaciones reverify sobre la agregación de unidades provinciales, la normalización tecnológica doble a 30 bits
y el bono base nacional, con 124 fixtures emulados sin discrepancias.
El [despacho de modificadores provinciales](docs/contracts/PROVINCE-MODIFIER-DISPATCH.md) añade 38
afirmaciones reverify sobre la tabla de saltos canónica de 8 slots y acumulación aditiva,
con 132 fixtures emulados sin discrepancias.
La [doble acotación política del slider de gasto nacional](docs/contracts/COUNTRY-CATEGORY-SPENDING-CLAMP.md) añade 70
afirmaciones reverify sobre la normalización de cotas políticas a 30 bits y el clamping min/max de 64 bits,
con 137 fixtures emulados sin discrepancias.
El [cálculo de puntuación de base naval y eficiencia costera](docs/contracts/COUNTRY-NAVAL-BASE-SCORE.md) añade 73
afirmaciones reverify sobre la división de centenas, la constante de piso de 5% y el techo del 100%,
con 127 fixtures emulados sin discrepancias.
La [asignación y distribución de cuotas por estrato](docs/contracts/PROVINCE-PROMOTION-TARGET-ALLOCATION.md) añade 170
afirmaciones reverify sobre el amortiguamiento de 30 bits, el clamping de paso mínimo de 50 POPs y la distribución voraz a candidatos,
con 119 fixtures emulados sin discrepancias.
La [agregación de suministro militar y mantenimiento](docs/contracts/COUNTRY-MILITARY-SUPPLY-FACTOR.md) añade 52
afirmaciones reverify sobre la acumulación aditiva doctrina/defines/tecnología, normalización a 30 bits y reseteo de pools,
con 126 fixtures emulados sin discrepancias.
La [compuerta de financiación con margen de reserva del 110% en proyectos](docs/contracts/PROJECT-BUFFER-FUNDING-GATE.md) añade 55
afirmaciones reverify sobre la discriminación de etapas, el multiplicador de reserva 36045/32768 y la comparación lexicográfica de 64 bits,
con 142 fixtures emulados sin discrepancias.
La [elegibilidad y cupo máximo de fábricas por estado](docs/contracts/STATE-FACTORY-BUILD-ELIGIBILITY.md) añade 154
afirmaciones reverify sobre la prohibición colonial, el límite universal de 8 fábricas, la no duplicidad, la reserva de cupo de IA y los prerrequisitos tecnológicos,
con 141 fixtures emulados sin discrepancias.
La [determinación de moral y organización máxima de regimientos](docs/contracts/REGIMENT-MAX-MORALE.md) añade 129
afirmaciones reverify sobre moral base, bono doctrinal, líderes, la excepción rebelde ("REB") y el piso irreducible del 25% presupuestario,
con 142 fixtures emulados sin discrepancias.
El [cálculo de moral media y organización de ejércitos y flotas](docs/contracts/ARMY-AVERAGE-MORALE.md) añade 119
afirmaciones reverify sobre vtables de CUnit/CArmy/CNavy, agregación de subunidades, normalización por recuento, doctrina y bonificación de líderes,
con 180 fixtures emulados sin discrepancias.
El [límite de suministro territorial y capacidad de aprovisionamiento de ejércitos](docs/contracts/ARMY-SUPPLY-LIMIT.md) añade 126
afirmaciones reverify sobre la vtable de CArmy, bases territoriales (amiga vs hostil), el patrón CNullLeader, tecnología de intendencia, penalizaciones de terreno, techo provincial y bonificación de estacionamiento,
con 154 fixtures emulados sin discrepancias.
La [proporción relativa de fuerza y cuota de bando en batalla](docs/contracts/COMBAT-FORCE-RATIO.md) añade 83
afirmaciones reverify sobre vtables polimórficas de batalla (CCombat, CLandCombat, CNavalCombat), suelo de combatientes, conmutación por desbordamiento en 2,147,482 y caminos idiv vs _allmul/_alldiv,
con 134 fixtures emulados sin discrepancias.
La [determinación del ancho de frente de combate](docs/contracts/COMBAT-FRONTAGE.md) añade 92
afirmaciones reverify sobre CCombat::CalculateFrontage, mínimos tecnológicos de coalición, penalizaciones de terreno provincial y división mágica por compilador (0x10624DD3),
con 198 fixtures emulados sin discrepancias.
El [avance de refuerzos y despliegue de segunda línea](docs/contracts/COMBAT-LINE-REINFORCEMENT.md) añade 55
afirmaciones reverify sobre CLandCombatant::AdvanceReinforcementLine, la secuencia de barrido central alternante (16, 15, 17, 14...), el blindaje de retaguardia para artillería (support > 0) y el desborde de flancos para infantería,
con 73 fixtures emulados sin discrepancias.
La [tabla universal de daño por tirada de combate](docs/contracts/COMBAT-DICE-DAMAGE-TABLE.md) añade 165
afirmaciones reverify sobre CCombat::LookupDiceDamage, inicialización perezosa con floor/ftol2, las 18 constantes IEEE 754 y la curva progresiva de efectividad (20 a 900),
con 45 fixtures emulados sin discrepancias.
La [selección y adquisición de objetivos tácticos por maniobra](docs/contracts/COMBAT-TARGET-ACQUISITION.md) añade 135
afirmaciones reverify sobre CLandCombatant::FindTargetRegiment, las 4 fases de adquisición (frente directo, flanqueo frontal, retaguardia directa y flanqueo en retaguardia) y el filtro de operatividad de 100 hombres / 1.0 de organización,
con 45 fixtures emulados sin discrepancias.
La [ejecución del ataque de regimiento y cómputo de bajas](docs/contracts/COMBAT-REGIMENT-ATTACK.md) añade 156
afirmaciones reverify sobre CLandCombatant::ExecuteRegimentAttack, la integración de target táctico, fases fuego/choque, tabla de daño por tirada, escala por soporte/fuerza, mitigación por fuertes/recon, tácticas y defensa,
con 86 fixtures emulados sin discrepancias.
La [poda de regimientos quebrantados y compactación centrípeta de línea](docs/contracts/COMBAT-LINE-CONSOLIDATION.md) añade 158
afirmaciones reverify sobre CLandCombatant::PruneAndConsolidateLine, la detección de colapso (<100 hombres o <1.0 org), despacho a listas de retirada/desbandada, relevo de retaguardia y deslizamiento centrípeto de huecos,
con 39 fixtures emulados sin discrepancias.
La [determinación de victoria, retirada y aniquilación total (stackwipe)](docs/contracts/COMBAT-VICTORY-STACKWIPE.md) añade 233
afirmaciones reverify sobre CCombat::EvaluateVictoryAndStackwipe (slot 11 en vtables de combate), la regla de stackwipe 2:1 por colapso moral o cerco geográfico, y la entrega al despachador de conclusión de batalla,
con 73 fixtures emulados sin discrepancias.
La [prioridad táctica y ordenación de reserva de combate](docs/contracts/COMBAT-RESERVE-PRIORITY.md) añade 40
afirmaciones reverify sobre CSubUnit::CompareTacticalValue, el cómputo de puntuación moral-táctica ponderada por fuerza, la inoperatividad por liderazgo inhabilitado y el punto de llamada en la inserción ordenada de reservas (0x005AB8B7),
con 64 fixtures emulados sin discrepancias.
La [proporción relativa de fuerza del atacante](docs/contracts/COMBAT-ATTACKER-RATIO.md) añade 83
afirmaciones reverify sobre CCombat::CalculateAttackerStrengthRatio (slot 6 en vtables de combate), la constante flotante de 1.5, el clamping inferior a 1 hombre, y la bifurcación 32-bit vs 64-bit para evitar overflow en batallas masivas,
con 45 fixtures emulados sin discrepancias.
La [suficiencia de suministro y carga logística provincial](docs/contracts/ARMY-SUPPLY-SUFFICIENCY.md) añade 70
afirmaciones reverify sobre CArmy::EvaluateSupplySufficiency (slot 3 en vtable de CArmy en 0x00DF8950), el manejo de zonas marítimas y transportes, la agregación de peso logístico de ejércitos aliados del mismo país y la suma de capacidad de intendencia,
con 44 fixtures emulados sin discrepancias.
El [posicionamiento y factor de fuerza en combate naval](docs/contracts/NAVAL-COMBAT-RATIO.md) añade 30
afirmaciones reverify sobre CNavalCombat::CalculateForceRatio (slot 6 en vtable de combate naval en 0x00E02450), la discretización por la constante mágica 0x10624DD3, el cálculo del diferencial respecto a 100,000 milésimas y la normalización de 64 bits por _allmul/_alldiv,
con 36 fixtures emulados sin discrepancias.
La [viabilidad de refuerzo demográfico de regimiento](docs/contracts/REGIMENT-REINFORCE.md) añade 36
afirmaciones reverify sobre CRegiment::CanReinforce (slot 20 en vtable de CRegiment en 0x00DF88D4), el manejo de POP de origen extinto, verificación territorial de país soberano y delegación a corredores de acceso militar / suministro (0x005CC2E0),
con 40 fixtures emulados sin discrepancias.
La [determinación polimórfica de fuerza total de formación militar](docs/contracts/FORMATION-TOTAL-STRENGTH.md) añade 42
afirmaciones reverify sobre CArmy::CalculateTotalStrength (0x005D61A0, slot 10 en CArmy en 0x00DF88F4) y CNavy::CalculateTotalStrength (0x005D91D0, slot 10 en CNavy en 0x00E02FF4), la agregación por lista enlazada de subunidades, la escala naval de 1000 hombres por buque y el enlace con el cómputo de ratio de combate,
con 59 fixtures emulados sin discrepancias.
La [agregación de carga logística provincial y presencia de tropas](docs/contracts/PROVINCE-TROOP-STRENGTH.md) añade 112
afirmaciones reverify sobre CProvince::CalculateFriendlyTroopStrength (0x005DC200) y CProvince::CalculateTotalTroopStrength (0x005DC2A0), su integración como motor de carga en CArmy::CalculateSupplyLimit (0x005D63E0), y la diferenciación soberana en territorio amistoso frente a saturación irrestricta en territorio hostil,
con 34 fixtures emulados sin discrepancias.
La [aplicación diaria de bajas y desglose de pérdidas de combate](docs/contracts/COMBAT-CASUALTY-COMMIT.md) añade 99
afirmaciones reverify sobre CCombatant::CommitCasualtiesAndMoraleLoss (0x005DC330) y CCombatant::CommitCasualtiesByUnitType (0x005DC3C0), su invocación en CCombat::ResolveDailyCasualtiesAndMoraleLoss (0x00595E71 y 0x00595F12), y la amortiguación contra efectivos negativos y desglose por categoría táctica,
con 40 fixtures emulados sin discrepancias.
El [censo y clasificación de subunidades de formación militar](docs/contracts/SUBUNIT-CENSUS.md) añade 70
afirmaciones reverify sobre CCombatant::CountRegimentsByFilterObject (0x005DC050) y CCombatant::CountRegimentsByDirectId (0x005DC0A0), el recorrido de la lista enlazada de subunidades, el filtrado por categoría de arma o ID de tipo, y su consumo en CCombatView::UpdateUnitTypeIcons (0x00786B65, 0x00786BE3, 0x00786C67),
con 88 fixtures emulados sin discrepancias.
El [cómputo de fuerza efectiva y fuerza actual de combatiente militar](docs/contracts/COMBATANT-STRENGTH.md) añade 117
afirmaciones reverify sobre CCombatant::CalculateEffectiveStrength (0x005DC0E0) y CCombatant::CalculateTotalCurrentStrength (0x005DC180), la evaluación polimórfica de IsLand() (slot 9 en CRegiment y CShip), la agregación viva frente a dotación naval (+0x244), y su consumo en CCombat y CCombatView,
con 58 fixtures emulados sin discrepancias.
La [ponderación de moral media y organización máxima de combatiente](docs/contracts/COMBATANT-MORALE.md) añade 157
afirmaciones reverify sobre CCombatant::CalculateAverageMorale (0x005DC630) y CCombatant::CalculateAverageMaxMorale (0x005DC710), la agregación ponderada en 64 bits por recuento de tropas, la delegación virtual a CUnit::CalculateAverageMorale (slot 37 en 0x005C8DC0) y CUnit::CalculateMaxMorale (slot 17 en 0x005CFA90), y su consumo directo en la barra de moral de CCombatView,
con 78 fixtures emulados sin discrepancias.
El [recuento de subunidades y cómputo de peso de suministro militar](docs/contracts/SUBUNIT-WEIGHT.md) añade 85
afirmaciones reverify sobre CCombatant::CountTotalRegiments (0x005DC560), CArmy::CalculateSupplyWeight (0x005DC590) y CCombatant::CalculateSupplyWeight (0x005DC5D0), la división por 1000 optimizada por 0x10624DD3, y su consumo en CBattleReport, CShipView (capacidad de embarque) y CArmyView,
con 66 fixtures emulados sin discrepancias.
La [determinación de amenaza hostil provincial y fuerzas beligerantes](docs/contracts/HOSTILE-TROOP.md) añade 136
afirmaciones reverify sobre CProvince::CalculateHostileTroopDivisions (0x005DC7C0) y CProvince::CountHostileRegiments (0x005DC8B0), el filtro de flotas navales (IsNavy(), slot 15), la exclusión de tropas nacionales propias, la evaluación diplomática beligerante/rebelde (tag REB) y la normalización de divisiones por la constante mágica 0x10624DD3,
con 30 fixtures emulados sin discrepancias.
La [determinación de fuerza hostil naval y censo directo de beligerancia provincial](docs/contracts/HOSTILE-NAVAL-DIRECT.md) añade 150
afirmaciones reverify sobre CProvince::CalculateHostileNavalDivisions (0x005DC940) y CProvince::CountHostileUnitsDirect (0x005DCA30), la dualidad polimórfica de slots 14 y 15 (IsLand vs IsNavy en CArmy y CNavy), el cómputo de divisiones por 0x10624DD3, y su consumo en el motor de patrulla/bloqueo costero y evaluación de guarnición,
con 60 fixtures emulados sin discrepancias.
La [capacidad de aprovisionamiento y límite de suministro naval](docs/contracts/NAVY-SUPPLY-LIMIT.md) añade 120
afirmaciones reverify sobre CNavy::CalculateSupplyLimit (0x005D81A0, slot 30 en CNavy en 0x00E03044), el homólogo marítimo de CArmy::CalculateSupplyLimit, el filtro de bases registradas en CGameState, exclusión de mar abierto, comprobación de atraque y bloqueo hostil, escala de 2000 por nivel de base, rasgo de almirante y tecnología naval en 64 bits,
con 45 fixtures emulados sin discrepancias.
El [mantenimiento operativo y evaluación de atrición naval](docs/contracts/NAVY-ATTRITION-RESUPPLY.md) añade 121
afirmaciones reverify sobre CNavy::CalculateSeaAttrition (0x005D7EC0, slot 31 en CNavy en 0x00E03048) y CNavy::EvaluateResupplyNecessity (0x005D8120), el periodo de gracia en alta mar por 0x10624DD3, el cálculo de desgaste por alcance de base naval, la delegación a CUnit::CalculateAverageSubunitHealthRatio (slot 21 en 0x005CFE90) y el umbral de carenado portuario del 85.0% (0x00E45ADC),
con 20 fixtures emulados sin discrepancias.
La [evaluación de cohesión y ratios promedio de fuerza y moral en formaciones militares](docs/contracts/FORMATION-COHESION.md) añade 214
afirmaciones reverify sobre CUnit::CalculateAverageSubunitStrengthRatio (0x005CFE90, slot 21 en CArmy y CNavy) y CUnit::CalculateAverageSubunitMoraleRatio (0x005CFF90, slot 22 en CArmy y CNavy), la consulta polimórfica a CSubUnit::GetMaxStrength (slot 12 en CRegiment y CShip) y CSubUnit::GetMaxMorale (slot 13 en CRegiment y CShip), la anulación de moral para POPs rebeldes, las cotas de desbordamiento de 32 bits (0x189373/0x39580d) y la normalización por conteo en 64 bits,
con 60 fixtures emulados sin discrepancias.
El [ciclo diario de mantenimiento naval y aplicación de daño por atrición](docs/contracts/NAVY-DAILY-UPDATE.md) añade 112
afirmaciones reverify sobre CNavy::DailyUpdate (0x005C7AE0, slot 29 en CNavy en 0x00E03040) y CSubUnit::SetStrength (0x005C02F0), el control de atrición global en CGameState (+0xD1C), el umbral de alcance naval en MilitaryDefines (+0xE4), el acumulador de días en alta mar (+0x1BC), el piso de supervivencia del buque (+0xE8) y el clamping de fuerza a [0, max_strength],
con 40 fixtures emulados sin discrepancias.
La [evaluación de potencia de combate efectiva y calificación táctica de subunidades](docs/contracts/UNIT-COMBAT-POWER.md) añade 159
afirmaciones reverify sobre CUnitType::CalculateCombatRating (0x005BDC80) y CUnit::CalculateEffectiveCombatPower (0x005D0500, slot 25 en CArmy en 0x00DF8930 y CNavy en 0x00E03030), la consulta a CSubUnit::GetMaxStrength (slot 12 en CRegiment y CShip), la bifurcación de atributos terrestres y navales por las constantes flotantes en 0x00E45998 (1000.5f), 0x00E45840 (0.0005) y 0x00E45660 (1000.0), el cálculo de factor tecnológico naval y la ponderación por ratio de salud viva en 64 bits,
con 54 fixtures emulados sin discrepancias.
La [evaluación de potencia de combate completa con moral, experiencia y tecnología](docs/contracts/UNIT-FULL-COMBAT-POWER.md) añade 197
afirmaciones reverify sobre CUnit::CalculateFullCombatPower (0x005D02F0, slot 26 en CArmy en 0x00DF8934 y CNavy en 0x00E03034), la consulta polimórfica a CSubUnit::GetMaxStrength (slot 12) y CSubUnit::GetMaxMorale (slot 13), el multiplicador de experiencia militar por la constante en 0x00E45BBC (10.5f -> 10 milésimas en 0x0125FED8), el umbral de desmoralización/quebranto del 50% por la constante en 0x00E45A18 (100.5f -> 100), y el escalado doctrinal/tecnológico nacional por MilitaryDefines (+0xE0) y MilitaryStats (+0x70),
con 38 fixtures emulados sin discrepancias.
La [evaluación de experiencia media y fuerza máxima total en formaciones militares](docs/contracts/FORMATION-EXPERIENCE-MAX-STRENGTH.md) añade 99
afirmaciones reverify sobre CUnit::CalculateAverageExperience (0x005CF8B0, slot 19 en CArmy en 0x00DF8918 y CNavy en 0x00E03018) y CUnit::CalculateTotalMaxStrength (0x005CF950, slot 20 en CArmy en 0x00DF891C y CNavy en 0x00E0301C), la agregación por lista enlazada de subunidades, la consulta directa a m_max_strength (+0xB0) de CUnitType, y la normalización de experiencia por el conteo de la formación mediante _allmul y _alldiv de 64 bits,
con 45 fixtures emulados sin discrepancias.
La [evaluación de moral media y fuerza viva media en formaciones militares](docs/contracts/FORMATION-AVERAGE-STATS.md) añade 107
afirmaciones reverify sobre CUnit::CalculateAverageMorale (0x005CFA90, slot 17 en CArmy en 0x00DF8910 y CNavy en 0x00E03010) y CUnit::CalculateAverageStrength (0x005CFB10, slot 18 en CArmy en 0x00DF8914 y CNavy en 0x00E03014), la filtración condicional de moral nula para POPs de origen rebelde (+0x74/+0x164), la acumulación lineal sobre la lista enlazada de subunidades y la normalización de 64 bits por el conteo de tropas,
con 45 fixtures emulados sin discrepancias.






