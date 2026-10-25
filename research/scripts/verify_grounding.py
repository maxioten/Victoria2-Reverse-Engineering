#!/usr/bin/env python3
"""Run the local evidence gates; stop immediately if any verifier fails."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
scripts = ('verify_claims.py', 'emulate_null_release.py', 'verify_calendar.py',
           'verify_tick_path.py', 'verify_rng.py', 'verify_daily_rng.py',
           'verify_rng_restore.py', 'verify_pop_schedule.py', 'verify_pop_unlink.py',
           'verify_pop_destructor.py', 'verify_object_registry.py', 'verify_integer_helpers.py',
           'verify_distribution.py', 'inventory_rtti.py', 'verify_pop_update.py', 'verify_pop_size.py',
           'verify_float_conversion.py', 'verify_pop_transfer.py', 'verify_pop_reuse.py', 'verify_pop_append.py',
           'verify_pop_growth.py', 'verify_pop_optional.py', 'verify_goods_pool_copy.py',
           'verify_pop_vector_callers.py', 'verify_pop_factory.py', 'verify_pop_consumer.py', 'verify_pop_merge.py', 'verify_pop_selection.py', 'verify_pop_factory_selection.py', 'verify_factory_internal_selector.py',
              'verify_price_clamp.py', 'verify_mtth.py', 'verify_ai_chance.py',
              'verify_event_spawn.py', 'verify_delayed_event_tick.py',
              'verify_province_event_spawn.py', 'verify_province_event_delayed_tick.py',
              'verify_market_price_delta.py', 'verify_market_sensitivity_curve.py',
              'verify_factory_production.py', 'verify_province_life_rating.py',
              'verify_country_tax_revenue.py', 'verify_country_admin_modifier.py',
              'verify_country_tariff_clamp.py', 'verify_promotion_quota.py',
              'verify_pop_set_size.py', 'verify_pop_transfer_threshold.py',
              'verify_country_category_spending.py', 'verify_country_infrastructure.py',
                'verify_province_modifier_dispatch.py', 'verify_country_spending_clamp.py',
                'verify_country_naval_base.py', 'verify_province_target_quota.py',
                'verify_country_military_supply.py', 'verify_project_buffer.py',
                'verify_state_factory_build.py', 'verify_regiment_max_morale.py',
                'verify_army_average_morale.py', 'verify_army_supply_limit.py',
                'verify_combat_force_ratio.py', 'verify_combat_frontage.py',
                'verify_combat_reinforcement.py', 'verify_combat_dice_damage.py',
                'verify_combat_target_acquisition.py', 'verify_combat_regiment_attack.py',
                'verify_combat_line_consolidation.py', 'verify_combat_victory_stackwipe.py',
                'verify_combat_reserve_priority.py', 'verify_combat_attacker_ratio.py',
                'verify_army_supply_sufficiency.py', 'verify_naval_combat_ratio.py',
                'verify_regiment_reinforce.py', 'verify_formation_total_strength.py',
                'verify_province_troop_strength.py', 'verify_combat_casualty_commit.py',
                'verify_subunit_census.py', 'verify_combatant_strength.py',
                'verify_combatant_morale.py', 'verify_subunit_weight.py',
                'verify_hostile_troop.py', 'verify_hostile_naval_direct.py',
                'verify_navy_supply_limit.py', 'verify_navy_attrition_resupply.py',
                'verify_formation_cohesion.py', 'verify_navy_daily_update.py',
                'verify_unit_combat_power.py', 'verify_unit_full_combat_power.py',
                'verify_formation_experience_max_strength.py', 'verify_formation_average_stats.py')
for script in scripts:
    subprocess.run([sys.executable, str(ROOT / 'scripts' / script)], check=True, cwd=ROOT)

artifacts = (
    'reverify/verified.json', 'reverify/negative-controls.json',
    'reverify/semantic-limit.json', 'crt-null-release.json',
    'calendar/reverify.json', 'calendar/emulation.json', 'calendar/model-proof.smt2',
    'tick-path/reverify.json', 'tick-path/cfg.json',
    'rng/reverify.json', 'rng/emulation.json', 'daily-rng/reverify.json', 'daily-rng/emulation.json',
    'rng-restore/reverify.json', 'rng-restore/emulation.json',
    'pop-schedule/reverify.json', 'pop-schedule/emulation.json',
    'pop-unlink/reverify.json', 'pop-unlink/emulation.json',
    'pop-destructor/reverify.json', 'pop-destructor/emulation.json',
    'object-registry/reverify.json', 'object-registry/emulation.json',
    'integer-helpers/reverify.json', 'integer-helpers/emulation.json',
    'distribution/reverify.json', 'distribution/emulation.json',
    'rtti/reverify.json', 'rtti/selected.json',
    'pop-update/reverify.json', 'pop-update/cfg.json',
    'pop-size/reverify.json', 'pop-size/emulation.json',
    'float-conversion/reverify.json',
    'pop-transfer/reverify.json', 'pop-transfer/emulation.json',
    'pop-reuse/reverify.json', 'pop-reuse/emulation.json',
    'pop-append/reverify.json', 'pop-append/emulation.json',
    'pop-growth/reverify.json', 'pop-growth/capacity.json',
    'pop-optional/reverify.json',
    'goods-pool-copy/reverify.json', 'goods-pool-copy/emulation.json',
    'pop-vector-callers/reverify.json','pop-vector-callers/emulation.json',
    'pop-vector-callers/call-reference-snapshot.json',
    'pop-factory/reverify.json', 'pop-consumer/reverify.json',
    'pop-merge/reverify.json','pop-merge/emulation.json',
    'pop-selection/reverify.json','pop-selection/emulation.json',
    'pop-factory-selection/reverify.json','pop-factory-selection/emulation.json',
    'factory-internal-selector/reverify.json','factory-internal-selector/call-reference-snapshot.json',
    'price-clamp/reverify.json', 'price-clamp/negative-controls.json', 'price-clamp/emulation.json',
    'mtth/reverify.json', 'mtth/negative-controls.json', 'mtth/emulation.json',
    'ai-chance/reverify.json', 'ai-chance/negative-controls.json', 'ai-chance/emulation.json',
    'event-spawn/reverify.json', 'event-spawn/negative-controls.json', 'event-spawn/emulation.json',
    'event-delayed-tick/reverify.json', 'event-delayed-tick/negative-controls.json', 'event-delayed-tick/emulation.json',
    'province-event-spawn/reverify.json', 'province-event-spawn/negative-controls.json', 'province-event-spawn/emulation.json',
    'province-event-delayed-tick/reverify.json', 'province-event-delayed-tick/negative-controls.json', 'province-event-delayed-tick/emulation.json',
    'market-price-delta/reverify.json', 'market-price-delta/negative-controls.json', 'market-price-delta/emulation.json',
    'market-sensitivity-curve/reverify.json', 'market-sensitivity-curve/negative-controls.json', 'market-sensitivity-curve/emulation.json',
    'factory-production/reverify.json', 'factory-production/negative-controls.json', 'factory-production/emulation.json',
    'province-life-rating/reverify.json', 'province-life-rating/negative-controls.json', 'province-life-rating/emulation.json',
    'country-tax-revenue/reverify.json', 'country-tax-revenue/negative-controls.json', 'country-tax-revenue/emulation.json',
    'country-admin-modifier/reverify.json', 'country-admin-modifier/negative-controls.json', 'country-admin-modifier/emulation.json',
    'country-tariff-clamp/reverify.json', 'country-tariff-clamp/negative-controls.json', 'country-tariff-clamp/emulation.json',
    'promotion-quota/reverify.json', 'promotion-quota/negative-controls.json', 'promotion-quota/emulation.json',
    'pop-set-size/reverify.json', 'pop-set-size/negative-controls.json', 'pop-set-size/emulation.json',
    'pop-transfer-threshold/reverify.json', 'pop-transfer-threshold/negative-controls.json', 'pop-transfer-threshold/emulation.json',
    'country-category-spending/reverify.json', 'country-category-spending/negative-controls.json', 'country-category-spending/emulation.json',
    'country-infrastructure/reverify.json', 'country-infrastructure/negative-controls.json', 'country-infrastructure/emulation.json',
    'province-modifier-dispatch/reverify.json', 'province-modifier-dispatch/negative-controls.json', 'province-modifier-dispatch/emulation.json',
    'country-spending-clamp/reverify.json', 'country-spending-clamp/negative-controls.json', 'country-spending-clamp/emulation.json',
    'country-naval-base/reverify.json', 'country-naval-base/negative-controls.json', 'country-naval-base/emulation.json',
    'province-target-quota/reverify.json', 'province-target-quota/negative-controls.json', 'province-target-quota/emulation.json',
    'country-military-supply/reverify.json', 'country-military-supply/negative-controls.json', 'country-military-supply/emulation.json',
    'project-buffer/reverify.json', 'project-buffer/negative-controls.json', 'project-buffer/emulation.json',
    'state-factory-build/reverify.json', 'state-factory-build/negative-controls.json', 'state-factory-build/emulation.json',
    'regiment-max-morale/reverify.json', 'regiment-max-morale/negative-controls.json', 'regiment-max-morale/emulation.json',
    'army-average-morale/reverify.json', 'army-average-morale/negative-controls.json', 'army-average-morale/emulation.json',
    'army-supply-limit/reverify.json', 'army-supply-limit/negative-controls.json', 'army-supply-limit/emulation.json',
    'combat-force-ratio/reverify.json', 'combat-force-ratio/negative-controls.json', 'combat-force-ratio/emulation.json',
    'combat-frontage/reverify.json', 'combat-frontage/negative-controls.json', 'combat-frontage/emulation.json',
    'combat-reinforcement/reverify.json', 'combat-reinforcement/negative-controls.json', 'combat-reinforcement/emulation.json',
    'combat-dice-damage/reverify.json', 'combat-dice-damage/negative-controls.json', 'combat-dice-damage/emulation.json',
    'combat-target-acquisition/reverify.json', 'combat-target-acquisition/negative-controls.json', 'combat-target-acquisition/emulation.json',
    'combat-regiment-attack/reverify.json', 'combat-regiment-attack/negative-controls.json', 'combat-regiment-attack/emulation.json',
    'combat-line-consolidation/reverify.json', 'combat-line-consolidation/negative-controls.json', 'combat-line-consolidation/emulation.json',
    'combat-victory-stackwipe/reverify.json', 'combat-victory-stackwipe/negative-controls.json', 'combat-victory-stackwipe/emulation.json',
    'combat-reserve-priority/reverify.json', 'combat-reserve-priority/negative-controls.json', 'combat-reserve-priority/emulation.json',
    'combat-attacker-ratio/reverify.json', 'combat-attacker-ratio/negative-controls.json', 'combat-attacker-ratio/emulation.json',
    'army-supply-sufficiency/reverify.json', 'army-supply-sufficiency/negative-controls.json', 'army-supply-sufficiency/emulation.json',
    'naval-combat-ratio/reverify.json', 'naval-combat-ratio/negative-controls.json', 'naval-combat-ratio/emulation.json',
    'regiment-reinforce/reverify.json', 'regiment-reinforce/negative-controls.json', 'regiment-reinforce/emulation.json',
    'formation-total-strength/reverify.json', 'formation-total-strength/negative-controls.json', 'formation-total-strength/emulation.json',
    'province-troop-strength/reverify.json', 'province-troop-strength/negative-controls.json', 'province-troop-strength/emulation.json',
    'combat-casualty-commit/reverify.json', 'combat-casualty-commit/negative-controls.json', 'combat-casualty-commit/emulation.json',
    'subunit-census/reverify.json', 'subunit-census/negative-controls.json', 'subunit-census/emulation.json',
    'combatant-strength/reverify.json', 'combatant-strength/negative-controls.json', 'combatant-strength/emulation.json',
    'combatant-morale/reverify.json', 'combatant-morale/negative-controls.json', 'combatant-morale/emulation.json',
    'subunit-weight/reverify.json', 'subunit-weight/negative-controls.json', 'subunit-weight/emulation.json',
    'hostile-troop/reverify.json', 'hostile-troop/negative-controls.json', 'hostile-troop/emulation.json',
    'hostile-naval-direct/reverify.json', 'hostile-naval-direct/negative-controls.json', 'hostile-naval-direct/emulation.json',
    'navy-supply-limit/reverify.json', 'navy-supply-limit/negative-controls.json', 'navy-supply-limit/emulation.json',
    'navy-attrition-resupply/reverify.json', 'navy-attrition-resupply/negative-controls.json', 'navy-attrition-resupply/emulation.json',
    'formation-cohesion/reverify.json', 'formation-cohesion/negative-controls.json', 'formation-cohesion/emulation.json',
    'navy-daily-update/reverify.json', 'navy-daily-update/negative-controls.json', 'navy-daily-update/emulation.json',
    'unit-combat-power/reverify.json', 'unit-combat-power/negative-controls.json', 'unit-combat-power/emulation.json',
    'unit-full-combat-power/reverify.json', 'unit-full-combat-power/negative-controls.json', 'unit-full-combat-power/emulation.json',
    'formation-experience-max-strength/reverify.json', 'formation-experience-max-strength/negative-controls.json', 'formation-experience-max-strength/emulation.json',
    'formation-average-stats/reverify.json', 'formation-average-stats/negative-controls.json', 'formation-average-stats/emulation.json',
)
generated = ROOT / 'evidence/generated'
report = {
    'status': 'PASS',
    'scope': 'Only the assertions and input domains in the individual receipts; not full engine verification.',
    'scripts': list(scripts),
    'source_sha256': {
        name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
        for name in (*scripts, 'rng_model.py', 'integer_model.py', 'distribution_model.py',
                     'float_model.py', 'pop_transfer_model.py', 'pop_merge_model.py', 'pop_selection_model.py', 'pop_factory_selection_model.py', 'price_clamp_model.py', 'mtth_model.py', 'ai_chance_model.py', 'delayed_event_tick_model.py', 'event_spawn_model.py', 'province_event_spawn_model.py', 'province_event_delayed_tick_model.py', 'market_price_delta_model.py', 'market_sensitivity_curve_model.py', 'factory_production_model.py', 'province_life_rating_model.py', 'country_tax_revenue_model.py', 'country_admin_modifier_model.py', 'country_tariff_clamp_model.py', 'promotion_quota_model.py', 'pop_set_size_model.py', 'pop_transfer_threshold_model.py', 'country_category_spending_model.py', 'country_infrastructure_model.py', 'province_modifier_dispatch_model.py', 'country_spending_clamp_model.py', 'country_naval_base_model.py', 'province_target_quota_model.py', 'country_military_supply_model.py', 'project_buffer_model.py', 'state_factory_build_model.py', 'regiment_max_morale_model.py', 'army_average_morale_model.py', 'army_supply_limit_model.py', 'combat_force_ratio_model.py', 'combat_frontage_model.py', 'combat_reinforcement_model.py', 'combat_dice_damage_model.py', 'combat_target_acquisition_model.py', 'combat_regiment_attack_model.py', 'combat_line_consolidation_model.py', 'combat_victory_stackwipe_model.py', 'combat_reserve_priority_model.py', 'combat_attacker_ratio_model.py', 'army_supply_sufficiency_model.py', 'naval_combat_ratio_model.py', 'regiment_reinforce_model.py', 'formation_total_strength_model.py', 'province_troop_strength_model.py', 'combat_casualty_commit_model.py', 'subunit_census_model.py', 'combatant_strength_model.py', 'combatant_morale_model.py', 'subunit_weight_model.py', 'hostile_troop_model.py', 'hostile_naval_direct_model.py', 'navy_supply_limit_model.py', 'navy_attrition_resupply_model.py', 'formation_cohesion_model.py', 'navy_daily_update_model.py', 'unit_combat_power_model.py', 'unit_full_combat_power_model.py', 'formation_experience_max_strength_model.py', 'formation_average_stats_model.py', 'analyze_extended_float.py', 'verify_grounding.py')
    },
    'artifacts_sha256': {
        name: hashlib.sha256((generated / name).read_bytes()).hexdigest()
        for name in artifacts
    },
}
native_receipt = generated / 'elf32-integer/execution.json'
if native_receipt.exists():
    native = json.loads(native_receipt.read_text())
    if native.get('pass') is True:
        for relative, expected in (
            ('elf32-integer/integer-probe', native['elf_sha256']),
            ('elf32-integer/fixtures.bin', native['fixture_sha256']),
        ):
            assert hashlib.sha256((generated / relative).read_bytes()).hexdigest() == expected
        assert hashlib.sha256((ROOT / 'harnesses/elf32_integer_helpers.S').read_bytes()).hexdigest() == native['harness_source_sha256']
        report['additional_evidence'] = {'elf32_integer': {
            'pass':True,'fresh_execution_this_gate':False,
            'receipt_sha256':hashlib.sha256(native_receipt.read_bytes()).hexdigest(),
            'scope':native['scope'],
        }}
wine_receipt = generated / 'native-integer/execution.json'
if wine_receipt.exists():
    native = json.loads(wine_receipt.read_text())
    if native.get('pass') is True:
        assert hashlib.sha256((generated / 'native-integer/integer-probe.exe').read_bytes()).hexdigest() == native['exe_sha256']
        assert hashlib.sha256((generated / 'native-integer/fixtures.bin').read_bytes()).hexdigest() == native['fixture_sha256']
        assert hashlib.sha256((ROOT / 'harnesses/native_integer_helpers.c').read_bytes()).hexdigest() == native['source_sha256']
        report.setdefault('additional_evidence', {})['pe32_wine_integer'] = {
            'pass':True,'fresh_execution_this_gate':False,
            'receipt_sha256':hashlib.sha256(wine_receipt.read_bytes()).hexdigest(),'scope':native['scope'],
        }
pop_receipt = generated / 'native-pop/execution.json'
if pop_receipt.exists():
    native = json.loads(pop_receipt.read_text())
    if native.get('pass') is True:
        for path, expected in (
            (generated / 'native-pop/pop-probe.exe', native['exe_sha256']),
            (ROOT / 'harnesses/native_pop_lifetime.c', native['source_sha256']),
            (ROOT / 'harnesses/native_registry_cases.h', native['registry_source_sha256']),
            (ROOT / 'scripts/build_native_pop_probe.py', native['build_script_sha256']),
            (ROOT / 'scripts/run_native_pop_probe.py', native['runner_script_sha256']),
        ):
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, str(path)
        report.setdefault('additional_evidence', {})['pe32_wine_pop_lifetime'] = {
            'pass': True, 'fresh_execution_this_gate': False,
            'receipt_sha256': hashlib.sha256(pop_receipt.read_bytes()).hexdigest(),
            'scope': native['scope'], 'observed': native['observed'],
        }
float_receipt = generated / 'native-float/execution.json'
if float_receipt.exists():
    native = json.loads(float_receipt.read_text())
    if native.get('pass') is True:
        for path, expected in (
            (generated / 'native-float/float-probe.exe', native['exe_sha256']),
            (generated / 'native-float/fixtures.bin', native['fixture_sha256']),
            (generated / 'native-float/execution.stdout', native['stdout_sha256']),
            (generated / 'native-float/execution.stderr', native['stderr_sha256']),
            (ROOT / 'harnesses/native_float_conversion.c', native['source_sha256']),
            (ROOT / 'scripts/build_native_float_probe.py', native['build_script_sha256']),
            (ROOT / 'scripts/run_native_float_probe.py', native['runner_script_sha256']),
            (ROOT / 'scripts/float_model.py', native['model_source_sha256']),
        ):
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, str(path)
        subprocess.run([sys.executable,str(ROOT / 'scripts/analyze_extended_float.py')],check=True,cwd=ROOT)
        characterization=generated / 'native-float/extended-counterexamples.json'
        report.setdefault('additional_evidence', {})['pe32_wine_float_conversion'] = {
            'pass':True, 'fresh_execution_this_gate':False,
            'receipt_sha256':hashlib.sha256(float_receipt.read_bytes()).hexdigest(),
            'scope':native['scope'], 'observed':native['observed'],
            'characterization_sha256':hashlib.sha256(characterization.read_bytes()).hexdigest(),
        }
growth_receipt=generated/'native-growth/execution.json'
if growth_receipt.exists():
    native=json.loads(growth_receipt.read_text())
    if native.get('pass') is True:
        for path,expected in (
            (ROOT/'harnesses/native_pop_growth.c',native['source_sha256']),
            (ROOT/'harnesses/native_private_image.h',native['loader_source_sha256']),
            (ROOT/'scripts/build_native_growth_probe.py',native['build_script_sha256']),
            (ROOT/'scripts/run_native_growth_probe.py',native['runner_script_sha256']),
            (ROOT/'scripts/pop_merge_model.py',native['merge_model_source_sha256']),
            (ROOT/'scripts/pop_factory_selection_model.py',native['factory_selection_model_source_sha256']),
            (generated/'native-growth/growth-probe.exe',native['exe_sha256']),
            (generated/'native-growth/execution.stdout',native['stdout_sha256']),
            (generated/'native-growth/execution.stderr',native['stderr_sha256']),
        ):assert hashlib.sha256(path.read_bytes()).hexdigest()==expected,str(path)
        assert native['binary_sha256']=='62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648'
        report.setdefault('additional_evidence',{})['pe32_wine_pop_growth']={
            'pass':True,'fresh_execution_this_gate':False,
            'receipt_sha256':hashlib.sha256(growth_receipt.read_bytes()).hexdigest(),
            'scope':native['scope'],'observed':native['observed'],
        }
(generated / 'grounding-gate.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: local evidence gates. Receipts: ' + str(generated / 'grounding-gate.json'))
