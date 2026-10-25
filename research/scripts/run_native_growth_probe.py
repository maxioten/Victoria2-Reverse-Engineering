#!/usr/bin/env python3
"""Run the private-image growth probe using the established isolated Wine prefix."""
import hashlib
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
from pop_merge_model import merge
from pop_factory_selection_model import select_factory_type

ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'evidence/generated/native-growth'
build=json.loads((OUT/'build.json').read_text())
attempt=OUT/('attempt-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'));attempt.mkdir()
paths={ROOT/'harnesses/native_pop_growth.c':build['source_sha256'],
    ROOT/'harnesses/native_private_image.h':build['loader_source_sha256'],
    OUT/'growth-probe.exe':build['exe_sha256'],ROOT.parent/'base-game/v2game.exe':build['binary_sha256']}
for path,expected in paths.items():assert hashlib.sha256(path.read_bytes()).hexdigest()==expected,str(path)
for name in ('native_pop_growth.c','native_private_image.h'):(attempt/name).write_bytes((ROOT/'harnesses'/name).read_bytes())
(attempt/'build.json').write_bytes((OUT/'build.json').read_bytes())
receipt=dict(build,**{'pass':False},wine_version=subprocess.check_output(['wine','--version'],text=True).strip(),
    build_script_sha256=hashlib.sha256((ROOT/'scripts/build_native_growth_probe.py').read_bytes()).hexdigest(),
    runner_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    merge_model_source_sha256=hashlib.sha256((ROOT/'scripts/pop_merge_model.py').read_bytes()).hexdigest(),
    factory_selection_model_source_sha256=hashlib.sha256((ROOT/'scripts/pop_factory_selection_model.py').read_bytes()).hexdigest(),
    scope='Original relocated PE32 append with full old capacity, normal successful real CRT/HeapAlloc/HeapFree. '
          'Synthetic unregistered POPs, four distributions with null vectors or eight populated/non-null buffers, null optional resource, absent registries and empty/populated catalogs. '
          'New allocations filled with declared byte pattern. Full new allocation and pre-free old allocation checked, '
          'header update after old free, deep-copied buffer contents/capacities, external or aligned internal source, native FS:0 restored. '
          'Catalog metadata prefixes rebuilt; source surplus logical tails copied, original source/capacity/catalog bytes unchanged. '
          'Also complete default construction/destruction across catalog counts 0/1/3/7 and four cache-presence modes, '
          'pre-existing lazy singletons, type+0x39c zero, x87 initialized CW037F with host FX state restored. '
          '192 further cycles set type+0x39c=1, construct a 256-byte optional resource and its two vectors, then destroy/free them with original code. '
          '480 direct CGoodsPool copy cases include real successful vector growth, resize, preserved/zero first destination entry and source indices1 onward copied. '
          '180 full CPop copy/destructor sequences start with an optional source resource: first pool assigned, second pool/scalars reconstructed; '
          'intermediate first-buffer free during growth and all destination destruction frees checked. '
          '216 combined CPop copy/destructor cases also populate all distribution buffers with nonempty catalogs and logical source surplus0/2. '
          '108 registered-source copy/destructor and108 registered vector-growth cases execute original registration,lookup,handle refresh and deregistration with controlled live tables. '
          '1053 factory/unlink lifecycles (405 empty catalogs and648 populated catalogs) execute original4B8D30,default constructor954A40,real type-selector/setter virtual callees,list linking,key type2e registration and dedicated counterF09568,then unlink/destruction. '
          '1080 full4BA780 consumer cases use three pending slots (one positive,two nonpositive),original factory/initializer/size/log/cleanup callees and a pre-existing movement-tree entry;no callee returns substituted. '
          '1152 additional full consumer calls merge into a pre-existing compatible node via original964370,95A5F0,68DEA0/444F10 and tree searches. No original allocation/free during consumer;one original node free in subsequent harness unlink. Modular weighted attribute,saturating balance and raw event counters checked against independent model. '
          '1536 further complete consumer/factory cycles validate post-search type choice over0..3 catalog entries,real CPopType/CNullPopType virtual predicates,signed level comparisons and3 output buckets. Last eligible entry is kept;factory-internal selector preserves it via real null-type predicate. '
          '2178 full cdecl4B8C80 calls validate its true/false virtual predicate branches with pre-existing singleton,province index0/1/3 and all sequences of0..4 rows (other/requested/fallback);exact returned pointer,ABI/FS0 and all fixture bytes checked;no original heap activity. '
          '960 complete factory/unlink cycles integrate the internal selector when it changes type;actual selected-type payload and bucket0/1/2,identity and full destruction checked with original callees and real heap. '
          'No lazy-singleton initialization, failure/limit/exception path, live world, externally maintained pointer graphs or concurrency proof.')
environment=dict(os.environ,WINEPREFIX=str(ROOT/'projects/wine-probe'),WINEARCH='wow64',WINEDEBUG='-all',WINEDLLOVERRIDES='winemenubuilder.exe=d')
try:
    result=subprocess.run(['wine',str(OUT/'growth-probe.exe'),'Z:'+str(ROOT.parent/'base-game/v2game.exe').replace('/','\\')],capture_output=True,text=True,env=environment,timeout=120)
except subprocess.TimeoutExpired as error:
    def decode(x):return x.decode(errors='replace') if isinstance(x,bytes) else x or ''
    stdout,stderr=decode(error.stdout),decode(error.stderr);receipt.update(status='timeout')
else:
    stdout,stderr=result.stdout,result.stderr;receipt.update(status='failed',exit_code=result.returncode)
    if result.returncode==0:
        records=[json.loads(x) for x in stdout.splitlines() if x.startswith('{')]
        summaries=[x for x in records if x.get('kind')=='summary'];cases=[x for x in records if x.get('kind')=='case']
        assert len(summaries)==1
        observed=summaries[0];assert observed['pass'] is True and observed['pointer_bytes']==4
        for field in ('cases','actual_heap_allocs','actual_heap_frees','pre_free_snapshots','catalog_words_checked'):assert observed[field]==build['expected_'+field],(field,observed)
        assert len(cases)==build['expected_cases']
        assert sum(c.get('distribution_profile',0)>0 for c in cases)==build['expected_distribution_cases']
        assert sum(c.get('distribution_profile',0)==5 for c in cases)==build['expected_catalog_cases']
        assert sum(c.get('entry')=='constructor_lifecycle' for c in cases)==build['expected_constructor_cases']
        assert sum(c.get('optional_enabled',0)>0 for c in cases)==build['expected_optional_cases']
        assert sum(c.get('entry')=='goods_pool_copy' for c in cases)==build['expected_pool_copy_cases']
        assert sum(c.get('entry')=='cpop_optional_copy' for c in cases)==build['expected_optional_copy_cases']
        assert sum(c.get('entry')=='cpop_optional_copy_combined' for c in cases)==build['expected_combined_copy_cases']
        assert sum(c.get('entry')=='registered_copy_lifecycle' for c in cases)==build['expected_registered_copy_cases']
        assert sum(c.get('entry')=='registered_vector_growth' for c in cases)==build['expected_registered_growth_cases']
        assert sum(c.get('entry')=='pop_factory_lifecycle' for c in cases)==build['expected_factory_cases']
        assert sum(c.get('entry')=='pop_consumer_new_node' for c in cases)==build['expected_consumer_cases']
        assert sum(c.get('entry')=='pop_consumer_merge' for c in cases)==build['expected_consumer_merge_cases']
        assert sum(c.get('entry')=='pop_consumer_type_selection' for c in cases)==build['expected_consumer_type_selection_cases']
        assert sum(c.get('entry')=='factory_internal_selector' for c in cases)==build['expected_internal_selector_cases']
        assert sum(c.get('entry')=='factory_internal_integration' for c in cases)==build['expected_internal_integration_cases']
        assert sum(2*(c.get('catalog_a_count',0)+c.get('catalog_b_count',0))*(2 if c.get('entry')=='pop_factory_lifecycle' else c.get('old_count',0)+1) for c in cases)==observed['catalog_words_checked']
        assert observed['highlow_relocations']==build['highlow_relocations']
        for case in cases:
            if case.get('entry') in ('factory_internal_selector','factory_internal_integration'):
                expected_heap=2 if case['entry']=='factory_internal_integration' else 0
                assert case['original_heap_allocs']==case['original_heap_frees']==expected_heap
                code=case['sequence_base3'];expected=0
                if case['predicate']:
                    for _ in range(case['row_count']):
                        value=code%3;code//=3
                        if value:
                            expected=int(value==2);break
                assert case['result_fallback']==expected
                if case['entry']=='factory_internal_integration':assert case['type_index']==(case['fallback_index'] if expected else 0)
                continue
            if case.get('entry')=='pop_consumer_type_selection':
                assert case['original_heap_allocs']==case['original_heap_frees']==2
                entries=[dict(level=level,predicate=predicate,flag3d9=flag) for level,predicate,flag in zip(case['levels'],case['predicates'],case['flags'])][:case['catalog_count']]
                selected=select_factory_type(case['special'],case['source_level'],entries)
                assert selected==case['selected_ordinal'] and case['type_index']==(selected if selected>=0 else 0)
                continue
            if case.get('entry')=='pop_consumer_merge':
                assert case['original_heap_allocs']==0 and case['original_heap_frees']==1
                result=merge(case['size'],case['destination_size'],int(case['source_attribute'],16),int(case['destination_attribute'],16),int(case['source_balance'],16),int(case['destination_balance'],16),2 if case['other_region'] else 1)
                assert result['attribute']==int(case['result_attribute'],16) and result['balance']==int(case['result_balance'],16)
                continue
            if case.get('entry')=='pop_consumer_new_node':
                assert case['original_heap_allocs']==case['original_heap_frees']==2
                assert case['size'] in (1,65535,65536,2000000,2000001)
                assert case['slot'] in (0,1,2) and case['other_region'] in (0,1)
                continue
            if case.get('entry')=='pop_factory_lifecycle':
                active=4*int(case['catalog_a_count']>0)+4*int(case['catalog_b_count']>0)
                assert case['original_heap_allocs']==case['original_heap_frees']==2+2*active
                assert case['key_type']==0x2e and case['key_id']==case['id_seed']
                assert case['type_index'] in (0,1,2) and case['previous_count'] in (0,1,2)
                continue
            if case.get('entry') in ('registered_copy_lifecycle','registered_vector_growth'):
                expected=1+int(case['entry']=='registered_vector_growth')
                assert case['original_heap_allocs']==case['original_heap_frees']==expected
                assert case['buckets'] in (1,3,7)
                continue
            if case.get('entry')=='cpop_optional_copy_combined':
                extra=case['source_surplus']
                active=4*int(case['catalog_a_count']+extra>0)+4*int(case['catalog_b_count']+extra>0)
                assert case['original_heap_allocs']==case['original_heap_frees']==active+3+int(case['first_pool_count']>1)
                continue
            if case.get('entry')=='cpop_optional_copy':
                assert case['original_heap_allocs']==case['original_heap_frees']==3+int(case['first_pool_count']>1)
                assert case['second_pool_count'] in (1,3,7)
                continue
            if case.get('entry')=='goods_pool_copy':
                n,m,cap=case['source_count'],case['old_destination_count'],case['old_capacity']
                grows=n>cap
                assert case['new_capacity']==(max(n,cap+cap//2) if grows else cap)
                assert case['original_heap_allocs']==int(grows)
                assert case['original_heap_frees']==int(grows and cap>0)
                continue
            if case.get('entry')=='constructor_lifecycle':
                active=4*int(case['catalog_a_count']>0)+4*int(case['catalog_b_count']>0)
                assert case['original_heap_allocs']==case['original_heap_frees']==active+3*case.get('optional_enabled',0)
                assert case['cache_mode'] in (0,1,2,3)
                continue
            n=case['old_count'];assert case['new_capacity']==max(n+1,n+n//2)
            profile=case['distribution_profile'];active=0 if profile==0 else (6 if profile==4 else 8)
            if profile==5:
                extra=case['source_surplus']
                active=4*int(case['catalog_a_count']+extra>0)+4*int(case['catalog_b_count']+extra>0)
            assert case['original_heap_allocs']==1+active*(n+1)
            assert case['original_heap_frees']==int(n>0)+(8*n if profile else 0)
        receipt.update(status='passed',cases=cases,observed=observed,**{'pass':True})
receipt['stdout_sha256']=hashlib.sha256(stdout.encode()).hexdigest();receipt['stderr_sha256']=hashlib.sha256(stderr.encode()).hexdigest()
for directory in (attempt,OUT):
    (directory/'execution.stdout').write_text(stdout);(directory/'execution.stderr').write_text(stderr)
    (directory/'execution.json').write_text(json.dumps(receipt,indent=2)+'\n')
if not receipt['pass']:raise SystemExit('Native growth probe failed; inspect local attempt receipt.')
print('PASS: native growth probe '+str(receipt['observed']))
