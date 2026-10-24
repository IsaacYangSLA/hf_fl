"""Regenerate cross-language fixtures from the checked-out Python reference.

Development helper only; Go production binaries and tests do not invoke Python.
"""
import copy,hashlib,json,math,sys,random,struct,subprocess
from pathlib import Path
repo=Path(__file__).resolve().parents[5]
sys.path.insert(0,str(repo/'packages/jobs/src'))
from hf2l_jobs.domain import JobSpec,ArtifactLocator,canonical_json
from hf2l_jobs.auth import principal_id
base=dict(project_id='research',name='Training',source_id='approved-source',source_commit='A'*40,runtime_image='cpu-runtime',plugin='example.plugin:Trainer',components=[dict(component_id='owner',role='owner',resources=dict(pool_id='cpu',cpu_millicores=1000,memory_bytes=1024,disk_bytes=2048))],target_round=3,max_duration_seconds=3600)
values=[
 ('ordered',{'z':1,'a':2}),
 ('numeric-types',[1,1.0,-0.0,0,10**100,1e-7,1e-6,1e-5,.0001,1e15,1e16,1e20,1e21,5e-324,1.7976931348623157e308]),
 ('unicode',{'é':'<>& \u2028 \u2029','𐀀':'你好 😀','a':'\x00\b\f\n\r\t\x7f','Z':'quote" backslash\\'}),
 ('float-roundtrips',[.1,.3,1.2345678901234567,1.0000000000000002,2.2250738585072014e-308,-1.234e19,1000000000000000.2]),
 ('nested',{'a':[None,True,False,{},[],{'b':.0}]}),
 ('large-integer',{'large':1234567890123456789012345678901234567890}),
]
rng=random.Random(20261023)
sample=[]
while len(sample)<1000:
 value=struct.unpack('>d',rng.getrandbits(64).to_bytes(8,'big'))[0]
 if math.isfinite(value):sample.append(value)
values.append(('seeded-float-bit-patterns',sample))
canonical=[]
for name,value in values:
 raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False)
 expected=canonical_json(value)
 canonical.append(dict(name=name,input=raw,expected=expected,sha256=hashlib.sha256(expected.encode()).hexdigest()))
principals=[]
for issuer,subject in [('https://id.example/realms/hf2l','alice'),('https://身份.example/世界','爱丽丝😀'),('https://id.example/<>&','a\u2028b\x7f'),('https://id.example','quote" backslash\\ \n')]:
 principals.append(dict(issuer=issuer,subject=subject,expected=principal_id(issuer,subject)))

specs=[]
def add(name,value):
 try:
  model=JobSpec.model_validate(value)
  normalized=model.to_dict();valid=True
  expected=canonical_json(normalized);digest=model.digest
 except Exception:
  valid=False;normalized=None;expected=None;digest=None
 specs.append(dict(name=name,input=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False),valid=valid,normalized=normalized,canonical=expected,sha256=digest))
def changed(name,change):
 value=copy.deepcopy(base);change(value);add(name,value)
add('defaults',base)
changed('unicode-floats',lambda s:s.update(name='联合学习😀 <>&',options={'lr':1.0,'tiny':1e-7,'negative_zero':-0.0,'huge':10**50}))
changed('external-two',lambda s:s.update(participants=[{'participant_id':'alice','dataset_binding':'alice-data'},{'participant_id':'bob','dataset_binding':'bob-data'}],options={'minimum_participants':2}))
def managed(s):
 s['participants']=[dict(participant_id='alice',dataset_binding='alice-data',mode='managed',component_id='alice-worker')]
 s['components'].append(dict(component_id='alice-worker',role='participant',participant_id='alice',resources=dict(pool_id='alice-cpu',cpu_millicores=500,memory_bytes=2048,disk_bytes=4096)))
changed('managed',managed)
changed('sha256-source',lambda s:s.update(source_commit='F'*64,runtime_image='sha256:'+'f'*64))
changed('gpu-shape-only',lambda s:s['components'][0]['resources'].update(gpu_count=1,gpu_profile='fixed-model'))
changed('secret-ref',lambda s:s.update(secret_refs={'training_key':'approved-key'}))
for key in ['target_round','max_duration_seconds']:
 for value in [True,0,-1,1.0,1.5,'1',None]:
  changed(f'{key}-{repr(value)}',lambda s,k=key,v=value:s.update({k:v}))
for key in ['cpu_millicores','memory_bytes','disk_bytes','gpu_count']:
 for value in [True,1.0,None]:
  changed(f'resource-{key}-{repr(value)}',lambda s,k=key,v=value:s['components'][0]['resources'].update({k:v}))
for key in ['options','secret_refs','participants','components','name','plugin']:
 changed(f'explicit-null-{key}',lambda s,k=key:s.update({k:None}))
changed('explicit-null-profile',lambda s:s['components'][0]['resources'].update(sandbox_profile=None))
changed('empty-profile',lambda s:s['components'][0]['resources'].update(sandbox_profile=''))
for key in ['command','mounts','executor_flags','api_key','apiKey','APIKEY','accessToken','password','Authorization','private-key']:
 changed(f'forbidden-option-{key}',lambda s,k=key:s.update(options={'nested':[{k:'value'}]}))
changed('unknown-field',lambda s:s.update(unexpected=True))
changed('unknown-resource',lambda s:s['components'][0]['resources'].update(unexpected=1))
changed('no-owner',lambda s:s['components'][0].update(role='build'))
changed('duplicate-component',lambda s:s['components'].append(copy.deepcopy(s['components'][0])))
changed('gpu-no-profile',lambda s:s['components'][0]['resources'].update(gpu_count=1))
changed('profile-no-gpu',lambda s:s['components'][0]['resources'].update(gpu_profile='fixed'))
changed('unmatched-managed',lambda s:s.update(participants=[dict(participant_id='alice',dataset_binding='alice-data',mode='managed',component_id='missing')]))
changed('external-with-component',lambda s:s.update(participants=[dict(participant_id='alice',dataset_binding='alice-data',component_id='owner')]))
changed('minimum-boolean',lambda s:s.update(options={'minimum_participants':True}))
changed('minimum-float',lambda s:s.update(options={'minimum_participants':2.0}))
changed('minimum-exceeds',lambda s:s.update(options={'minimum_participants':2}))
changed('nonascii-ident',lambda s:s.update(project_id='项目'))
changed('mutable-source',lambda s:s.update(source_commit='main'))
changed('unapproved-runtime-url',lambda s:s.update(runtime_image='https://image.example/model'))
changed('long-name',lambda s:s.update(name='😀'*201))
changed('name200unicode',lambda s:s.update(name='😀'*200))
changed('control-name',lambda s:s.update(name='training\x7f'))
changed('option-string-unicode-bound',lambda s:s.update(options={'label':'é'*8192}))
changed('option-string-too-long',lambda s:s.update(options={'label':'é'*8193}))
changed('option-total-too-big',lambda s:s.update(options={str(i):'a'*8000 for i in range(10)}))
nested={}
for _ in range(10):nested={'x':nested}
changed('option-depth',lambda s:s.update(options=nested))

locators=[]
for value in [
 {'kind':'local','resource_id':'owned','relative_path':'checkpoints/model.bin'},
 {'kind':'exchange','space_id':'s','record_id':'r','attachment_id':'a'},
 {'kind':'local','resource_id':'owned','relative_path':'../foreign'},
 {'kind':'local','resource_id':'owned','relative_path':'/etc/shadow'},
 {'kind':'local','resource_id':'owned','relative_path':'a//b'},
 {'kind':'local','resource_id':'owned','relative_path':'a/./b'},
 {'kind':'local','resource_id':'owned','relative_path':'a\\b'},
 {'kind':'exchange','space_id':'s','record_id':'r'},
 {'kind':'exchange','space_id':'s','record_id':'r','attachment_id':'a','resource_id':'foreign'},
 {'kind':'exchange','space_id':'s','record_id':'r','attachment_id':'a','url':'https://evil.example'},
 {'kind':'local','resource_id':'owned','relative_path':'é'*1024},
 {'kind':'local','resource_id':'owned','relative_path':'a\x00b'},
]:
 try:normalized=ArtifactLocator.model_validate(value).to_dict();valid=True
 except Exception:normalized=None;valid=False
 locators.append(dict(input=json.dumps(value,ensure_ascii=False,separators=(',',':')),valid=valid,normalized=normalized))
result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'source_files':{name:hashlib.sha256((repo/name).read_bytes()).hexdigest() for name in ['packages/jobs/src/hf2l_jobs/domain.py','packages/jobs/src/hf2l_jobs/auth.py']},'reference':'hf2l_jobs.domain and hf2l_jobs.auth; expected values generated before Go execution','canonical':canonical,'principals':principals,'specs':specs,'locators':locators}
out=Path(__file__).with_name('python_contracts.json')
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n')
print(json.dumps({'canonical':len(canonical),'principals':len(principals),'specs':len(specs),'locators':len(locators),'bytes':out.stat().st_size}))
