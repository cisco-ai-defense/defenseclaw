import os,shutil,yaml,sys
E=os.path.expanduser('~/dc-eh/evidence/rel-1-0-10/s7/cascade/')
src=os.path.expanduser('~/dc-eh/wt/s7-cascade/policies'); dst=E+'policies-safeguard'
if os.path.exists(dst): shutil.rmtree(dst)
shutil.copytree(src,dst)
prompt=open(sys.argv[1]).read()
for pack in ('default',):
    p=f'{dst}/guardrail/{pack}/judge/tool-injection.yaml'
    d=yaml.safe_load(open(p)); d['system_prompt']=prompt
    yaml.safe_dump(d, open(p,'w'), sort_keys=False, allow_unicode=True, width=10000)
print('ok', len(prompt))
