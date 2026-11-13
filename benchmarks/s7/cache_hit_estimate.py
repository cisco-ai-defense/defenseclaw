import json,sys
for corpus in ('s3','s2'):
    n=same_call=same_sample=cross=0
    seen_global=set()
    for l in open(f'/home/ubuntu/.system-one-data/outputs/{corpus}/cases.jsonl'):
        r=json.loads(l); evs=r['payload'].get('events') or [r['payload']]
        hist=[]; seen=set(); samples=set()
        for e in evs:
            k=(e.get('tool_name'), e.get('command') or json.dumps(e.get('args'),sort_keys=True))
            n+=1
            if k in seen: same_call+=1
            s=tuple(hist[-7:])+(k,)
            if s in samples: same_sample+=1
            if k in seen_global: cross+=1
            seen.add(k); samples.add(s); seen_global.add(k); hist.append(k)
    print(corpus, 'calls', n, 'repeat of an earlier call in the session %.1f%%' % (100*same_call/n),
          'repeat of the full judge key (last 7 + call) %.2f%%' % (100*same_sample/n),
          'call seen in any earlier session %.1f%%' % (100*cross/n))
