import json, os, csv, sys
import pyarrow.parquet as pq
C="$WORK/.system-one-data/outputs/secjudge/contamination/cache"

def jl_peek(p, n=2):
    rows=[]; total=0
    with open(p, encoding="utf-8", errors="replace") as f:
        for i,l in enumerate(f):
            l=l.strip()
            if not l: continue
            total+=1
            if len(rows)<n:
                try: rows.append(json.loads(l))
                except Exception as e: rows.append({"__parse_error__":str(e)[:100]})
    return total, rows

print("### S-Labs csv")
for f in ["train","validation","test"]:
    p=f"{C}/S-Labs__prompt-injection-dataset/data/{f}.csv"
    with open(p, newline="", encoding="utf-8") as fh:
        r=csv.DictReader(fh); rows=list(r)
    print(" ", f, len(rows), "cols", r.fieldnames, "ex:", json.dumps(rows[0])[:200])

print("### nl2bash-custom json")
for f in ["train","dev","test"]:
    p=f"{C}/AnishJoshi__nl2bash-custom/data/{f}.json"
    d=json.load(open(p))
    print(" ", f, type(d).__name__, len(d))
    if isinstance(d,dict): print("    keys", list(d.keys())[:10]); 
    print("    ex:", json.dumps(d[0] if isinstance(d,list) else d)[:300])

print("### Magicoder")
t,rows=jl_peek(f"{C}/ise-uiuc__Magicoder-OSS-Instruct-75K/data-oss_instruct-decontaminated.jsonl")
print("  rows",t,"keys",sorted(rows[0].keys()))
print("  ex:", json.dumps(rows[0])[:300])

print("### Trendyol")
t,rows=jl_peek(f"{C}/Trendyol__Trendyol-Cybersecurity-Instruction-Tuning-Dataset/CyberSec-Dataset_escaped.jsonl")
print("  rows",t,"keys",sorted(rows[0].keys()))
print("  ex:", json.dumps(rows[0])[:400])

print("### 3nesdeniz")
for f in ["train","validation","test"]:
    t,rows=jl_peek(f"{C}/3nesdeniz__agentic-prompt-injection-boundary-pairs/data/{f}.jsonl")
    print(" ",f,t,"keys",sorted(rows[0].keys()))
print("  ex:", json.dumps(rows[0])[:400])

print("### deepset parquet")
for f in ["train-00000-of-00001-9564e8b05b4757ab","test-00000-of-00001-701d16158af87368"]:
    tb=pq.read_table(f"{C}/deepset__prompt-injections/data/{f}.parquet")
    print(" ",f,tb.num_rows,tb.schema.names)
    print("   ex:", json.dumps(tb.slice(0,1).to_pylist())[:250])

print("### infraset parquet")
for f in ["runs","commands","tasks"]:
    tb=pq.read_table(f"{C}/infraset__infraset/data/{f}.parquet")
    print(" ",f,tb.num_rows,tb.schema.names)
    print("   ex:", json.dumps(tb.slice(0,1).to_pylist(), default=str)[:500])

print("### rogue-security parquet")
tb=pq.read_table(f"{C}/rogue-security__coding-agent-security-benchmark/data/test-00000-of-00001.parquet")
print("  rows",tb.num_rows, tb.schema.names)
print("  ex:", json.dumps(tb.slice(0,1).to_pylist(), default=str)[:800])

print("### Nemotron IPI")
t,rows=jl_peek(f"{C}/nvidia__Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1/train.jsonl")
print("  rows",t,"keys",sorted(rows[0].keys()))
print("  ex:", json.dumps(rows[0])[:600])
