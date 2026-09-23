import json, sys
from huggingface_hub import snapshot_download
PINS=json.load(open("$WORK/g4j/pins.json"))
order=["google/gemma-4-E2B-it","larkooo/gemma-e2b-rlcd","kushalpatil/jevify-gemma4-26b-a4b","google/gemma-4-26B-A4B-it"]
for rid in order:
    p=snapshot_download(rid, revision=PINS[rid], max_workers=16)
    print("DONE", rid, p, flush=True)
print("ALLDONE", flush=True)
