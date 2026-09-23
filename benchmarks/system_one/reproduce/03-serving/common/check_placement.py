"""Gate: the 26B must be fully resident on GPU.

Phase 0 measured 4.65 s per prefill with 33 GB of the 51.6 GB in host memory, which
projects to 117 h for 30,310 requests (90,930 prefills) and is not viable. If accelerate
put any layer on cpu or disk, fail now rather than discover it 20 hours later.
"""
import json
import sys

banner = json.load(open(sys.argv[1]))
if isinstance(banner, dict) and "data" in banner:
    # /v1/models may wrap the provenance
    entries = banner["data"]
    banner = entries[0] if entries else {}

placement = banner.get("placement")
print("attention      :", banner.get("attention"))
print("dtype          :", banner.get("dtype"), "tf32:", banner.get("tf32"))
print("prefix_cache   :", banner.get("prefix_cache"))
print("temperature    :", banner.get("temperature"))
print("template sha256:", banner.get("chat_template_sha256"))
print("asserted tail  :", banner.get("asserted_generation_prompt_tail"))
print("enable_thinking:", banner.get("enable_thinking"))
print("placement      :", placement)
print("load_seconds   :", banner.get("load_seconds"))

fail = []
if banner.get("attention") != "eager":
    fail.append("attention is %r, must be eager (G2)" % banner.get("attention"))
if banner.get("prefix_cache") is not False:
    fail.append("prefix_cache is %r, must be False" % banner.get("prefix_cache"))
if banner.get("enable_thinking") is not False:
    fail.append("enable_thinking is %r, must be False (G1)" % banner.get("enable_thinking"))
if banner.get("chat_template_sha256") != "ae53464bf3be25802b3a5b37def7fd89667067d7577049b3b2d74c4d8de4c6d4":
    fail.append("chat template digest %r is not the pinned 26B-family digest"
                % banner.get("chat_template_sha256"))
if banner.get("asserted_generation_prompt_tail") != [100, 45518, 107, 101]:
    fail.append("asserted tail %r != [100, 45518, 107, 101]"
                % banner.get("asserted_generation_prompt_tail"))
if placement:
    offloaded = {k: v for k, v in placement.items() if k in ("cpu", "disk") or "cpu" in k or "disk" in k}
    if offloaded:
        fail.append("model is NOT fully resident: %r layers offloaded -> the 4.65 s/prefill path" % offloaded)
else:
    print("NOTE: no hf_device_map reported (single-device .to(device) placement)")

if fail:
    for f in fail:
        print("GATE FAIL:", f)
    sys.exit(1)
print("PLACEMENT + GATES OK")
