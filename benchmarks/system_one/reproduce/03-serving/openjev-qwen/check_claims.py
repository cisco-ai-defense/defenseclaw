"""Check the publisher's own JevBench figures against the numbers quoted to us.

We were told the card claims 85.28% (197/231) overall and 72.07% (80/111) on Hard. The
staged package carries the publisher's own verification records, so the claim can be read
rather than taken on trust. These are a different task and metric from our F1 and must not
be printed beside it; this only checks that the numbers we repeat are the ones it states.
"""
import json
import pathlib

D = pathlib.Path("/opt/dlami/nvme/model-staging/open-jev-27b-v1.1")

for name in ("verification/jevbench.json", "package/provenance.json"):
    path = D / name
    if not path.exists():
        print(f"=== {name}: MISSING ===")
        continue
    print(f"=== {name} ===")
    data = json.loads(path.read_text())

    def walk(node, prefix=""):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}/{key}")
        elif isinstance(node, list):
            print(f"  {prefix} = list of {len(node)}")
            for index, value in enumerate(node[:8]):
                walk(value, f"{prefix}/{index}")
        else:
            keep = ("accuracy", "correct", "planned", "n_", "limit", "tier",
                    "hard", "overall", "total", "task")
            if any(token in prefix.lower() for token in keep):
                print(f"  {prefix} = {node}")

    walk(data)

print("=== quoted to us ===")
print("  overall 85.28% (197/231) ->", 197 / 231)
print("  hard    72.07% (80/111)  ->", 80 / 111)
print("  alt     81/111           ->", 81 / 111)
