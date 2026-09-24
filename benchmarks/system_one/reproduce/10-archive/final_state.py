from huggingface_hub import HfApi
api = HfApi()
for r in ["defenseclaw-slm-toolcall-v1",
          "defenseclaw-system-one-predictions-v1",
          "defenseclaw-system-one-evaluations-v1",
          "defenseclaw-system-one-corpora-v1",
          "defenseclaw-system-one-contamination-v1"]:
    rid = "Vineethsain/" + r
    i = api.repo_info(rid, repo_type="dataset")
    n = len(api.list_repo_files(rid, repo_type="dataset"))
    print("%-42s private=%-5s files=%-5d sha=%s" % (r, i.private, n, i.sha))
