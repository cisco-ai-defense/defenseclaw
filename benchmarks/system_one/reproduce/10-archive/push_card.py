from huggingface_hub import HfApi
api = HfApi()
repo = "Vineethsain/defenseclaw-slm-toolcall-v1"
i = api.repo_info(repo, repo_type="dataset")
assert i.private
api.upload_file(path_or_fileobj="$WORK/new_card_tc.md", path_in_repo="README.md",
                repo_id=repo, repo_type="dataset",
                commit_message="Correct the trivial-floor count to 9 of 19 and disambiguate deberta's 56.75% shrunk-rows figure from the row-level truncated flag")
i2 = api.repo_info(repo, repo_type="dataset")
print("%s private=%s sha=%s" % (repo.split("/")[-1], i2.private, i2.sha))
assert i2.private
