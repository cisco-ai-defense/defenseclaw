import sys, json
from huggingface_hub import HfApi
api=HfApi()
tree, repo, msg = sys.argv[1], sys.argv[2], sys.argv[3]
info=api.repo_info(repo,repo_type="dataset")
assert info.private, f"REFUSING: {repo} is not private"
print(f"pre-push  {repo} private={info.private} sha={info.sha}")
api.upload_folder(folder_path=f"$WORK/hf-stage/{tree}", repo_id=repo,
                  repo_type="dataset", commit_message=msg)
info2=api.repo_info(repo,repo_type="dataset")
files=api.list_repo_files(repo,repo_type="dataset")
print(f"post-push {repo} private={info2.private} sha={info2.sha} files={len(files)}")
assert info2.private, f"ALARM: {repo} became public"
