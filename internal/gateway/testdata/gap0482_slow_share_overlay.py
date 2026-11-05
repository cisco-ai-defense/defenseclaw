"""Build a Go test overlay that models a pending network-share root probe."""

import json
from pathlib import Path
import sys


source = Path("internal/hookpaths/network_path.go").resolve()
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
original = source.read_text()
root_old = "networkShareRootOf = networkShareRoot"
root_new = '''networkShareRootOf = func(path string) string {
        root := os.Getenv("R482_FAKE_SHARE")
        if root != "" && (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) {
            return root
        }
        return networkShareRoot(path)
    }'''
probe_old = "probeNetworkShare  = func(root string) { _, _ = os.Stat(root) }"
probe_new = '''probeNetworkShare  = func(root string) {
        if os.Getenv("R482_FAKE_SHARE") != "" {
            if os.Getenv("R482_FAKE_SHARE_ROOT_FAST") != "1" {
                time.Sleep(2 * time.Second)
            }
            return
        }
        _, _ = os.Stat(root)
    }'''
assert original.count(root_old) == 1
assert original.count(probe_old) == 1
replacement = original.replace(root_old, root_new).replace(probe_old, probe_new)
target = output / "network_path.go"
target.write_text(replacement)
overlays = {str(source): str(target)}
read_old = 'var readShareInfo = func(name string, follow bool) (os.FileInfo, error) {'
if read_old in original:
    read_new = '''var readShareInfo = func(name string, follow bool) (os.FileInfo, error) {
        root := os.Getenv("R482_FAKE_SHARE")
        if os.Getenv("R482_FAKE_SHARE_UNANSWERED") == "1" && root != "" &&
            (name == root || strings.HasPrefix(name, root+string(filepath.Separator))) {
            time.Sleep(2 * time.Second)
        }'''
    assert original.count(read_old) == 1
    target.write_text(replacement.replace(read_old, read_new))
else:
    proof_source = Path("internal/gateway/semantic_authorized_keys_proof.go").resolve()
    proof = proof_source.read_text()
    assert proof.count('os.Lstat(target)') >= 1
    proof = proof.replace('"strings"', '"strings"\n"time"', 1)
    proof = proof.replace('os.Lstat(target)', 'gap0482DelayedLstat(target)')
    proof += '''
func gap0482DelayedLstat(name string) (os.FileInfo, error) {
    root := os.Getenv("R482_FAKE_SHARE")
    if os.Getenv("R482_FAKE_SHARE_UNANSWERED") == "1" && root != "" &&
        (name == root || strings.HasPrefix(name, root+string(filepath.Separator))) {
        time.Sleep(2 * time.Second)
    }
    return os.Lstat(name)
}
'''
    proof_target = output / "semantic_authorized_keys_proof.go"
    proof_target.write_text(proof)
    overlays[str(proof_source)] = str(proof_target)
(output / "overlay.json").write_text(json.dumps({"Replace": overlays}))
