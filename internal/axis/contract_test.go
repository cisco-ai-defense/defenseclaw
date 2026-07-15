package axis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCWDRejectsTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "src"), 0700); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	if e := os.Symlink(outside, filepath.Join(root, "escape")); e != nil {
		t.Fatal(e)
	}
	if _, e := ResolveCWD(root, "../"); e == nil {
		t.Fatal("traversal accepted")
	}
	if _, e := ResolveCWD(root, "escape"); e == nil {
		t.Fatal("symlink escape accepted")
	}
}
func TestManifestAndDigest(t *testing.T) {
	m := Manifest{ProtocolVersion: ProtocolVersion, Provider: "defenseclaw", Model: "Qwen3.6-27B-GGUF", Tools: append([]string(nil), ApprovedTools...), ReleaseID: "r1", CatalogHash: "c", ManifestHash: "m"}
	if e := m.Validate(m); e != nil {
		t.Fatal(e)
	}
	m.Tools[0] = "shell"
	if e := m.Validate(Manifest{ProtocolVersion: ProtocolVersion, Provider: "defenseclaw", Model: "Qwen3.6-27B-GGUF", Tools: append([]string(nil), ApprovedTools...), ReleaseID: "r1", CatalogHash: "c", ManifestHash: "m"}); e == nil {
		t.Fatal("unapproved tool accepted")
	}
	a, e := Digest(map[string]any{"b": 2, "a": 1})
	if e != nil || len(a) != 64 {
		t.Fatalf("digest: %v %q", e, a)
	}
}
