package hookpaths

import (
	"encoding/json"
	"testing"
)

// TestPatchCallNamesProtectedTargetWholeName is rel-1-0-10:GAP-0432: the
// protected names of a patch call of unknown targets are whole names. A
// source or test file named for the feature names no protected file; the
// keys file, its variants and the SSH folder do, also at the start of an
// escaped line of raw JSON argument text.
func TestPatchCallNamesProtectedTargetWholeName(t *testing.T) {
	rows := []struct {
		command string
		args    json.RawMessage
		want    bool
	}{
		{`cat internal/gateway/semantic_authorized_keys_proof.go | rg apply_patch`, nil, false},
		{`rg -n apply_patch internal/gateway/authorized_keys_symlink_write_test.go; true`, nil, false},
		{`rg -n x pkg/myauthorized_keys2go.go`, nil, false},
		{`apply_patch < p && cat ~/.ssh/authorized_keys`, nil, true},
		{`apply_patch < /tmp/authorized_keys.patch`, nil, true},
		{`apply_patch < p; echo authorized_keys2`, nil, true},
		{`apply_patch < p; ls AUTHORIZED_KEYS`, nil, true},
		{`apply_patch < p; type C:\ProgramData\ssh\administrators_authorized_keys`, nil, true},
		{`apply_patch < p; cat "authorized_keys"`, nil, true},
		{`apply_patch < p; F=authorized_keys`, nil, true},
		{`cd ~/.ssh && apply_patch < p`, nil, true},
		{"", json.RawMessage(`{"command":"apply_patch <<EOF\nauthorized_keys\nEOF"}`), true},
		{"", json.RawMessage(`{"command":"rg apply_patch internal/gateway/semantic_authorized_keys_proof.go\n"}`), false},
	}
	for _, row := range rows {
		if got := PatchCallNamesProtectedTarget("Bash", row.args, row.command, "/home/u/p", "/home/u", nil); got != row.want {
			t.Errorf("PatchCallNamesProtectedTarget(%q, %s) = %v, want %v", row.command, row.args, got, row.want)
		}
	}
}
