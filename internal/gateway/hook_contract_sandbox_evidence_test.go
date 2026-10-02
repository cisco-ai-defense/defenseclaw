package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

// writeImageStore writes a minimal, valid image store: the same shape
// internal/openshell/image writes, with only the fields this test needs.
func writeImageStore(t *testing.T, dataDir string, records ...image.Record) {
	t.Helper()
	dir := filepath.Join(dataDir, "sandboxes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	doc := map[string]any{"version": 1, "images": records}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images.json"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func verifiedClaudeCodeImage() image.Record {
	return image.Record{
		Tag:                "defenseclaw/sandbox:claudecode-41d116a05187f7ae-u1000",
		ImageID:            "sha256:b5c5beadc6252084bf397c610cc7a214b62dd4a07213a1ef50d98c1f52eb453e",
		ContentHash:        "41d116a05187f7aea74790a94d6bda7be78e5efddc0e42d1d054a14dbacff3f7",
		Connector:          "claudecode",
		HarnessVersion:     "2.1.156",
		HookContract:       "claudecode-hooks-v1",
		UID:                1000,
		GID:                1000,
		IngressPort:        18971,
		DefenseClawVersion: "0.8.10",
		FailMode:           "closed",
		HookFireVerified:   true,
	}
}

// TestSandboxHarnessHookContractAcceptsVerifiedImage is the F9 case: no host
// agent, but the harness image's hooks were proven to fire.
func TestSandboxHarnessHookContractAcceptsVerifiedImage(t *testing.T) {
	dir := t.TempDir()
	writeImageStore(t, dir, verifiedClaudeCodeImage())

	evidence, ok, err := sandboxHarnessHookContractFor(dir, "claudecode", "0.8.10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("verified harness image was not accepted as evidence")
	}
	if got, want := evidence.Record.HarnessVersion, "2.1.156"; got != want {
		t.Errorf("harness version = %q, want %q", got, want)
	}
	if got, want := evidence.Resolution.Contract.ContractID, "claudecode-hooks-v1"; got != want {
		t.Errorf("contract = %q, want %q", got, want)
	}
	if got, want := evidence.Resolution.Status, "known"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
}

func TestSandboxHarnessHookContractRefusals(t *testing.T) {
	unverified := verifiedClaudeCodeImage()
	unverified.HookFireVerified = false

	otherConnector := verifiedClaudeCodeImage()
	otherConnector.Connector = "codex"

	foreignRelease := verifiedClaudeCodeImage()
	foreignRelease.DefenseClawVersion = "0.8.9"

	unknownHarness := verifiedClaudeCodeImage()
	unknownHarness.HarnessVersion = "9.9.9"

	noVersion := verifiedClaudeCodeImage()
	noVersion.HarnessVersion = ""

	cases := []struct {
		name    string
		records []image.Record
	}{
		{name: "no store", records: nil},
		{name: "unverified hooks", records: []image.Record{unverified}},
		{name: "another connector", records: []image.Record{otherConnector}},
		{name: "another release built it", records: []image.Record{foreignRelease}},
		{name: "harness version has no reviewed contract", records: []image.Record{unknownHarness}},
		{name: "record has no harness version", records: []image.Record{noVersion}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.records != nil {
				writeImageStore(t, dir, tc.records...)
			}
			if evidence, ok, err := sandboxHarnessHookContractFor(dir, "claudecode", "0.8.10"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			} else if ok {
				t.Fatalf("refusal case accepted evidence: %+v", evidence)
			}
		})
	}
}

// TestSandboxHarnessHookContractPrefersNewestRecord keeps the choice
// deterministic when a connector has several recorded images.
func TestSandboxHarnessHookContractPrefersNewestRecord(t *testing.T) {
	older := verifiedClaudeCodeImage()
	older.Tag = "defenseclaw/sandbox:claudecode-older-u1000"
	older.BuiltAt = older.BuiltAt.Add(-24 * time.Hour)
	newer := verifiedClaudeCodeImage()
	newer.Tag = "defenseclaw/sandbox:claudecode-newer-u1000"

	dir := t.TempDir()
	writeImageStore(t, dir, older, newer)

	evidence, ok, err := sandboxHarnessHookContractFor(dir, "claudecode", "0.8.10")
	if err != nil || !ok {
		t.Fatalf("verified harness image was not accepted (ok=%v err=%v)", ok, err)
	}
	if evidence.Record.Tag != newer.Tag {
		t.Errorf("tag = %q, want the newest record %q", evidence.Record.Tag, newer.Tag)
	}
}
