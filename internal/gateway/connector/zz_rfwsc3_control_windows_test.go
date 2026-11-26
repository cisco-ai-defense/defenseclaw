package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// RFWSC3 diagnostic (not committed as is): Windows Codex Setup then Teardown
// with no edit, in the fixture TestCodexTeardownRemovesHealedEditedHookPaths
// uses, and the same with an in-place launcher-name edit. Logs counts only.
func rfwsc3CodexRun(t *testing.T, edit bool) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# personal\nmodel = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = path
	defer func() { CodexConfigPathOverride = "" }()
	previousInspector := codexPolicyInspector
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{Source: "rfwsc3 control"}, nil
	}
	defer func() { codexPolicyInspector = previousInspector }()
	setHookBinaryOverride(t, filepath.Join(dir, "DefenseClaw", windowsHookBinaryName))
	c := NewCodexConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, ".defenseclaw"), APIAddr: "127.0.0.1:18970"}
	count := func(label string) string {
		b, _ := os.ReadFile(path)
		s := string(b)
		return label + ": hook tables=" + itoa(strings.Count(s, "[[hooks.")) +
			" orig=" + itoa(strings.Count(s, windowsHookBinaryName)) +
			" edited=" + itoa(strings.Count(s, editedWindowsHookBinaryName)) +
			" state=" + itoa(strings.Count(s, "hooks.state")) +
			" cmdexe=" + itoa(strings.Count(strings.ToLower(s), "cmd.exe")) +
			" personal=" + itoa(strings.Count(s, "# personal"))
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	t.Log(count("after setup"))
	if edit {
		installed, _ := os.ReadFile(path)
		edited := bytes.ReplaceAll(installed, []byte(windowsHookBinaryName), []byte(editedWindowsHookBinaryName))
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Log(count("after edit"))
		if err := c.Setup(context.Background(), opts); err != nil {
			t.Fatalf("heal: %v", err)
		}
		t.Log(count("after heal"))
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	t.Log(count("after teardown"))
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestRFWSC3CodexControlNoEdit(t *testing.T) { rfwsc3CodexRun(t, false) }
func TestRFWSC3CodexControlEdit(t *testing.T)   { rfwsc3CodexRun(t, true) }
