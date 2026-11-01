package connector

import (
	"bytes"
	"testing"
)

// GAP-0032 (rel-1-0-5): comments and blank lines at the end of a section
// DefenseClaw re-renders ([hooks], or a replaced [otel]) belong to the table
// after it, so an operator comment above their own table survives setup and
// upgrade instead of leaving with the product's hooks.
func TestCodexOwnedEditKeepsACommentBetweenHooksAndTheNextTable(t *testing.T) {
	operator := "# operator otel\n[otel]\nenvironment = \"op-env\"\n" +
		"[otel.exporter.otlp-http]\nendpoint = \"https://collector.example.invalid/v1/logs\"\n"
	before := []byte("model = \"gpt-5\"\r\n[hooks]\r\n[[hooks.Stop]]\r\nmatcher = '*'\r\n\r\n" +
		operator + "[profiles.review] # kept\r\nmodel = \"gpt-5.1\"\r\n")
	var current map[string]interface{}
	if err := parseCodexTOML(before, &current); err != nil {
		t.Fatal(err)
	}
	desired := map[string]interface{}{
		"hooks": map[string]interface{}{"Stop": []string{"owned"}},
		"otel":  current["otel"],
	}
	after, err := editCodexOwnedTOML(before, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte("\r\n"+operator)) {
		t.Fatalf("the operator comment above [otel] (or its blank line) was dropped:\n%q", after)
	}
	if bytes.Contains(after, []byte("matcher = '*'")) {
		t.Fatalf("the old product hook entry was kept:\n%q", after)
	}
	again, err := editCodexOwnedTOML(after, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, after) {
		t.Fatalf("a second edit changed the file:\nfirst  %q\nsecond %q", after, again)
	}
	var decoded map[string]interface{}
	if err := parseCodexTOML(after, &decoded); err != nil {
		t.Fatalf("edited Codex TOML is invalid: %v", err)
	}
	if decoded["hooks"] == nil || decoded["profiles"] == nil {
		t.Fatalf("tables missing: %#v", decoded)
	}
}

// A comment-only tail of the product hooks at the end of the file is still
// the product's own section end: nothing grows on repeated setups.
func TestCodexOwnedEditOfHooksAtTheEndIsStable(t *testing.T) {
	before := []byte("model = \"gpt-5\"\n\n[hooks]\n[[hooks.Stop]]\nmatcher = '*'\n\n")
	desired := map[string]interface{}{"hooks": map[string]interface{}{"Stop": []string{"owned"}}}
	first, err := editCodexOwnedTOML(before, desired)
	if err != nil {
		t.Fatal(err)
	}
	second, err := editCodexOwnedTOML(first, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("repeated edit not stable:\nfirst  %q\nsecond %q", first, second)
	}
}
