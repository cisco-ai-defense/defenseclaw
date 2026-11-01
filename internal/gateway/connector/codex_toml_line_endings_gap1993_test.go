// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"
)

// GAP-1993: an operator [otel] table saved with LF endings in a CRLF
// config.toml came back with CRLF endings after an upgrade, because the
// editor converted the whole file to one ending. Every kept line keeps its
// own ending; only the lines DefenseClaw renders take the file's ending.
func TestCodexOwnedEditKeepsEachKeptLinesOwnEnding(t *testing.T) {
	operator := "[otel]\nenvironment = \"windows\"\nlog_user_prompt = true\n" +
		"[otel.exporter.otlp-http]\nendpoint = \"https://collector.example.invalid/v1/logs\"\nprotocol = \"binary\"\n"
	before := []byte("model = \"gpt-5\"\r\napproval_policy = \"on-request\"\r\n" + operator + "[profiles.review]\r\nmodel = \"gpt-5.1\"\r\n")
	var current map[string]interface{}
	if err := parseCodexTOML(before, &current); err != nil {
		t.Fatal(err)
	}
	desired := map[string]interface{}{
		"notify": []string{"bash", "/tmp/notify-bridge.sh"},
		"hooks":  map[string]interface{}{"Stop": []string{"owned"}},
		"otel":   current["otel"],
	}
	after, err := editCodexOwnedTOML(before, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte(operator)) {
		t.Fatalf("the operator LF [otel] table changed:\n%q", after)
	}
	for _, line := range []string{"model = \"gpt-5\"\r\n", "approval_policy = \"on-request\"\r\n", "[profiles.review]\r\n"} {
		if !bytes.Contains(after, []byte(line)) {
			t.Fatalf("a CRLF user line lost its ending: %q in %q", line, after)
		}
	}
	rest := strings.Replace(string(after), operator, "", 1)
	if strings.Count(rest, "\n") != strings.Count(rest, "\r\n") {
		t.Fatalf("a rendered line does not use the file's CRLF ending: %q", rest)
	}
	var decoded map[string]interface{}
	if err := parseCodexTOML(after, &decoded); err != nil {
		t.Fatalf("edited Codex TOML is invalid: %v", err)
	}
	if decoded["notify"] == nil || decoded["hooks"] == nil {
		t.Fatalf("owned tables missing: %#v", decoded)
	}
}

// The features.hooks repair keeps each kept line's own ending too.
func TestRemoveCodexManagedHookFeatureKeepsEachKeptLinesOwnEnding(t *testing.T) {
	before := []byte("model = \"gpt-5\"\r\n[features]\r\nhooks = false\r\n[otel]\nenvironment = \"windows\"\n")
	after, err := RemoveCodexManagedHookFeature(before)
	if err != nil {
		t.Fatal(err)
	}
	want := "model = \"gpt-5\"\r\n[features]\r\n[otel]\nenvironment = \"windows\"\n"
	if string(after) != want {
		t.Fatalf("after = %q, want %q", after, want)
	}
}
