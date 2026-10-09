// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodexOwnedEditPreservesUserTextAndBOM(t *testing.T) {
	before := append([]byte{0xef, 0xbb, 0xbf}, []byte(
		"# café 東京\r\nmodel = \"gpt-5\"\r\nnotify = [\"/bin/my-notify\"]\r\n# keep order\r\napproval_policy = \"on-request\"\r\n[profiles.review]\r\nmodel = \"gpt-5.1\"\r\n",
	)...)
	desired := map[string]interface{}{
		"notify": []string{"bash", "/tmp/notify-bridge.sh"},
		"hooks":  map[string]interface{}{"Stop": []string{"owned"}},
		"otel":   map[string]interface{}{"environment": "test"},
	}
	after, err := editCodexOwnedTOML(before, desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"# café 東京\r\n", "model = \"gpt-5\"\r\n", "# keep order\r\n", "approval_policy = \"on-request\"\r\n", "[profiles.review]\r\n"} {
		if !bytes.Contains(after, []byte(line)) {
			t.Fatalf("user text missing after edit: %q", line)
		}
	}
	if !bytes.HasPrefix(after, before[:3]) || strings.Contains(string(after), "\r\r\n") {
		t.Fatal("Codex BOM or line endings changed")
	}
	var decoded map[string]interface{}
	if err := parseCodexTOML(after, &decoded); err != nil {
		t.Fatalf("edited Codex TOML is invalid: %v", err)
	}
}
