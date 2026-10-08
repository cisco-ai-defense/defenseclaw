// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// GAP-0570: the standalone hook reports, read as the user, the name an
// invoked skill folder declares.
func TestHookAssetFactsReportWhatTheGatewayCannotRead(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	skill := filepath.Join(home, ".claude", "skills", "epa-alias")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: epa-deny\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	facts, ok := assetfacts.Decode(hookAssetFacts("claudecode", []byte(`{"tool_name":"Skill","tool_input":{"skill":"epa-alias"}}`)))
	if !ok || len(facts.Skills) != 1 || facts.Skills[0].Folder != "epa-alias" || facts.Skills[0].Declared != "epa-deny" {
		t.Fatalf("skill facts = %+v (ok=%v)", facts, ok)
	}

}
