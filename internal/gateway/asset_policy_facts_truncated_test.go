// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1303: the standalone hook sends at most 16 skill name claims. A skill
// folder past them that the service-account gateway cannot read may declare
// a denied name, so it is refused as unproven instead of read as allowed.
func TestTruncatedSkillClaimsRefuseAnUnreadableUnclaimedFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "secret-tool", Connector: "codex"}}
	api := &APIServer{scannerCfg: cfg}
	home := t.TempDir()
	hidden := filepath.Join(home, ".codex", "skills", "hidden")
	if err := os.MkdirAll(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hidden, "SKILL.md"), []byte("---\nname: secret-tool\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hidden, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })

	var claims []assetfacts.Skill
	for i := range 17 {
		claims = append(claims, assetfacts.Skill{Folder: fmt.Sprintf("s%02d", i), Declared: fmt.Sprintf("alias-%02d", i)})
	}
	claims[16] = assetfacts.Skill{Folder: "hidden", Declared: "secret-tool"}
	truncated, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{Skills: claims}))
	if !ok || !truncated.SkillsTruncated || len(truncated.DeclaredFor("hidden")) != 0 {
		t.Fatalf("facts = %+v, want 16 claims and SkillsTruncated without the hidden claim", truncated)
	}
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: home})
	read := func(facts assetfacts.Facts, command string) (config.AssetPolicyDecision, bool) {
		ctx := context.WithValue(peer, claimedAssetFactsContextKey{}, facts)
		return api.codexSkillAssetDecision(ctx, codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash",
			ToolInput: map[string]interface{}{"command": []interface{}{"bash", "-lc", command}},
		})
	}
	decision, matched := read(truncated, "cat ~/.codex/skills/hidden/SKILL.md")
	if !matched || decision.Action != "block" || decision.Source != "skill-facts-truncated" {
		t.Fatalf("matched=%v decision=%+v, want the unproven folder refused", matched, decision)
	}
	// Without truncation the claims are complete: no claim means the folder
	// declares no other name, as before.
	complete := truncated
	complete.SkillsTruncated = false
	if decision, matched := read(complete, "cat ~/.codex/skills/hidden/SKILL.md"); matched {
		t.Fatalf("complete claims refused an unclaimed folder: %+v", decision)
	}
	// A claimed folder keeps its claim; a folder that is not there is no skill.
	if decision, matched := read(truncated, "cat ~/.codex/skills/s03/SKILL.md ~/.codex/skills/gone/SKILL.md"); matched {
		t.Fatalf("a claimed or missing folder was refused: %+v", decision)
	}
}
