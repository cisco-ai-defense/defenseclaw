// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-1076: a custom pack that no setting selects is reported when the
// gateway would refuse it once a setting did (stale pin, missing folder);
// a matching pin and a selected pack (CheckRulePacks refuses that one) are
// not.
func TestUnselectedCustomPackProblemsNamesOnlyUnselectedPacksThatWillNotLoad(t *testing.T) {
	packDir := t.TempDir()
	suppressions := "version: 1\npre_judge_strips: []\nfinding_suppressions: []\ntool_suppressions: []\n"
	if err := os.WriteFile(filepath.Join(packDir, "suppressions.yaml"), []byte(suppressions), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := guardrail.LoadRulePack(packDir)
	if err != nil {
		t.Fatal(err)
	}
	stale := "sha256:" + strings.Repeat("0", 64)
	good := "sha256:" + loaded.FilesDigest()
	cfg := &config.Config{}
	cfg.Guardrail.RulePack = "picked"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{
		"picked":  {Path: packDir, Digest: stale},
		"profile": {Path: packDir, Digest: stale},
		"spare":   {Path: packDir, Digest: stale},
		"gone":    {Path: filepath.Join(packDir, "missing"), Digest: good},
		"fine":    {Path: packDir, Digest: good},
	}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"team": {RulePack: "profile"}}
	problems := UnselectedCustomPackProblems(cfg)
	if len(problems) != 2 ||
		!strings.HasPrefix(problems[0], "guardrail.custom_packs.gone is registered but will not load") ||
		!strings.Contains(problems[0], "is not a folder") ||
		!strings.HasPrefix(problems[1], "guardrail.custom_packs.spare is registered but will not load") ||
		!strings.Contains(problems[1], good) {
		t.Fatalf("problems = %q", problems)
	}
	if got := UnselectedCustomPackProblems(&config.Config{}); got != nil {
		t.Fatalf("no custom packs: %q", got)
	}
}
