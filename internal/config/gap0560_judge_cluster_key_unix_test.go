//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0560: the LLM judge of a managed Agent Substrate gateway gets its key
// from the chart's LLM credentials Secret: enterprise.inspection.llm.credential
// names a key of it (bedrock, the key the /llm route reads). Before, a
// standalone deployment had no source a cluster could provide: the key was
// read only from a systemd credential or <config dir>/secrets, never from
// the environment, so every judge call fell back to the AWS credential chain
// and failed ("failed to retrieve aws credentials").
func TestGAP0560ManagedClusterJudgeKeyComesFromTheLLMSecret(t *testing.T) {
	t.Setenv("DC_JUDGE_BEDROCK_KEY", "from-env")
	dir := t.TempDir()
	stamp := filepath.Join(dir, "..2026_11_17_22_00_00.000000001")
	if err := os.Mkdir(stamp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stamp, "bedrock"), []byte("ABSKclusterkey\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(stamp), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "bedrock"), filepath.Join(dir, "bedrock")); err != nil {
		t.Fatal(err)
	}
	managed.UseClusterCredentialDir(dir)
	t.Cleanup(func() { managed.UseClusterCredentialDir("") })
	cfg := Config{
		DeploymentMode: "managed_enterprise",
		ConfigFilePath: "/etc/defenseclaw/config.yaml",
		Enterprise: EnterpriseConfig{
			Profile:    "standalone",
			Inspection: EnterpriseInspectionConfig{LLM: EnterpriseLLMConfig{Credential: "bedrock"}},
		},
		LLM: LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", APIKeyEnv: "DC_JUDGE_BEDROCK_KEY"},
	}
	if got := cfg.ResolveLLM("guardrail.judge").ResolvedAPIKey(); got != "ABSKclusterkey" {
		t.Fatalf("judge key = %q, want the cluster Secret's bedrock key (never the environment)", got)
	}
}
