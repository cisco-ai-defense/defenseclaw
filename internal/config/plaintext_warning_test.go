// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// GAP-0138: a managed host has no per-user .env for the administrator's
// config, so the plain-text warning points at the protected credential.
func TestPlaintextSecretWarningNamesTheManagedRemedy(t *testing.T) {
	var buffer bytes.Buffer
	restoreOutput, restoreFlags := log.Writer(), log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(restoreOutput); log.SetFlags(restoreFlags) })

	managedCfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	managedCfg.InspectLLM.APIKey = "example-sensitive-value"
	warnPlaintextSecrets(managedCfg)
	got := buffer.String()
	if !strings.Contains(got, "inspect_llm.api_key") || !strings.Contains(got, "enterprise secret set") ||
		!strings.Contains(got, "enterprise.inspection.llm.credential") || strings.Contains(got, ".defenseclaw/.env") ||
		strings.Contains(got, "example-sensitive-value") {
		t.Fatalf("managed warning = %q", got)
	}

	buffer.Reset()
	perUser := &Config{}
	perUser.InspectLLM.APIKey = "example-sensitive-value"
	warnPlaintextSecrets(perUser)
	if got := buffer.String(); !strings.Contains(got, "~/.defenseclaw/.env") || strings.Contains(got, "enterprise secret set") {
		t.Fatalf("per-user warning changed: %q", got)
	}
}
