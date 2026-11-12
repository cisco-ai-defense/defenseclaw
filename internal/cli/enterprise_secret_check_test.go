// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func runSecretCheck(t *testing.T, args ...string) (map[string]any, string, int) {
	t.Helper()
	cmd := newEnterpriseSecretCheckCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	code := 0
	if err != nil {
		code = commandExitCode(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("not one JSON document (exit %d): %v\n%s", code, err, out.String())
	}
	return doc, out.String(), code
}

func errorCode(doc map[string]any) string {
	errs, _ := doc["errors"].([]any)
	if len(errs) == 0 {
		return ""
	}
	first, _ := errs[0].(map[string]any)
	code, _ := first["code"].(string)
	return code
}

// #1320: `enterprise secret check` reports what inspection.ai_defense reports
// once a request was answered: ok for an accepted key, exit 1 with
// ai_defense_rejected for a rejected one, and refusals before the request
// as the failure document of the other secret verbs.
func TestEnterpriseSecretCheckReportsTheKeyOutcome(t *testing.T) {
	_, _, euid := anchorsInstallDevice(t)
	cfg := &config.Config{Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	loadInstalledConfig = func(*enterpriseunix.Env) (*config.Config, error) { return cfg, nil }
	posture := "ok"
	checkAIDefense = func(context.Context, *config.Config) (string, error) { return posture, nil }
	t.Cleanup(func() {
		loadInstalledConfig = func(env *enterpriseunix.Env) (*config.Config, error) { return env.InstalledConfig() }
		checkAIDefense = gateway.CheckStandaloneAIDefense
	})

	doc, _, code := runSecretCheck(t, "--name", "ai-defense-api-key", "--json")
	if code != 0 || doc["ok"] != true || doc["action"] != "check" || doc["ai_defense"] != "ok" || errorCode(doc) != "" {
		t.Fatalf("accepted key: exit %d %v", code, doc)
	}

	posture = "unavailable:auth_failed"
	doc, _, code = runSecretCheck(t, "--name", "ai-defense-api-key", "--json")
	if code != 1 || doc["ok"] != false || doc["ai_defense"] != "rejected" || errorCode(doc) != "ai_defense_rejected" || doc["exit_code"] != float64(1) {
		t.Fatalf("rejected key: exit %d %v", code, doc)
	}

	posture = "disabled"
	if doc, _, code = runSecretCheck(t, "--name", "ai-defense-api-key", "--json"); code != 1 || errorCode(doc) != "ai_defense_disabled" {
		t.Fatalf("AI Defense off: exit %d %v", code, doc)
	}

	if doc, _, code = runSecretCheck(t, "--name", "judge-key", "--json"); code != 2 || errorCode(doc) != "invalid_arguments" {
		t.Fatalf("another credential: exit %d %v", code, doc)
	}

	loadInstalledConfig = func(*enterpriseunix.Env) (*config.Config, error) { return nil, fs.ErrNotExist }
	if doc, _, code = runSecretCheck(t, "--name", "ai-defense-api-key", "--json"); code != 1 || errorCode(doc) != "not_installed" {
		t.Fatalf("not installed: exit %d %v", code, doc)
	}

	*euid = 1000
	if doc, _, code = runSecretCheck(t, "--name", "ai-defense-api-key", "--json"); code != 1 || errorCode(doc) != "not_root" {
		t.Fatalf("not root: exit %d %v", code, doc)
	}
}

// The example runs the gateway by its absolute path: it is not on the PATH
// (cowork-1-0-8 GAP-0081).
func TestSecretCheckExampleNamesTheGatewayByItsFullPath(t *testing.T) {
	example := newEnterpriseSecretCheckCommand().Example
	want := "sudo " + managedHostGatewayCommand() + " enterprise secret check"
	if !strings.Contains(example, want) || strings.Contains(example, "sudo defenseclaw-gateway") {
		t.Fatalf("example = %q, want it to contain %q", example, want)
	}
}

// A Secure Client computer keeps the example of release 1.0.5 after the
// command tree is cut down to the one of main (review round 4, S1).
func TestSecretCheckExampleOnSecureClientKeepsTheReleasedText(t *testing.T) {
	previous := secureClientHost
	t.Cleanup(func() { secureClientHost = previous })
	root := &cobra.Command{Use: "defenseclaw-gateway"}
	check := newEnterpriseSecretCheckCommand()
	root.AddCommand(check)

	secureClientHost = func() bool { return true }
	keepCommandTreeOfMainOnSecureClient(root)
	const released = "  sudo defenseclaw-gateway enterprise secret check --name ai-defense-api-key --json"
	if check.Example != released {
		t.Fatalf("Secure Client example = %q, want %q", check.Example, released)
	}
}
