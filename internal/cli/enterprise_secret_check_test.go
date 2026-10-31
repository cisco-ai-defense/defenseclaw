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
	"testing"

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
// ai_defense_unavailable for a rejected one, and refusals before the request
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
	if code != 1 || doc["ok"] != false || doc["ai_defense"] != "unavailable:auth_failed" || errorCode(doc) != "ai_defense_unavailable" || doc["exit_code"] != float64(1) {
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
