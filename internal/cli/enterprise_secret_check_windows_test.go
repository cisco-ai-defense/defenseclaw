// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-6:GAP-0036: Windows has `enterprise secret check` too. It reports
// what inspection.ai_defense reports once a request was answered, with the
// Windows exit codes: 0 accepted, 1603 not accepted, 1639 a --name that is
// not the AI Defense credential, 5 a standard account on a managed computer.
func TestWindowsEnterpriseSecretCheckReportsTheKeyOutcome(t *testing.T) {
	cmd := enterpriseSecretCmd
	found := false
	for _, sub := range cmd.Commands() {
		found = found || sub.Name() == "check"
	}
	if !found {
		t.Fatal("enterprise secret has no check verb on Windows")
	}
	savedCheck, savedLoad, savedElevated, savedHost := checkAIDefense, loadSecretCheckConfig, windowsSecretIsElevated, managedHostWindowsStandalone
	t.Cleanup(func() {
		checkAIDefense, loadSecretCheckConfig, windowsSecretIsElevated, managedHostWindowsStandalone = savedCheck, savedLoad, savedElevated, savedHost
	})
	cfg := &config.Config{Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	cfg.Enterprise.Inspection.AIDefense.Credential = "ai-defense-api-key"
	loadSecretCheckConfig = func() (*config.Config, error) { return cfg, nil }
	windowsSecretIsElevated = func() bool { return true }
	posture := "ok"
	checkAIDefense = func(context.Context, *config.Config) (string, error) { return posture, nil }
	run := func(args ...string) (map[string]any, int) {
		t.Helper()
		check := newEnterpriseSecretCheckCommand()
		var out bytes.Buffer
		check.SetOut(&out)
		check.SetErr(io.Discard)
		check.SetArgs(args)
		code := 0
		if err := check.ExecuteContext(context.Background()); err != nil {
			code = commandExitCode(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("not one JSON document (exit %d): %v\n%s", code, err, out.String())
		}
		return doc, code
	}
	firstCode := func(doc map[string]any) string {
		errs, _ := doc["errors"].([]any)
		if len(errs) == 0 {
			return ""
		}
		first, _ := errs[0].(map[string]any)
		code, _ := first["code"].(string)
		return code
	}
	doc, code := run("--name", "ai-defense-api-key", "--json")
	if code != 0 || doc["ok"] != true || doc["action"] != "check" || doc["ai_defense"] != "ok" || firstCode(doc) != "" {
		t.Fatalf("accepted key: exit %d, %v", code, doc)
	}
	posture = "unavailable:auth_failed"
	doc, code = run("--name", "ai-defense-api-key", "--json")
	if code != windowsSecretExitFailure || doc["ok"] != false || doc["ai_defense"] != posture ||
		firstCode(doc) != "ai_defense_unavailable" || doc["exit_code"] != float64(windowsSecretExitFailure) {
		t.Fatalf("rejected key: exit %d, %v", code, doc)
	}
	doc, code = run("--name", "other-key", "--json")
	if code != windowsSecretExitInvalid || firstCode(doc) != "invalid_arguments" {
		t.Fatalf("a name that is not the AI Defense credential: exit %d, %v", code, doc)
	}
	windowsSecretIsElevated = func() bool { return false }
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
	doc, code = run("--name", "ai-defense-api-key", "--json")
	if code != 5 || firstCode(doc) != "elevation_required" {
		t.Fatalf("a standard account: exit %d, %v", code, doc)
	}
}
