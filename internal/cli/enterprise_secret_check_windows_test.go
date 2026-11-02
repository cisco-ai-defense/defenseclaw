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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if code != windowsSecretExitFailure || doc["ok"] != false || doc["ai_defense"] != "rejected" ||
		firstCode(doc) != "ai_defense_rejected" || doc["exit_code"] != float64(windowsSecretExitFailure) {
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

// A standalone command runs as an administrator, outside the gateway's
// service environment. The probe must still validate and read the same
// protected file that the gateway service reads before making its request.
func TestWindowsEnterpriseSecretCheckProbesStoredKey(t *testing.T) {
	const key = "stored-key-GAP-0460"
	dir := windowsSecretTestHarness(t)
	// TrustedInstaller is an independently trusted reader. Use an ordinary
	// virtual service SID so the missing gateway identity reproduces the bug.
	windowsSecretGatewayAccount = `NT SERVICE\W32Time`
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{
		name: "ai-defense-api-key", fromStdin: true,
	}, key+"\n"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.WindowsServiceAccountEnv, "")
	cfg := &config.Config{
		ConfigFilePath: filepath.Join(filepath.Dir(dir), "etc", "config.yaml"),
		DeploymentMode: string(config.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	savedLoad := loadSecretCheckConfig
	loadSecretCheckConfig = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { loadSecretCheckConfig = savedLoad })
	for _, tc := range []struct {
		name, posture string
		status        int
		exit          int
	}{
		{"rejected 401", "rejected", http.StatusUnauthorized, windowsSecretExitFailure},
		{"rejected 403", "rejected", http.StatusForbidden, windowsSecretExitFailure},
		{"accepted", "ok", http.StatusOK, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan bool, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case requests <- r.Header.Get("X-Cisco-AI-Defense-API-Key") == key:
				default:
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"is_safe":true,"action":"Allow"}`))
			}))
			defer server.Close()
			cfg.CiscoAIDefense.Endpoint = server.URL
			cfg.CiscoAIDefense.TimeoutMs = 2000
			check := newEnterpriseSecretCheckCommand()
			var out bytes.Buffer
			check.SetOut(&out)
			check.SetErr(io.Discard)
			check.SetArgs([]string{"--name", "ai-defense-api-key", "--json"})
			err := check.ExecuteContext(context.Background())
			if strings.Contains(out.String(), key) {
				t.Fatal("secret check printed the stored key")
			}
			var doc secretCheckResult
			if json.Unmarshal(out.Bytes(), &doc) != nil || doc.AIDefense != tc.posture || runExit(err) != tc.exit {
				t.Fatalf("check posture = %q, exit = %d; want %q, %d", doc.AIDefense, runExit(err), tc.posture, tc.exit)
			}
			if tc.exit != 0 && (len(doc.Errors) != 1 || doc.Errors[0].Code != "ai_defense_rejected" || !strings.Contains(doc.Errors[0].Message, "rejected")) {
				t.Fatal("a rejected key was not reported as rejected")
			}
			select {
			case carriedKey := <-requests:
				if !carriedKey {
					t.Fatal("the request did not carry the stored key")
				}
			default:
				t.Fatal("the check did not make a request")
			}
		})
	}
	unreachable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cfg.CiscoAIDefense.Endpoint = unreachable.URL
	unreachable.Close()
	check := newEnterpriseSecretCheckCommand()
	var out bytes.Buffer
	check.SetOut(&out)
	check.SetErr(io.Discard)
	check.SetArgs([]string{"--name", "ai-defense-api-key", "--json"})
	err := check.ExecuteContext(context.Background())
	var doc secretCheckResult
	if strings.Contains(out.String(), key) {
		t.Fatal("unreachable check printed the stored key")
	}
	if json.Unmarshal(out.Bytes(), &doc) != nil || doc.AIDefense != "unavailable:unreachable" ||
		runExit(err) != windowsSecretExitFailure || len(doc.Errors) != 1 || doc.Errors[0].Code != "ai_defense_unavailable" {
		t.Fatalf("unreachable check posture = %q, exit = %d", doc.AIDefense, runExit(err))
	}
	if err := os.Remove(filepath.Join(dir, "ai-defense-api-key")); err != nil {
		t.Fatal(err)
	}
	check = newEnterpriseSecretCheckCommand()
	out.Reset()
	check.SetOut(&out)
	check.SetErr(io.Discard)
	check.SetArgs([]string{"--name", "ai-defense-api-key", "--json"})
	err = check.ExecuteContext(context.Background())
	doc = secretCheckResult{}
	if strings.Contains(out.String(), key) {
		t.Fatal("secret check printed the removed key")
	}
	if json.Unmarshal(out.Bytes(), &doc) != nil || doc.AIDefense != "unavailable:credential_unavailable" || runExit(err) != windowsSecretExitFailure ||
		len(doc.Errors) != 1 || doc.Errors[0].Code != "ai_defense_unavailable" || !strings.Contains(doc.Errors[0].Message, "could not check") {
		t.Fatal("missing credential was not reported as unavailable")
	}
}
