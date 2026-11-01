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
	"errors"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestManagementContractWindowsSecretCheck validates every Windows
// `enterprise secret check --json` document against
// secret-result.schema.json: the answered request (check result branch) and
// each failure before the request (the Windows failure branch with action
// check). Those failures printed action check, which that branch did not
// allow (rel-1-0-6:GAP-0036 review). stdout holds exactly one document,
// stderr nothing, and the exit code is the document's.
func TestManagementContractWindowsSecretCheck(t *testing.T) {
	schemas := contracttest.Compile(t)
	valid := []string{"--name", "ai-defense-api-key", "--json"}
	for _, tc := range []struct {
		name    string
		args    []string
		setup   func(posture *string, probeErr *error)
		code    string // errors[0].code; "" for an accepted key
		exit    int
		checked bool // the document is the check result (ai_defense set)
	}{
		{name: "accepted key", exit: 0, checked: true},
		{name: "rejected key", setup: func(p *string, _ *error) { *p = "unavailable:auth_failed" },
			code: "ai_defense_unavailable", exit: windowsSecretExitFailure, checked: true},
		{name: "ai defense off", setup: func(p *string, _ *error) { *p = "disabled" },
			code: "ai_defense_disabled", exit: windowsSecretExitFailure, checked: true},
		{name: "not elevated, managed",
			setup: func(*string, *error) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
			},
			code: "elevation_required", exit: enterprisestatus.WindowsExitAccessDenied},
		{name: "not elevated, unmanaged",
			setup: func(*string, *error) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return "", false }
			},
			code: "elevation_required", exit: windowsSecretExitFailure},
		{name: "bad name", args: []string{"--name", "BAD", "--json"}, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "not the ai defense credential", args: []string{"--name", "other-key", "--json"}, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "missing name", args: []string{"--json"}, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "bad flag", args: append(append([]string{}, valid...), "--bogus"), code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "not installed",
			setup: func(*string, *error) {
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
			},
			code: "not_installed", exit: windowsSecretExitFailure},
		{name: "deployment record unreadable",
			setup: func(*string, *error) {
				windowsSecretDeploymentInstalled = func() (bool, error) {
					return false, errors.New("the standalone deployment record cannot be read")
				}
			},
			code: "state_invalid", exit: windowsSecretExitFailure},
		{name: "request not built", setup: func(_ *string, e *error) { *e = errors.New("the AI Defense client cannot be built") },
			code: "state_invalid", exit: windowsSecretExitFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := managed.StandaloneLayout{GOOS: "windows", SecretsDir: filepath.Join(t.TempDir(), "secrets"), LifecycleDir: t.TempDir()}
			stubWindowsSecretHost(t, layout)
			savedCheck, savedLoad := checkAIDefense, loadSecretCheckConfig
			t.Cleanup(func() { checkAIDefense, loadSecretCheckConfig = savedCheck, savedLoad })
			// As the real loader: the deployment check first, then the installed
			// config, which here is this one.
			cfg := &config.Config{Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
			cfg.Enterprise.Inspection.AIDefense.Credential = "ai-defense-api-key"
			loadSecretCheckConfig = func() (*config.Config, error) {
				if err := requireWindowsSecretDeployment(); err != nil {
					return nil, err
				}
				return cfg, nil
			}
			posture, probeErr := "ok", error(nil)
			if tc.setup != nil {
				tc.setup(&posture, &probeErr)
			}
			checkAIDefense = func(context.Context, *config.Config) (string, error) { return posture, probeErr }
			args := valid
			if tc.args != nil {
				args = tc.args
			}
			secretRawArgs = func() []string { return args }
			cmd := newEnterpriseSecretCheckCommand()
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(args)
			err := cmd.ExecuteContext(context.Background())
			if stderr.Len() != 0 {
				t.Fatalf("%v: stderr %q, want nothing (the document carries the error); stdout %q", args, stderr.String(), stdout.String())
			}
			if bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
				t.Fatalf("%v: want exactly one document, got %q", args, stdout.String())
			}
			doc := schemas.Validate(t, "secret-result.schema.json", stdout.Bytes())
			requireExit(t, doc, runExit(err), tc.exit)
			var code any = ""
			if errs, _ := doc["errors"].([]any); len(errs) > 0 {
				if first, ok := errs[0].(map[string]any); ok {
					code = first["code"]
				}
			}
			_, hasPosture := doc["ai_defense"]
			if doc["action"] != "check" || code != tc.code || hasPosture != tc.checked || (doc["ok"] == true) != (tc.code == "") {
				t.Fatalf("%v: document %s, want action check, code %q, check result %v", args, stdout.String(), tc.code, tc.checked)
			}
		})
	}
}
