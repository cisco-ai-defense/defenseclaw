// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func envOf(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestObservedEnvRedirectRecordsOnlyMovedLocations(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	req.AccountHome = req.Home
	custom := filepath.Join(req.Home, "alt-copilot")

	if _, ok := ObservedEnvRedirect(req); ok {
		t.Fatal("no environment: nothing is redirected")
	}
	req.Getenv = envOf(map[string]string{"COPILOT_HOME": filepath.Join(req.Home, ".copilot")})
	if _, ok := ObservedEnvRedirect(req); ok {
		t.Fatal("a value naming the default location redirects nothing")
	}
	req.Getenv = envOf(map[string]string{"COPILOT_HOME": custom + string(filepath.Separator)})
	redirect, ok := ObservedEnvRedirect(req)
	if !ok || redirect.Vars["COPILOT_HOME"] != custom || len(redirect.Homes) != 0 {
		t.Fatalf("COPILOT_HOME moves the user config: %+v %v", redirect, ok)
	}
	req.Getenv = envOf(map[string]string{"COPILOT_HOME": "relative/copilot"})
	if redirect, ok := ObservedEnvRedirect(req); ok {
		t.Fatalf("a relative value depends on the agent's working directory and is not recorded: %+v", redirect)
	}

	envHome := filepath.Join(req.Home, "other-home")
	req.Getenv = nil
	req.Home, req.Homes = req.AccountHome, []string{envHome}
	redirect, ok = ObservedEnvRedirect(req)
	if !ok || len(redirect.Homes) != 1 || redirect.Homes[0] != envHome {
		t.Fatalf("a HOME other than the account's is recorded: %+v %v", redirect, ok)
	}
	req.AccountHome = ""
	if _, ok := ObservedEnvRedirect(req); ok {
		t.Fatal("without the account's home nothing is recorded")
	}
}

func TestObservedEnvRedirectSkipsInlineContent(t *testing.T) {
	req := guardRequest(t, "opencode", config.ForeignHooksRemove)
	req.AccountHome = req.Home
	req.Getenv = envOf(map[string]string{"OPENCODE_CONFIG_CONTENT": `{"plugin":["x"]}`})
	if redirect, ok := ObservedEnvRedirect(req); ok {
		t.Fatalf("inline config content is not a location: %+v", redirect)
	}
	dir := filepath.Join(req.Home, "oc")
	req.Getenv = envOf(map[string]string{"OPENCODE_CONFIG_CONTENT": `{}`, "OPENCODE_CONFIG_DIR": dir, "XDG_CONFIG_HOME": filepath.Join(req.Home, ".config")})
	redirect, ok := ObservedEnvRedirect(req)
	if !ok || redirect.Vars["OPENCODE_CONFIG_DIR"] != dir {
		t.Fatalf("OPENCODE_CONFIG_DIR is recorded: %+v", redirect)
	}
	if _, inline := redirect.Vars["OPENCODE_CONFIG_CONTENT"]; inline {
		t.Fatalf("inline content must never be recorded: %+v", redirect)
	}
}

// The record is the user's: LoadEnvRedirects keeps only absolute, plain
// location values under well-formed variable names.
func TestLoadEnvRedirectsDropsInvalidValues(t *testing.T) {
	home := t.TempDir()
	good := filepath.Join(home, "claude-alt")
	record := map[string]any{
		"v": 1,
		"connectors": map[string]any{
			"claudecode": []any{
				map[string]any{"vars": map[string]string{
					"CLAUDE_CONFIG_DIR":       good,
					"lower_case":              good,
					"XDG_CONFIG_HOME":         "relative",
					"CODEX_HOME":              good + "\nx",
					"OPENCODE_CONFIG_CONTENT": good,
				}, "homes": []string{"relative-home", good}},
				map[string]any{"vars": map[string]string{"CLAUDE_CONFIG_DIR": "also/relative"}},
			},
		},
	}
	data, _ := json.Marshal(record)
	writeFile(t, EnvRecordPath(home), string(data))
	redirects, err := LoadEnvRedirects(home, "claudecode")
	if err != nil || len(redirects) != 1 {
		t.Fatalf("only the valid redirect remains: %+v %v", redirects, err)
	}
	if len(redirects[0].Vars) != 1 || redirects[0].Vars["CLAUDE_CONFIG_DIR"] != good || len(redirects[0].Homes) != 1 || redirects[0].Homes[0] != good {
		t.Fatalf("invalid values must be dropped: %+v", redirects[0])
	}
	writeFile(t, EnvRecordPath(home), "{broken")
	if _, err := LoadEnvRedirects(home, "claudecode"); err == nil {
		t.Fatal("a corrupt record is an error")
	}
	if _, err := LoadEnvRedirects("relative", "claudecode"); err == nil {
		t.Fatal("a relative home is an error")
	}

	t.Run("round trip", func(t *testing.T) {
		home := t.TempDir()
		now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
		one := EnvRedirect{Vars: map[string]string{"CODEX_HOME": filepath.Join(home, "codex-a")}}
		if err := RecordEnvRedirect(home, "codex", one, now); err != nil {
			t.Fatal(err)
		}
		// Seeing the same redirect again soon does not rewrite the record; a
		// day later it refreshes its last-seen time.
		if err := RecordEnvRedirect(home, "codex", one, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if redirects, err := LoadEnvRedirects(home, "codex"); err != nil || len(redirects) != 1 || redirects[0].Seen != now.Format(time.RFC3339) {
			t.Fatalf("an unchanged redirect must not rewrite the record: %+v %v", redirects, err)
		}
		if err := RecordEnvRedirect(home, "codex", one, now.Add(envRefreshAfter+time.Hour)); err != nil {
			t.Fatal(err)
		}
		if redirects, _ := LoadEnvRedirects(home, "codex"); len(redirects) != 1 || redirects[0].Seen != now.Add(envRefreshAfter+time.Hour).Format(time.RFC3339) {
			t.Fatalf("a redirect seen again a day later is refreshed, not duplicated: %+v", redirects)
		}
		now = now.Add(envRefreshAfter + time.Hour)
		for i := 0; i < envRedirectLimit+3; i++ {
			redirect := EnvRedirect{Vars: map[string]string{"CODEX_HOME": filepath.Join(home, "codex-"+string(rune('b'+i)))}}
			if err := RecordEnvRedirect(home, "codex", redirect, now.Add(time.Duration(i+2)*time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		redirects, err := LoadEnvRedirects(home, "codex")
		if err != nil || len(redirects) != envRedirectLimit {
			t.Fatalf("the record keeps the %d most recent redirects: %d %v", envRedirectLimit, len(redirects), err)
		}
		if !strings.HasSuffix(redirects[0].Vars["CODEX_HOME"], "codex-"+string(rune('b'+envRedirectLimit+2))) {
			t.Fatalf("the most recent redirect comes first: %+v", redirects[0])
		}
		if other, _ := LoadEnvRedirects(home, "cursor"); len(other) != 0 {
			t.Fatalf("redirects are per connector: %+v", other)
		}
	})
}

// The guardian's cleanup has no user environment: with the redirect the
// hook recorded it also cleans the redirected user config, and a file both
// reach is cleaned once.
func TestCleanupCoversRecordedEnvRedirects(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	req.AccountHome = req.Home
	custom := filepath.Join(req.Home, "alt-copilot")
	redirected := filepath.Join(custom, "hooks", "rewrite.json")
	writeFile(t, redirected, `{"hooks": {"preToolUse": [{"bash": "./rewrite.sh"}]}}`)
	defaultHooks := filepath.Join(req.Home, ".copilot", "hooks", "other.json")
	writeFile(t, defaultHooks, `{"hooks": {"preToolUse": [{"bash": "./other.sh"}]}}`)

	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 1 || result.Removed[0].Path != defaultHooks {
		t.Fatalf("without the redirect only the default location is cleaned: %+v %v", result, err)
	}
	if !strings.Contains(readFile(t, redirected), "rewrite.sh") {
		t.Fatal("the redirected file is out of reach without the recorded redirect")
	}

	writeFile(t, defaultHooks, `{"hooks": {"preToolUse": [{"bash": "./other.sh"}]}}`)
	redirect := EnvRedirect{Vars: map[string]string{"COPILOT_HOME": custom}}
	result, err = CleanUserForeignHooksWithRedirects(req, []EnvRedirect{redirect, redirect}, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]int{}
	for _, finding := range result.Removed {
		paths[finding.Path]++
	}
	if paths[redirected] != 1 || paths[defaultHooks] != 1 || len(result.Removed) != 2 {
		t.Fatalf("each file is cleaned once, the redirected one included: %+v", result.Removed)
	}
	if strings.Contains(readFile(t, redirected), "rewrite.sh") || strings.Contains(readFile(t, defaultHooks), "other.sh") {
		t.Fatal("both foreign hooks must be removed")
	}
	if !strings.HasPrefix(result.BackupDir, filepath.Join(req.Home, ".defenseclaw", "foreign-hooks-backup")) {
		t.Fatalf("backups stay in the account's home: %q", result.BackupDir)
	}
}
