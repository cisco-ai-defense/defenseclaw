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

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const geminiEffectiveTestToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGeminiSettingsJSONCMatchesVendorCommentContract(t *testing.T) {
	parsed, err := parseGeminiSettingsObject([]byte(`{
  // a line comment
  "url": "https://example.test//literal/*value*/",
  /* a block comment */
  "nested": {"enabled": true}
}`), "settings.json")
	if err != nil {
		t.Fatalf("parse commented Gemini settings: %v", err)
	}
	if got := parsed["url"]; got != "https://example.test//literal/*value*/" {
		t.Fatalf("comment markers inside string changed: %#v", got)
	}
	if _, err := parseGeminiSettingsObject([]byte(`{"nested":{"enabled":true,}}`), "settings.json"); err == nil {
		t.Fatal("Gemini JSONC parser accepted a trailing comma rejected by JSON.parse")
	}
	if _, err := parseGeminiSettingsObject([]byte(`{/* unterminated`), "settings.json"); err == nil {
		t.Fatal("Gemini JSONC parser accepted an unterminated block comment")
	}
}

func TestManagedGeminiTelemetryOwnershipIsExact(t *testing.T) {
	foreign := map[string]interface{}{
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"otlpEndpoint": "https://operator.example/otlp/geminicli/team",
			"operator":     "keep",
		},
	}
	if changed := pruneGeminiConfigEntries(foreign, nil); changed {
		t.Fatalf("foreign Gemini telemetry was treated as managed: %#v", foreign)
	}
	telemetry := foreign["telemetry"].(map[string]interface{})
	if telemetry["operator"] != "keep" || telemetry["otlpEndpoint"] == nil {
		t.Fatalf("foreign Gemini telemetry was mutated: %#v", telemetry)
	}
	managed := "http://127.0.0.1:18970/otlp/geminicli/" + geminiEffectiveTestToken
	if !managedGeminiOTLPEndpoint(managed) {
		t.Fatalf("canonical managed Gemini endpoint was not recognized: %s", managed)
	}
	for _, endpoint := range []string{
		"https://operator.example/otlp/geminicli/" + geminiEffectiveTestToken,
		"http://127.0.0.1:18970/otlp/geminicli/not-a-token",
		"http://127.0.0.1:18970/otlp/geminicli/" + strings.ToUpper(geminiEffectiveTestToken),
		"http://127.0.0.1:18970/otlp/geminicli/" + geminiEffectiveTestToken + "/extra",
	} {
		if managedGeminiOTLPEndpoint(endpoint) {
			t.Errorf("non-managed Gemini endpoint was recognized: %s", endpoint)
		}
	}
}

func TestGeminiVerifyCleanRejectsManagedTelemetryResidue(t *testing.T) {
	root := t.TempDir()
	settingsPath := filepath.Join(root, "settings.json")
	previous := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = settingsPath
	t.Cleanup(func() { GeminiSettingsPathOverride = previous })
	writeGeminiTestSettings(t, settingsPath, map[string]interface{}{
		"telemetry": map[string]interface{}{
			"enabled":      true,
			"traces":       true,
			"otlpEndpoint": "http://127.0.0.1:18970/otlp/geminicli/" + geminiEffectiveTestToken,
		},
	})
	conn := NewGeminiCLIConnector()
	err := conn.VerifyClean(SetupOpts{DataDir: filepath.Join(root, "dc")})
	if err == nil || !strings.Contains(err.Error(), "managed native telemetry") {
		t.Fatalf("VerifyClean accepted managed Gemini telemetry residue: %v", err)
	}
}

func TestGeminiEffectiveSettingsRejectKnownHigherPrecedenceOverrides(t *testing.T) {
	t.Run("user hooks disabled", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, userPath, map[string]interface{}{
			"hooksConfig": map[string]interface{}{"enabled": false},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "hooksConfig.enabled=false") {
			t.Fatalf("disabled user hooks were not rejected: %v", err)
		}
	})

	t.Run("current workspace disables DefenseClaw", func(t *testing.T) {
		opts, userPath, workspacePath, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, workspacePath, map[string]interface{}{
			"hooksConfig": map[string]interface{}{"disabled": []interface{}{"defenseclaw"}},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "hook name defenseclaw is disabled") {
			t.Fatalf("workspace hook disable was not rejected: %v", err)
		}
	})

	t.Run("settings environment expansion disables DefenseClaw", func(t *testing.T) {
		opts, userPath, workspacePath, _ := newGeminiEffectiveTestLayout(t)
		t.Setenv("DEFENSECLAW_TEST_BLOCKED_HOOK", "defenseclaw")
		writeGeminiTestSettings(t, workspacePath, map[string]interface{}{
			"hooksConfig": map[string]interface{}{"disabled": []interface{}{"$DEFENSECLAW_TEST_BLOCKED_HOOK"}},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "hook name defenseclaw is disabled") {
			t.Fatalf("expanded workspace hook disable was not rejected: %v", err)
		}
	})

	t.Run("settings environment default disables DefenseClaw", func(t *testing.T) {
		opts, userPath, workspacePath, _ := newGeminiEffectiveTestLayout(t)
		unsetEnvironmentForGeminiTest(t, "DEFENSECLAW_TEST_UNSET_HOOK")
		writeGeminiTestSettings(t, workspacePath, map[string]interface{}{
			"hooksConfig": map[string]interface{}{"disabled": []interface{}{"${DEFENSECLAW_TEST_UNSET_HOOK:-defenseclaw}"}},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "hook name defenseclaw is disabled") {
			t.Fatalf("default-expanded workspace hook disable was not rejected: %v", err)
		}
	})

	t.Run("process cwd is inspected when workspace is not pinned", func(t *testing.T) {
		opts, userPath, workspacePath, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, workspacePath, map[string]interface{}{
			"hooksConfig": map[string]interface{}{"enabled": false},
		})
		t.Chdir(opts.WorkspaceDir)
		opts.WorkspaceDir = ""
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "hooksConfig.enabled=false") {
			t.Fatalf("current-working-directory hook disable was not rejected: %v", err)
		}
	})

	t.Run("system redirects telemetry", func(t *testing.T) {
		opts, userPath, _, systemPath := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, systemPath, map[string]interface{}{
			"telemetry": map[string]interface{}{"otlpEndpoint": "https://operator.example/otlp"},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "otlpEndpoint is overridden") {
			t.Fatalf("system telemetry redirect was not rejected: %v", err)
		}
	})

	t.Run("workspace outfile overrides collector", func(t *testing.T) {
		opts, userPath, workspacePath, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, workspacePath, map[string]interface{}{
			"telemetry": map[string]interface{}{"outfile": "operator-telemetry.jsonl"},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "outfile is overridden") {
			t.Fatalf("workspace telemetry outfile was not rejected: %v", err)
		}
	})

	t.Run("system enables incompatible CLI auth", func(t *testing.T) {
		opts, userPath, _, systemPath := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, systemPath, map[string]interface{}{
			"telemetry": map[string]interface{}{"useCliAuth": true},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "useCliAuth is overridden") {
			t.Fatalf("system telemetry useCliAuth was not rejected: %v", err)
		}
	})

	t.Run("system environment default redirects telemetry", func(t *testing.T) {
		opts, userPath, _, systemPath := newGeminiEffectiveTestLayout(t)
		unsetEnvironmentForGeminiTest(t, "DEFENSECLAW_TEST_UNSET_ENDPOINT")
		writeGeminiTestSettings(t, systemPath, map[string]interface{}{
			"telemetry": map[string]interface{}{
				"otlpEndpoint": "${DEFENSECLAW_TEST_UNSET_ENDPOINT:-https://operator.example/otlp}",
			},
		})
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "otlpEndpoint is overridden") {
			t.Fatalf("expanded system telemetry redirect was not rejected: %v", err)
		}
	})

	t.Run("process environment redirects telemetry", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		t.Setenv("GEMINI_TELEMETRY_OTLP_ENDPOINT", "https://operator.example/otlp")
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "GEMINI_TELEMETRY_OTLP_ENDPOINT") {
			t.Fatalf("process telemetry redirect was not rejected: %v", err)
		}
	})

	for _, tc := range []struct {
		name  string
		value string
	}{
		{"OTEL_EXPORTER_OTLP_ENDPOINT", "https://operator.example/otlp"},
		{"GEMINI_TELEMETRY_OUTFILE", "operator-telemetry.jsonl"},
		{"GEMINI_TELEMETRY_USE_CLI_AUTH", "true"},
	} {
		t.Run("process environment rejects "+tc.name, func(t *testing.T) {
			opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
			t.Setenv(tc.name, tc.value)
			err := validateGeminiEffectiveSettings(opts, userPath, false)
			if err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("%s override was not rejected: %v", tc.name, err)
			}
		})
	}

	t.Run("home workspace does not create a duplicate pristine layer", func(t *testing.T) {
		unsetGeminiTelemetryEnvironment(t)
		root := t.TempDir()
		configHome := filepath.Join(root, ".gemini")
		userPath := filepath.Join(configHome, "settings.json")
		t.Setenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", filepath.Join(root, "system-defaults.json"))
		t.Setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", filepath.Join(root, "system-settings.json"))
		writeGeminiTestSettings(t, userPath, map[string]interface{}{
			"telemetry": map[string]interface{}{"otlpEndpoint": "https://operator.example/pristine"},
		})
		opts := SetupOpts{
			APIAddr:       "127.0.0.1:18970",
			ConfigHome:    configHome,
			WorkspaceDir:  root,
			OTLPPathToken: geminiEffectiveTestToken,
		}
		if err := validateGeminiEffectiveSettings(opts, userPath, false); err != nil {
			t.Fatalf("same user/workspace file manufactured a higher-layer override: %v", err)
		}
	})
}

func TestGeminiEffectiveDotEnvPrecedenceIsFailClosed(t *testing.T) {
	t.Run("trusted Gemini env overrides ordinary env", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		ordinary := filepath.Join(opts.WorkspaceDir, ".env")
		writeGeminiTestFile(t, ordinary, "GEMINI_TELEMETRY_ENABLED=true\n")
		geminiEnv := filepath.Join(opts.WorkspaceDir, ".gemini", ".env")
		writeGeminiTestFile(t, geminiEnv, "GEMINI_TELEMETRY_OTLP_ENDPOINT=https://operator.example/otlp\n")
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), geminiEnv) {
			t.Fatalf("effective .gemini/.env redirect was not rejected: %v", err)
		}
	})

	if runtime.GOOS == "windows" {
		t.Run("Windows dotenv names are case insensitive", func(t *testing.T) {
			opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
			writeGeminiTestFile(t, filepath.Join(opts.WorkspaceDir, ".gemini", ".env"), "gemini_telemetry_otlp_endpoint=https://operator.example/otlp\n")
			err := validateGeminiEffectiveSettings(opts, userPath, false)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "gemini_telemetry_otlp_endpoint") {
				t.Fatalf("case-insensitive Windows .env redirect was not rejected: %v", err)
			}
		})
	}

	t.Run("parent env is discovered", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		parent := filepath.Dir(opts.WorkspaceDir)
		writeGeminiTestFile(t, filepath.Join(parent, ".env"), "GEMINI_TELEMETRY_USE_COLLECTOR=false\n")
		err := validateGeminiEffectiveSettings(opts, userPath, false)
		if err == nil || !strings.Contains(err.Error(), "GEMINI_TELEMETRY_USE_COLLECTOR") {
			t.Fatalf("parent .env override was not rejected: %v", err)
		}
	})

	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"GEMINI_TELEMETRY_OUTFILE",
		"GEMINI_TELEMETRY_USE_CLI_AUTH",
	} {
		t.Run("trusted dotenv rejects "+name, func(t *testing.T) {
			opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
			writeGeminiTestFile(t, filepath.Join(opts.WorkspaceDir, ".gemini", ".env"), name+"=operator-override\n")
			err := validateGeminiEffectiveSettings(opts, userPath, false)
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s in trusted .env was not rejected: %v", name, err)
			}
		})
	}

	t.Run("ignoreLocalEnv skips ordinary project env", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, userPath, map[string]interface{}{
			"advanced": map[string]interface{}{"ignoreLocalEnv": true},
		})
		writeGeminiTestFile(t, filepath.Join(opts.WorkspaceDir, ".env"), "GEMINI_TELEMETRY_ENABLED=false\n")
		if err := validateGeminiEffectiveSettings(opts, userPath, false); err != nil {
			t.Fatalf("ignoreLocalEnv did not skip ordinary project .env: %v", err)
		}
	})

	t.Run("excluded telemetry key is skipped for ordinary env", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		writeGeminiTestSettings(t, userPath, map[string]interface{}{
			"advanced": map[string]interface{}{
				"excludedEnvVars": []interface{}{"GEMINI_TELEMETRY_OTLP_ENDPOINT"},
			},
		})
		writeGeminiTestFile(t, filepath.Join(opts.WorkspaceDir, ".env"), "GEMINI_TELEMETRY_OTLP_ENDPOINT=https://operator.example/otlp\n")
		if err := validateGeminiEffectiveSettings(opts, userPath, false); err != nil {
			t.Fatalf("excluded project env key affected effective telemetry: %v", err)
		}
	})

	t.Run("preset process value wins over dotenv", func(t *testing.T) {
		opts, userPath, _, _ := newGeminiEffectiveTestLayout(t)
		desiredEndpoint := "http://127.0.0.1:18970/otlp/geminicli/" + geminiEffectiveTestToken
		t.Setenv("GEMINI_TELEMETRY_OTLP_ENDPOINT", desiredEndpoint)
		writeGeminiTestFile(t, filepath.Join(opts.WorkspaceDir, ".gemini", ".env"), "GEMINI_TELEMETRY_OTLP_ENDPOINT=https://operator.example/otlp\n")
		if err := validateGeminiEffectiveSettings(opts, userPath, false); err != nil {
			t.Fatalf("dotenv overrode a valid preset process value: %v", err)
		}
	})
}

func TestGeminiTelemetryEnvironmentNameCaseFollowsPlatform(t *testing.T) {
	const lower = "gemini_telemetry_enabled"
	if got := geminiTelemetryEnvironmentKeyForOS(lower, "windows"); got != "GEMINI_TELEMETRY_ENABLED" {
		t.Fatalf("Windows telemetry env key = %q", got)
	}
	if got := geminiTelemetryEnvironmentKeyForOS(lower, "linux"); got != lower {
		t.Fatalf("non-Windows telemetry env key = %q, want case-sensitive %q", got, lower)
	}
}

func newGeminiEffectiveTestLayout(t *testing.T) (SetupOpts, string, string, string) {
	t.Helper()
	unsetGeminiTelemetryEnvironment(t)
	root := t.TempDir()
	configHome := filepath.Join(root, "home", ".gemini")
	workspace := filepath.Join(root, "repo", "child")
	userPath := filepath.Join(configHome, "settings.json")
	workspacePath := filepath.Join(workspace, ".gemini", "settings.json")
	defaultsPath := filepath.Join(root, "system", "system-defaults.json")
	systemPath := filepath.Join(root, "system", "settings.json")
	t.Setenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", defaultsPath)
	t.Setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", systemPath)
	return SetupOpts{
		APIAddr:       "127.0.0.1:18970",
		ConfigHome:    configHome,
		WorkspaceDir:  workspace,
		OTLPPathToken: geminiEffectiveTestToken,
	}, userPath, workspacePath, systemPath
}

func unsetGeminiTelemetryEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range geminiTelemetryEnvironmentNames {
		unsetEnvironmentForGeminiTest(t, name)
	}
}

func unsetEnvironmentForGeminiTest(t *testing.T, name string) {
	t.Helper()
	value, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func writeGeminiTestSettings(t *testing.T, path string, value map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal Gemini settings: %v", err)
	}
	writeGeminiTestFile(t, path, string(data))
}

func writeGeminiTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create %s parent: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
