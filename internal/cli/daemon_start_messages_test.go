// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1864: a gateway that exits before readiness reports the error it
// logged (here a locked audit database), not the health probe's refusal,
// and never an error an earlier run left in gateway.log.
func TestGatewayExitedBeforeReadinessNamesTheLoggedCause(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	if err := os.WriteFile(logPath, []byte("Error: an older run failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	offset := gatewayLogSize(logPath)
	probe := fmt.Errorf("%w (last health probe: dial tcp: connection refused)", errGatewayExitedBeforeReadiness)
	if err := gatewayExitedBeforeReadinessError(probe, logPath, offset); err != probe {
		t.Fatalf("no new log error: %v, want the probe error", err)
	}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("[gateway] starting\nError: failed to open audit store: audit: refresh baselines: database is locked (5) (SQLITE_BUSY)\n")
	_ = file.Close()
	msg := gatewayExitedBeforeReadinessError(probe, logPath, offset).Error()
	for _, want := range []string{"another program has the audit database locked", "database is locked (5)", "try again in a moment"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "older run") {
		t.Errorf("error %q still shows the probe detail or an old error", msg)
	}
}

// GAP-0097: a jsonl destination path that became a directory stops the
// gateway with runtime_unavailable; the start error names the destination,
// the path and the rule the gateway logged, not only the code.
func TestGatewayExitedBeforeReadinessNamesTheRefusedDestination(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	offset := gatewayLogSize(logPath)
	line := `defenseclaw: observability destination "lane-copy": /home/u/.defenseclaw/lane.jsonl is a directory; ` +
		"point it at a file; fix the path or remove the destination\n"
	body := "[gateway] starting\n" + line +
		"Error: sidecar: observability v8 bootstrap: sidecar observability v8 bootstrap failed: runtime_unavailable\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := fmt.Errorf("%w (last health probe: dial tcp: connection refused)", errGatewayExitedBeforeReadiness)
	msg := gatewayExitedBeforeReadinessError(probe, logPath, offset).Error()
	for _, want := range []string{`observability destination "lane-copy"`, "lane.jsonl is a directory", "runtime_unavailable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
}

func writeGatewayMessageConfig(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	raw := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_bind: 127.0.0.1\n  api_port: 19132\n%s",
		filepath.ToSlash(home), body)
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous; gatewayStatusConfigProblem = nil })
	return configPath
}

// Check the same loader start uses, including a released v8 source. Log-tail
// parsing alone does not guarantee that start names an unsafe destination.
func TestGatewayStartPreflightNamesUnsafeJSONLDestination(t *testing.T) {
	for _, schema := range []string{"8", "9"} {
		t.Run(schema, func(t *testing.T) {
			path := t.TempDir()
			configPath := writeGatewayMessageConfig(t, fmt.Sprintf("observability:\n  destinations:\n    - name: unsafe-copy\n      kind: jsonl\n      path: %q\n", path))
			raw, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.Replace(string(raw), "config_version: 8", "config_version: "+schema, 1))
			if err := os.WriteFile(configPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, loadErr := loadDaemonConfig(startCmd)
			if loadErr == nil {
				t.Fatal("start accepted an unsafe JSONL destination")
			}
			message := daemonConfigLoadError("start", loadErr).Error()
			for _, want := range []string{`destination "unsafe-copy"`, path, "is a directory", "point it at a file"} {
				if !strings.Contains(message, want) {
					t.Errorf("start refusal omits %q: %s", want, message)
				}
			}
		})
	}
}

// GAP-1900: gateway status names a missing destination key with one remedy.
func TestGatewayStatusMissingDestinationKeyGivesOneRemedy(t *testing.T) {
	const secretEnv = "DC_TEST_STATUS_ONE_REMEDY_KEY"
	t.Setenv(secretEnv, "")
	configPath := writeGatewayMessageConfig(t, fmt.Sprintf(`observability:
  destinations:
    - name: galileo
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        Galileo-API-Key: {env: %s}
`, secretEnv))
	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with a missing destination secret loaded")
	}
	msg := gatewayStatusConfigLoadError(loadErr).Error()
	if n := strings.Count(strings.ToLower(msg), "set it with"); n != 1 {
		t.Errorf("status error gives the remedy %d times: %q", n, msg)
	}
	for _, want := range []string{
		`observability destination "galileo" needs ` + secretEnv + ", which is not set",
		"defenseclaw keys set " + secretEnv, `remove destination "galileo" from ` + configPath,
		"then run: defenseclaw-gateway start",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("status error %q does not contain %q", msg, want)
		}
	}
	if strings.Contains(msg, "config_semantic_invalid") {
		t.Errorf("status error shows the internal code: %q", msg)
	}
}

// GAP-2213: the unset ("") choice of a per-connector enum is not listed as
// a value to type.
func TestGatewayConfigLoadErrorLeavesOutTheUnsetEnumChoice(t *testing.T) {
	writeGatewayMessageConfig(t, "guardrail:\n  connectors:\n    codex:\n      hook_fail_mode: OPEN\n")
	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with an invalid connector hook_fail_mode loaded")
	}
	msg := gatewayStatusConfigLoadError(loadErr).Error()
	if !strings.Contains(msg, `guardrail.connectors.codex.hook_fail_mode is "OPEN"; allowed values: open, closed`) ||
		strings.Contains(msg, "allowed values: ,") {
		t.Fatalf("status error = %q", msg)
	}
}

// GAP-1914: restart and status name the bad enum value and the allowed
// values, as config validate does, not the raw schema diagnostic.
func TestGatewayConfigLoadErrorNamesTheBadEnumValue(t *testing.T) {
	configPath := writeGatewayMessageConfig(t, "guardrail:\n  mode: enforce-everything\n")
	loadErr := loadGatewayCommandConfigFor(statusCmd)
	if loadErr == nil {
		t.Fatal("config with an invalid guardrail.mode loaded")
	}
	for _, msg := range []string{
		daemonConfigLoadError("restart", loadErr).Error(),
		gatewayStatusConfigLoadError(loadErr).Error(),
	} {
		want := configPath + ` line 7: guardrail.mode is "enforce-everything"; allowed values: observe, action`
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
		for _, internal := range []string{"config_schema_invalid", "canonical v8 schema", "received string"} {
			if strings.Contains(msg, internal) {
				t.Errorf("error %q still shows %q", msg, internal)
			}
		}
	}
}

// GAP-1990: a value of the wrong type gets the same short form as a bad enum
// value, not the raw schema diagnostic.
func TestGatewayConfigLoadErrorNamesTheWrongValueType(t *testing.T) {
	for value, got := range map[string]string{"42": "a number", "[observe]": "a list"} {
		configPath := writeGatewayMessageConfig(t, "guardrail:\n  mode: "+value+"\n")
		loadErr := loadGatewayCommandConfigFor(statusCmd)
		if loadErr == nil {
			t.Fatalf("config with guardrail.mode: %s loaded", value)
		}
		for _, msg := range []string{
			daemonConfigLoadError("start", loadErr).Error(),
			gatewayStatusConfigLoadError(loadErr).Error(),
		} {
			want := configPath + " line 7: guardrail.mode: expected a value of type string (got " + got + ")"
			if !strings.Contains(msg, want) {
				t.Errorf("error %q does not contain %q", msg, want)
			}
			for _, internal := range []string{"config_schema_invalid", "canonical v8 schema", "received "} {
				if strings.Contains(msg, internal) {
					t.Errorf("error %q still shows %q", msg, internal)
				}
			}
		}
	}
}

// GAP-0825: a start or restart refused for a writable audit folder ends with the
// repair and the restart step, not with the generic gateway-log pointer, and a
// cause without a repair keeps that pointer.
func TestGatewayReadinessFailureEndsWithTheRepairStep(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	offset := gatewayLogSize(logPath)
	folder := "/home/u"
	repair := "audit: database directory " + folder + " is group- or other-writable; as the account that owns it, " +
		"run: chmod go-w \x27" + folder + "\x27, then run: defenseclaw-gateway restart"
	probe := fmt.Errorf("%w (last health probe: dial tcp: connection refused)", errGatewayExitedBeforeReadiness)
	for _, tc := range []struct {
		name, logged string
		wantRepair   bool
	}{
		{"repair", "Error: failed to open audit store: " + repair + "\n", true},
		{"long repair", "Error: failed to open audit store: " + strings.Repeat("x", 300) + " " + repair + "\n", true},
		{"locked database", "Error: failed to open audit store: audit: refresh baselines: database is locked (5)\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(logPath, []byte("[gateway] starting\n"+tc.logged), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, prefix := range []string{"start daemon readiness", "restart daemon readiness"} {
				cause := gatewayExitedBeforeReadinessError(probe, logPath, offset)
				msg := gatewayReadinessFailure(prefix, cause, logPath).Error()
				if tc.wantRepair {
					if !strings.HasSuffix(msg, "then run: defenseclaw-gateway restart") {
						t.Errorf("%q does not end with the restart step", msg)
					}
					if strings.Contains(msg, "for errors)") {
						t.Errorf("%q still carries the generic gateway-log pointer", msg)
					}
					if !strings.Contains(msg, "chmod go-w \x27"+folder+"\x27") {
						t.Errorf("%q lost the repair command", msg)
					}
				} else if !strings.HasSuffix(msg, "for errors)") || !strings.Contains(msg, logPath) {
					t.Errorf("%q lost the gateway-log pointer", msg)
				}
			}
		})
	}
}

// A valid audit folder with a long name makes the whole refusal longer than the
// 400 bytes other causes are cut to. The final error keeps the complete folder, the
// chmod go-w repair and the restart step, up to the longest path the system allows.
func TestGatewayReadinessFailureKeepsTheCompleteRepairForALongFolder(t *testing.T) {
	probe := fmt.Errorf("%w (last health probe: dial tcp: connection refused)", errGatewayExitedBeforeReadiness)
	long := "/home/u"
	for len(long) < 3000 {
		long += "/" + strings.Repeat("b", 200)
	}
	// Components made of apostrophes: the shell-quoted copy of the folder in the
	// repair command is about four times as long as the folder.
	quoted := "/home/u"
	for len(quoted) < 3300 {
		quoted += "/" + strings.Repeat("\x27", 200)
	}
	for _, folder := range []string{"/home/u/" + strings.Repeat("a", 180), long, quoted} {
		logPath := filepath.Join(t.TempDir(), "gateway.log")
		command := "\x27" + strings.ReplaceAll(folder, "\x27", "\x27\\\x27\x27") + "\x27"
		repair := "audit: database directory " + folder + " is group- or other-writable; as the account that owns it, " +
			"run: chmod go-w " + command + ", then run: defenseclaw-gateway restart"
		if err := os.WriteFile(logPath, []byte("Error: failed to open audit store: "+repair+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cause := gatewayExitedBeforeReadinessError(probe, logPath, 0)
		for _, prefix := range []string{"start daemon readiness", "restart daemon readiness"} {
			msg := gatewayReadinessFailure(prefix, cause, logPath).Error()
			if !strings.Contains(msg, "database directory "+folder+" is group- or other-writable") ||
				!strings.Contains(msg, "chmod go-w "+command) {
				t.Errorf("%d-byte folder: %s lost the folder or the chmod repair", len(folder), prefix)
			}
			if !strings.HasSuffix(msg, "then run: defenseclaw-gateway restart") {
				t.Errorf("%d-byte folder: %s lost its final step", len(folder), prefix)
			}
		}
	}
}
