// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// overLimitDockerHTTPRegistry is a Docker daemon configuration the docker
// insecure HTTP registry rule blocks (exact_admin_security_rules_test.go).
const overLimitDockerHTTPRegistry = `{"insecure-registries":["http://mirror.local"]}`

// TestOverLimitWriteKeepsItsContentRule pins GAP-0687: a native write whose
// text is padded past the 64 KiB string limit keeps the verdict of its
// content rule. White space padding is read through (bounded text); text
// that cannot be bounded takes the rule's conservative finding, for the
// content-rule targets only. Large benign writes stay allowed.
func TestOverLimitWriteKeepsItsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	daemon := "/etc/docker/daemon.json"
	pad70, pad300 := strings.Repeat(" ", 70000), strings.Repeat(" ", 300000)
	opaque := "\n" + strings.Repeat("x", 70000)
	for _, c := range []struct {
		name, connector, tool, pathKey, target, content string
		block                                           bool
		conservative                                    bool
	}{
		{"small", "claudecode", "Write", "file_path", daemon, overLimitDockerHTTPRegistry, true, false},
		{"70k spaces", "claudecode", "Write", "file_path", daemon, overLimitDockerHTTPRegistry + pad70, true, false},
		{"300k spaces", "claudecode", "Write", "file_path", daemon, overLimitDockerHTTPRegistry + pad300, true, false},
		{"leading spaces", "claudecode", "Write", "file_path", daemon, pad70 + overLimitDockerHTTPRegistry, true, false},
		{"inner spaces", "claudecode", "Write", "file_path", daemon, "{" + pad70 + overLimitDockerHTTPRegistry[1:], true, false},
		{"unbounded text", "claudecode", "Write", "file_path", daemon, overLimitDockerHTTPRegistry + opaque, true, true},
		{"hermes write_file 70k spaces", "hermes", "write_file", "path", daemon, overLimitDockerHTTPRegistry + pad70, true, false},
		// Hard negatives: benign content, an ordinary file, a large write.
		{"benign 70k spaces", "claudecode", "Write", "file_path", daemon, `{"log-level":"warn"}` + pad70, false, false},
		{"project daemon.json 70k", "claudecode", "Write", "file_path", "{PROJ}/daemon.json", overLimitDockerHTTPRegistry + pad70, false, false},
		{"project large file", "claudecode", "Write", "file_path", "{PROJ}/big.txt", overLimitWriteText + opaque, false, false},
		{"hermes project large file", "hermes", "write_file", "path", "{PROJ}/big.txt", overLimitWriteText, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			target := strings.ReplaceAll(c.target, "{PROJ}", project)
			args := map[string]any{c.pathKey: target, "content": c.content}
			var got string
			if c.connector == "hermes" {
				got = hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, c.tool, args))
			} else {
				call := nativeWriteCall{c.connector, c.tool, func(string) map[string]any { return args }}
				got = overLimitHostHook(t, c.connector, home, call.body(t, project, target))
			}
			action := overLimitHookAction(t, got)
			if (action == "block") != c.block {
				t.Fatalf("action = %q, want block %t: %.600s", action, c.block, got)
			}
			if c.block && !strings.Contains(got, dockerInsecureHTTPRegistryRuleID) {
				t.Fatalf("block does not name %s: %.600s", dockerInsecureHTTPRegistryRuleID, got)
			}
			if strings.Contains(got, overLimitElidedContentTitle) != c.conservative {
				t.Fatalf("conservative finding = %t, want %t: %.600s", !c.conservative, c.conservative, got)
			}
		})
	}
}

// TestOverLimitCodexPatchKeepsItsVerdict pins the same for Codex, whose
// native write is apply_patch: a patch padded past the limit keeps the
// verdict of the same patch at normal size.
func TestOverLimitCodexPatchKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	patch := func(body string) map[string]any {
		return map[string]any{"command": "*** Begin Patch\n*** Add File: /etc/docker/daemon.json\n+" + body + "\n*** End Patch\n"}
	}
	verdict := func(body string) string {
		call := nativeWriteCall{"codex", "apply_patch", func(string) map[string]any { return patch(body) }}
		return overLimitHookAction(t, overLimitHostHook(t, "codex", home, call.body(t, project, "/etc/docker/daemon.json")))
	}
	small := verdict(overLimitDockerHTTPRegistry)
	if padded := verdict(overLimitDockerHTTPRegistry + strings.Repeat(" ", 70000)); padded != small {
		t.Fatalf("padded verdict %q, small %q", padded, small)
	}
}

// TestOverLimitWriteContentRulePosture pins that the over-limit verdict
// keeps the rule's posture per profile: it blocks where the rule blocks and
// alerts where the rule alerts (balanced defaults), for bounded and
// unbounded text alike.
func TestOverLimitWriteContentRulePosture(t *testing.T) {
	for name, content := range map[string]string{
		"bounded":   overLimitDockerHTTPRegistry + strings.Repeat(" ", 70000),
		"unbounded": overLimitDockerHTTPRegistry + "\n" + strings.Repeat("x", 70000),
	} {
		raw, err := json.Marshal(map[string]any{"file_path": "/etc/docker/daemon.json", "content": content})
		if err != nil {
			t.Fatal(err)
		}
		for profile, want := range map[string]string{"default": "block", "permissive": "alert", "strict": "block"} {
			t.Run(name+"/"+profile, func(t *testing.T) {
				connector := "over-limit-content-" + profile + "-" + name
				installToolCallCorpusProfileConnector(t, connector, profile)
				input := exactStructuredInput(t, "Write", nil)
				input.Args = raw
				result := EvaluateDeterministicAction(t.Context(), input, string(raw), connector, profile)
				if !slices.Contains(result.RuleIDs, dockerInsecureHTTPRegistryRuleID) || result.Action != want {
					t.Fatalf("result=%+v, want %s action %s", result, dockerInsecureHTTPRegistryRuleID, want)
				}
			})
		}
	}
}
