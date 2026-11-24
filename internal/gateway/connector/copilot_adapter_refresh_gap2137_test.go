// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2137: the closed catch block the template renders is
// copilotAdapterClosedFailure, which replaces a Copilot CLI prompt; a closed
// adapter of 1.0.0 to 1.0.11 (tools only) and an open one are both rewritten
// to it by the fail-mode refresh, once.
func TestGAP2137CopilotAdapterRefreshGivesTheClosedCatchThePrompt(t *testing.T) {
	if !strings.Contains(copilotAdapterClosedFailure, `$Event -ceq 'userPromptTransformed'`) ||
		!strings.Contains(copilotAdapterClosedFailure, `"modifiedTransformedPrompt":"DefenseClaw blocked the current user message.`) {
		t.Fatalf("closed catch %q does not answer the prompt", copilotAdapterClosedFailure)
	}
	if strings.Contains(copilotAdapterClosedFailure, copilotAdapterClosedFailureToolsOnly) {
		t.Fatal("the tools-only form is a substring of the current one: the refresh would not be idempotent")
	}
	tmpl, err := hookFS.ReadFile("hooks/copilot-hook.ps1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tmpl), copilotAdapterClosedFailure) || strings.Contains(string(tmpl), copilotAdapterClosedFailureToolsOnly+"\n") {
		t.Fatal("the template's closed catch block is not copilotAdapterClosedFailure")
	}
	for name, line := range map[string]string{"tools-only closed": copilotAdapterClosedFailureToolsOnly, "open": copilotAdapterOpenFailure} {
		for _, eol := range []string{"\n", "\r\n"} {
			path := filepath.Join(t.TempDir(), "copilot-hook.ps1")
			body := "catch {" + eol + "    " + line + eol + "}" + eol
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			changed, err := closeBakedHookFailMode(path, bakedAdapterFailModeOpens)
			if err != nil || !changed {
				t.Fatalf("%s: changed=%v err=%v", name, changed, err)
			}
			after, _ := os.ReadFile(path)
			if want := "catch {" + eol + "    " + copilotAdapterClosedFailure + eol + "}" + eol; string(after) != want {
				t.Fatalf("%s: refreshed to %q, want %q", name, after, want)
			}
			if changed, err := closeBakedHookFailMode(path, bakedAdapterFailModeOpens); err != nil || changed {
				t.Fatalf("%s: second refresh changed=%v err=%v, want no change", name, changed, err)
			}
		}
	}
}
