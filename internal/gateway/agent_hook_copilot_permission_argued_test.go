// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2012: a create or edit preToolUse whose own callback (it always
// carries {file_path, diff}) never arrives must not leave the next ordinary
// apply_patch pair ambiguous: the patch's argumentless edit callback is bound
// and allowed, in observe and action, never HOOK-TOOL-CALL-UNPARSED. A
// protected patch after such a call is still blocked in action.
func TestCopilotArguedCallbackCallsLeaveTheNextPatchPairBound(t *testing.T) {
	for _, mode := range []string{"observe", "action"} {
		for _, shape := range []string{"create-nocb", "edit-nocb", "create-cb"} {
			t.Run(mode+"/"+shape, func(t *testing.T) {
				project := t.TempDir()
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = "copilot"
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
				session := "gap2012-" + mode + "-" + shape
				head := `{"sessionId":"` + session + `","cwd":` + jsonQuote(project) + `,`
				perm := func(input string) string {
					return `{"hookName":"permissionRequest","sessionId":"` + session + `","cwd":` + jsonQuote(project) + `,"toolName":"edit","toolInput":` + input + `}`
				}
				cpath := filepath.Join(project, "c.txt")
				epath := filepath.Join(project, "e.txt")
				if err := os.WriteFile(epath, []byte("old\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				first := `{"id":"c1","name":"create","args":{"path":` + jsonQuote(cpath) + `,"file_text":"ordinary c\n"}}`
				if shape == "edit-nocb" {
					first = `{"id":"e1","name":"edit","args":{"path":` + jsonQuote(epath) + `,"old_str":"old","new_str":"new"}}`
				}
				check := func(step string, a copilotEnvelopeAnswer, body string) {
					t.Helper()
					if a.Action != "allow" || strings.Contains(body, hookToolCallUnparsedRuleID) {
						t.Fatalf("%s: %s", step, body)
					}
				}
				a, body := postCopilotHook(t, api, "preToolUse", head+`"toolCalls":[`+first+`]}`)
				check("first preToolUse", a, body)
				if shape == "create-cb" {
					g := filepath.ToSlash(cpath)
					d := "\ndiff --git a" + g + " b" + g + "\ncreate file mode 100644\nindex 0000000..0000000\n--- a/dev/null\n+++ b" + g + "\n@@ -1,0 +1,1 @@\n+ordinary c\n\n"
					a, body = postCopilotHook(t, api, "permissionRequest", perm(`{"file_path":`+jsonQuote(cpath)+`,"diff":`+jsonQuote(d)+`}`))
					check("create callback", a, body)
				}
				patch := jsonQuote("*** Begin Patch\n*** Add File: a.txt\n+ordinary a\n*** End Patch\n")
				a, body = postCopilotHook(t, api, "preToolUse", head+`"toolCalls":[{"id":"p1","name":"apply_patch","args":`+patch+`}]}`)
				check("patch preToolUse", a, body)
				a, body = postCopilotHook(t, api, "permissionRequest", perm(`{}`))
				check("argumentless patch callback", a, body)
				if mode == "action" {
					home, err := os.UserHomeDir()
					if err != nil {
						t.Fatal(err)
					}
					keys := jsonQuote("*** Begin Patch\n*** Add File: " + filepath.Join(home, ".ssh", "authorized_keys") + "\n+ssh-ed25519 example\n*** End Patch\n")
					postCopilotHook(t, api, "preToolUse", head+`"toolCalls":[`+first+`]}`)
					if a, body = postCopilotHook(t, api, "preToolUse", head+`"toolCalls":[{"id":"p9","name":"apply_patch","args":`+keys+`}]}`); a.Action != "block" {
						t.Fatalf("protected patch after %s: %s", shape, body)
					}
					if a, body = postCopilotHook(t, api, "permissionRequest", perm(`{}`)); a.Action != "block" {
						t.Fatalf("argumentless callback after the protected patch: %s", body)
					}
				}
			})
		}
	}
}
