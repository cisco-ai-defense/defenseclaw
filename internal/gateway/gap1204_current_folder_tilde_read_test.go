// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestCurrentFolderTildeReadsGetTheVerdictOfCat (rel-1-0-10:GAP-1204): bash
// expands a ~+ head to the working folder ($PWD), so cat ~+/NAME with the
// cwd known reads the file cat NAME reads. A call of one statement was read
// with ~+/ as a literal relative folder, so cat ~+/.ssh/id_rsa in the home
// allowed where cat of the key blocks (PATH-SSH-KEY). Each shape is judged as
// cat of the full path is, in every pack, through the real Claude Code hook
// handler. The files exist in a scratch home; a plain file is the control.
func TestCurrentFolderTildeReadsGetTheVerdictOfCat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows: the fixture folder is a C:\\ path, which bash reads with its backslashes removed, so the cat oracle names another file than $PWD or ~+ (rel-1-0-10:GAP-1249); the Windows working folder is GAP-1535")
	}
	installCorrelationHMACForTest(t)
	policiesRoot := guardrailPoliciesRoot(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{".aws/credentials", ".ssh/id_rsa", ".kube/config", "proj/.env", "proj/notes.txt"} {
		full := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := []struct{ dir, name string }{
		{home, ".aws/credentials"},
		{home, ".ssh/id_rsa"},
		{home, ".kube/config"},
		{home + "/.ssh", "id_rsa"},
		{home + "/proj", ".env"},
		{home + "/proj", "notes.txt"},
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		installDefaultProfileConnector(t, "claudecode")
		store, logger := testStoreAndV8Logger(t)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = policiesRoot + "/" + pack
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
		handler := http.HandlerFunc(api.handleAgentHook("claudecode"))
		n := 0
		verdict := func(cwd, command string) (string, []string) {
			n++
			ev := claudeToolEvent("PreToolUse", "gap1204-"+pack, fmt.Sprintf("call-%d", n), command)
			ev["cwd"] = cwd
			got := callAgentHookForTest(t, handler, ev)
			rules := append([]string(nil), got.RuleIDs...)
			slices.Sort(rules)
			return got.Action, rules
		}
		for _, f := range files {
			full := f.dir + "/" + f.name
			oracleAction, oracleRules := verdict(f.dir, "cat "+full)
			for _, shape := range []string{
				`cat ~+/` + f.name,
				`cat ~+/"` + f.name + `"`,
				`cat ~+/./` + f.name,
				`cd ` + f.dir + ` && cat ~+/` + f.name,
			} {
				action, rules := verdict(f.dir, shape)
				if action != oracleAction || !slices.Equal(rules, oracleRules) {
					t.Errorf("%s: %q (cwd %s) is %s %v, cat %s is %s %v", pack, shape, f.dir, action, rules, full, oracleAction, oracleRules)
				}
			}
		}
	}
}
