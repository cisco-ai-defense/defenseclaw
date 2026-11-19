// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestRunTimeHomeInAFolderOfTheHomeReadsItsAccountFiles (rel-1-0-10:
// GAP-1022): HOME set at run time to a folder of the home (cd ~/.aws &&
// HOME=$(pwd), HOME=$(cd ~/.aws; pwd), HOME=$(echo ~/.aws),
// export HOME=$(pwd)/../.aws) and a read of the bare file name through it
// (cp ~/credentials) reads ~/.aws/credentials. The call was a clean allow in
// every pack: the run-time home is unproven, and a read through it counted
// only when it climbed out of the home or named a credentials-file path
// relative to the previous home. It is now judged, not allowed. A scratch
// home and a project home that read no account file stay allowed, through
// the real Claude Code hook handler.
func TestRunTimeHomeInAFolderOfTheHomeReadsItsAccountFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows: the run-time home guess reads a POSIX working folder; a C:\\ folder keeps the rel reading (rel-1-0-10:GAP-1249, Windows is GAP-1535)")
	}
	installCorrelationHMACForTest(t)
	policiesRoot := guardrailPoliciesRoot(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{".aws/credentials", ".kube/config", "proj/README.md", ".aws/notes.txt"} {
		full := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		cwd, command string
		judged       bool
	}
	var rows []row
	for _, f := range []struct{ dir, base string }{{".aws", "credentials"}, {".kube", "config"}} {
		rows = append(rows,
			row{home + "/proj", "cd ~/" + f.dir + " && HOME=$(pwd) && cp ~/" + f.base + " /tmp/n", true},
			row{home + "/proj", "HOME=$(cd ~/" + f.dir + "; pwd); cp ~/" + f.base + " /tmp/n", true},
			row{home + "/proj", "HOME=$(cd ~/" + f.dir + " && pwd); cat ~/" + f.base, true},
			row{home + "/proj", "HOME=$(echo ~/" + f.dir + "); cp ~/" + f.base + " /tmp/n", true},
			row{home + "/proj", "HOME=$(echo $HOME/" + f.dir + "); cat $HOME/" + f.base, true},
			row{home + "/proj", "export HOME=$(pwd)/../" + f.dir + "; cp ~/" + f.base + " /tmp/n", true},
			row{home + "/" + f.dir, `HOME="$(pwd)"; cat ~/` + f.base, true},
		)
	}
	rows = append(rows,
		row{home + "/proj", "HOME=$(mktemp -d); cat ~/README.md", false},
		row{home + "/proj", "HOME=$(pwd); cat ~/README.md", false},
		row{home + "/proj", "HOME=$(cd ~/.aws; pwd); cat ~/notes.txt", false},
	)
	for _, pack := range []string{"default", "permissive", "strict"} {
		installDefaultProfileConnector(t, "claudecode")
		store, logger := testStoreAndV8Logger(t)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		cfg.Guardrail.RulePackDir = policiesRoot + "/" + pack
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
		handler := http.HandlerFunc(api.handleAgentHook("claudecode"))
		for n, r := range rows {
			ev := claudeToolEvent("PreToolUse", "gap1022-"+pack, fmt.Sprintf("call-%d", n), r.command)
			ev["cwd"] = r.cwd
			got := callAgentHookForTest(t, handler, ev)
			judged := got.Action != "allow" || len(got.RuleIDs) != 0
			if judged != r.judged {
				t.Errorf("%s: %q (cwd %s) is %s %v, want judged=%v", pack, r.command, r.cwd, got.Action, got.RuleIDs, r.judged)
			}
		}
	}
}
