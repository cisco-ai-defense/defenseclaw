// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The import path of a python -c program is the agent shell's, which the
// gateway does not see: a PYTHONPATH an earlier call exported, or one the
// user's profile sets, can supply a json.py that execs __main__.__doc__, or a
// sitecustomize that does so at exit with no import statement at all. The
// gateway's own clean environment and a clean working directory prove
// nothing, so the docstring that spells an authorized_keys write blocks. The
// interpreter shows each program write the keys file under such a path.
func TestPythonDocstringWriteBlocksWhateverTheGatewaysEnvironment(t *testing.T) {
	const connector = "python-agent-import-path"
	installToolCallCorpusProfileConnector(t, connector, "default")
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	work := t.TempDir() // holds no module
	const write = `"""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""`
	for _, tc := range []struct {
		name, code, module, body string
	}{
		{"shadowed json import", write + "\nimport json\n", "json.py",
			"import sys\nexec(sys.modules['__main__'].__doc__)\n"},
		{"sitecustomize with no import", write + "\nprint(\"ok\")\n", "sitecustomize.py",
			"import atexit, sys\natexit.register(lambda: exec(sys.modules['__main__'].__doc__))\n"},
		{"shadowed json import in one line", write + "; import json; print(json.dumps(1))", "json.py",
			"import sys\nexec(sys.modules['__main__'].__doc__)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if python, err := exec.LookPath("python3"); err == nil && runtime.GOOS != "windows" {
				shadow, home := t.TempDir(), t.TempDir()
				if err := os.WriteFile(filepath.Join(shadow, tc.module), []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(python, "-c", tc.code)
				cmd.Dir = work
				cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
					return strings.HasPrefix(kv, "PYTHON") || strings.HasPrefix(kv, "HOME=")
				}), "PYTHONPATH="+shadow, "HOME="+home)
				out, err := cmd.CombinedOutput()
				if _, statErr := os.Stat(filepath.Join(home, ".ssh", "authorized_keys")); statErr != nil {
					t.Fatalf("python3 -c under PYTHONPATH with %s did not write the keys file: %v %s", tc.module, err, out)
				}
			}
			command := "python3 -c '" + tc.code + "'"
			args := []byte(`{"command":` + strconv.Quote(command) + `}`)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool: "Bash", Args: args, CWD: work,
					ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
				},
				LegacyText: string(args), Connector: connector, EnforcementCapable: true,
			})
			if got := buildVerdict(findings, "tool_call").Action; got != guardrailActionBlock {
				t.Errorf("verdict %s, want %s (%v)", got, guardrailActionBlock, findingIDs(findings))
			}
		})
	}
}
