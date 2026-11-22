// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import "testing"

// GAP-0633: an interpreter with a version after its name is a runner. An
// installed php8.2 given a script of the folder runs the folder's code,
// as php does; d4da3087f8 refused it, 8f2e0c63cf (installed program,
// project as data) let it through.
func TestGAP0633VersionedRunnerIsARunner(t *testing.T) {
	for _, cmd := range []string{"/usr/bin/php8.2", "/usr/bin/ruby3.2", "/usr/bin/lua5.4", "/usr/local/bin/node22",
		"/usr/bin/perl5.36", "/usr/bin/python3.12", "/usr/bin/php"} {
		if d := repoServerDecision(t, cmd, []string{"/work/repo/tools/srv.src"}, nil); !d.Unavailable {
			t.Errorf("%s with a folder script: %+v, want unscanned (the fail mode decides)", cmd, d)
		}
	}
	known := map[string]struct {
		cmd   string
		args  []string
		files []AttachedFile
	}{
		"php8.2 given an installed script": {"/usr/bin/php8.2", []string{"/usr/local/lib/mcp/srv.php"}, nil},
		"python3.12 -m, module not in the folder": {"/usr/bin/python3.12", []string{"-m", "mcp_server_time"},
			[]AttachedFile{{Role: RoleMCPModuleAbsent, Path: "mcp_server_time"}}},
		"a program with digits, not a runner": {"/usr/local/bin/sqlite3", []string{"/work/repo/data.db"}, nil},
		"a server name ending in a version":   {"/usr/local/bin/mcp-server-git2", []string{"--repository", "/work/repo"}, nil},
	}
	for name, r := range known {
		if d := repoServerDecision(t, r.cmd, r.args, nil, r.files...); d.Unavailable {
			t.Errorf("%s: %+v, want decided by the config rules", name, d)
		}
	}
}
