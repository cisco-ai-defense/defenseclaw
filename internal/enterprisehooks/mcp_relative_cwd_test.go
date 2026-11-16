// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0219: a project server with a relative cwd got no admission row. The
// record keeps it with its cwd as written, and the as-user start refuses it
// with the folder text, so admission blocks it as not scanned instead of
// leaving it out. A .mcp.json saved with a byte order mark is read too.
func TestRelativeCWDProjectServerIsPublishedAndRefusedAtStart(t *testing.T) {
	home := filepath.Join(t.TempDir(), "dcw-std1")
	project := filepath.Join(home, "r103-gb05-relcwd")
	state := []byte(`{"projects":{` + jsonString(project) + `:{}}}`)
	servers, err := config.ClaudeStateMCPServers(state, func(p string) ([]byte, error) {
		if p != project {
			return nil, os.ErrNotExist
		}
		return []byte("\xef\xbb\xbf" + `{"mcpServers":{"gb05-relcwd":{"command":"npx","args":["-y","."],"cwd":"server"}}}`), nil
	})
	if err != nil || len(servers) != 1 || servers[0].Name != "gb05-relcwd" || servers[0].CWD != "server" || servers[0].Project != project {
		t.Fatalf("servers %+v (err %v), want gb05-relcwd with cwd server in its project", servers, err)
	}
	const sid = "S-1-5-21-1-1001"
	data, err := MarshalClaudeMCPSpoolRecord(sid, servers)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, sid+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	published, unreadable, err := ReadClaudeMCPSpool(dir, sid, nil)
	if err != nil || unreadable != nil || len(published) != 1 || published[0].CWD != "server" || published[0].Project != project {
		t.Fatalf("published %+v unreadable %+v (err %v)", published, unreadable, err)
	}
	checks := claudeMCPWorkDirChecks{noLinks: func(string) error { return nil }, final: func(p string) (string, error) { return p, nil }}
	fs := mcpAsUserLauncherFS{exists: func(string) bool { return true }, trusted: func(string) error { return nil }}
	dirOut, launcher, err := planMCPAsUserLaunch(published[0], home, nil, mcpAsUserLauncher{name: "npx", file: "npx.cmd"},
		[]string{`PATH=C:\Program Files\nodejs`}, checks, fs)
	if err == nil || dirOut != "" || launcher != "" || !strings.Contains(err.Error(), `MCP server "gb05-relcwd" is not started in server`) {
		t.Fatalf("start plan dir %q launcher %q (%v), want the folder refusal", dirOut, launcher, err)
	}
}

func jsonString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
