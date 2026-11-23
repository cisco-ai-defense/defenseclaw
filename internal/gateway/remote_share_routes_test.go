// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// gap1074Spellings are the spellings Windows opens a share on another machine
// by; {H} is the server, a fresh one for every row.
var gap1074Spellings = []struct{ name, root string }{
	{"unc-back", `\\{H}\share`},
	{"unc-fwd", "//{H}/share"},
	{"unc-4slash", "////{H}/share"},
	{"qunc", `\\?\UNC\{H}\share`},
	{"dunc", `\\.\UNC\{H}\share`},
	{"ntunc", `\??\UNC\{H}\share`},
	{"global-unc", `\\?\Global\UNC\{H}\share`},
	{"globalroot-mup", `\\?\GLOBALROOT\Device\Mup\{H}\share`},
	{"webdav-ssl", `\\{H}@SSL\DavWWWRoot`},
	{"ipv4", `\\192.0.2.{N}\share`},
}

// gap1074Tails are an ordinary file and a protected-looking one below the share.
var gap1074Tails = []string{`team\notes.txt`, `Users\u\.ssh\authorized_keys`}

// gap1074Routes are the hook routes that name a path: Bash, the PowerShell
// tool, cmd through Bash, Write, Edit and an MCP file tool. {P} is the path.
var gap1074Routes = []struct {
	name, tool string
	input      func(path string) map[string]any
}{
	{"bash-cp", "Bash", func(p string) map[string]any { return map[string]any{"command": "cp notes.txt '" + p + "'"} }},
	{"bash-source", "Bash", func(p string) map[string]any { return map[string]any{"command": "source '" + p + "'"} }},
	{"powershell", "PowerShell", func(p string) map[string]any { return map[string]any{"command": "Copy-Item notes.txt '" + p + "'"} }},
	{"cmd", "Bash", func(p string) map[string]any { return map[string]any{"command": `cmd /c copy notes.txt "` + p + `"`} }},
	{"write", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "x"} }},
	{"edit", "Edit", func(p string) map[string]any {
		return map[string]any{"file_path": p, "old_string": "a", "new_string": "b"}
	}},
	{"mcp", "mcp__files__write_file", func(p string) map[string]any { return map[string]any{"path": p, "content": "x"} }},
}

func gap1074Rank(action any) int {
	switch action {
	case "block":
		return 2
	case "alert", "ask":
		return 1
	}
	return 0
}

// The gateway routes contact no share on another machine for a path a hook
// call names, in any spelling, on any route, in the five tiers
// (rel-1-0-10:GAP-1074): no share ask and no read that hands the system a
// path below such a share (the config guard's target walk read the write,
// edit and cp targets with os.Lstat and filepath.EvalSymlinks past the share
// gate, which opened an SMB session on native Windows), and the verdict is never weaker than the one the
// call gets when the share answers (as rel read an answering share): the
// remote path is judged by its text. Off Windows only for the comparison: on
// Windows an answering share is a real read of the network.
func TestGatewayRemoteShareOperandIsNeverAsked(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	ask := func(string) {
		mu.Lock()
		asked++
		mu.Unlock()
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return asked }
	compare := runtime.GOOS != "windows"
	rows, contacts, weaker := 0, 0, 0
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		a.inspectToolScanTimeout = time.Minute // this test counts share asks, not latency
		for _, s := range gap1074Spellings {
			for _, tail := range gap1074Tails {
				for _, route := range gap1074Routes {
					rows++
					host := fmt.Sprintf("g1074gw-%s%04d.example.test", os.Getenv("DC_G1074_HOST_TAG"), rows)
					path := strings.NewReplacer("{H}", host, "{N}", fmt.Sprint(rows%250+1)).Replace(s.root) + `\` + tail
					hook := func(id string) map[string]any {
						return gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
							"hook_event_name": "PreToolUse", "session_id": "g1074-" + id, "cwd": t.TempDir(),
							"tool_name": route.tool, "tool_use_id": "tu-g1074-" + id, "tool_input": route.input(path),
						})
					}
					restore := overrideRemoteSharesIdle(t, ask, nil)
					server := strings.ToLower(host)
					unobserve := observeRemoteShareReadsIdle(t, func(name string) {
						if strings.Contains(strings.ToLower(name), server) {
							ask(name)
						}
					})
					before := count()
					unread := hook(fmt.Sprintf("u%d", rows))
					unobserve()
					restore()
					if n := count() - before; n != 0 {
						contacts += n
						t.Errorf("%s %s %s: %d remote share contact(s)", p.name, route.name, s.name, n)
					}
					if !compare {
						continue
					}
					restore = overrideRemoteSharesIdle(t, func(string) {}, func(string) bool { return true })
					answered := hook(fmt.Sprintf("a%d", rows))
					restore()
					if gap1074Rank(unread["action"]) < gap1074Rank(answered["action"]) {
						weaker++
						t.Errorf("%s %s %s %s: unread %v, answered %v", p.name, route.name, s.name, tail, unread["action"], answered["action"])
					}
				}
			}
		}
	}
	t.Logf("GAP1074 gateway rows %d remote contacts %d weaker %d", rows, contacts, weaker)
}
