// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// A path through the command's own working-directory link names the file
// below the folder the command runs in. Whatever program reads it, in any
// position, the call gets the answer of the same call spelled with the plain
// path: no weaker for a write, and no stronger for a read or an ordinary file
// (rel-1-0-10:GAP-2265).
func TestGAP2265ProcessCWDLinkMatchesPlainPath(t *testing.T) {
	templates := []string{
		// writers whose option grammar the per-program readers did not know
		"install -vt {D} /tmp/authorized_keys", "install -Dt {D} /tmp/authorized_keys",
		"install /tmp/k {F} -m 600", "install /tmp/k {F} -o root", "install /tmp/k {F} -S .bak",
		"install --target-dir={D} /tmp/authorized_keys",
		"rsync /tmp/k {F} -e ssh", "rsync /tmp/k {F} --exclude x",
		"mv --exchange /tmp/k {F}", "mv --forc /tmp/k {F}",
		// writers with no per-program reader
		"ln -t {D} /tmp/authorized_keys", "link /tmp/k {F}", "scp /tmp/k {F}", "ditto /tmp/k {F}",
		"curl -o {F} https://example.invalid/k", "wget -O {F} https://example.invalid/k",
		"sort -o {F} /tmp/k", "sort /tmp/k -o {F}", "patch -o {F} /tmp/a /tmp/p", "split -b 1k /tmp/k {F}",
		"tar -C {D} -xf /tmp/x.tar", "tar -xf /tmp/x.tar -C {D}", "xxd -r /tmp/k {F}", "touch {F}",
		"sudo install -vt {D} /tmp/authorized_keys", "sh -c \"install -vt {D} /tmp/authorized_keys\"",
		"future-writer --dest={F} /tmp/k",
	}
	// Readers keep the answer of the plain read and ordinary files the answer
	// of their plain spelling: the link adds no write.
	same := []string{
		"grep k {F}", "head {F}", "wc -l {F}", "ssh-keygen -lf {F}", "diff {F} /tmp/k",
		"install -vt {O} a.txt", "curl -o {O}/a.txt https://example.invalid/a", "sort -o {N} a.txt",
		"tar -C {O} -xf a.tar", "grep x {N}", "python3 {T}", "future-writer --dest={N} a.txt",
	}
	spell := func(template, base string) string {
		return strings.NewReplacer("{D}", base+"/.ssh", "{F}", base+"/.ssh/authorized_keys",
			"{O}", base+"/out", "{N}", base+"/notes.txt", "{T}", base+"/tool.py").Replace(template)
	}
	links := []string{"/proc/self/cwd/..", "/proc/thread-self/cwd/.."}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, "claudecode", pack)
			hook := func(ctx context.Context, cwd, command string) string {
				body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap2265",
					"cwd": cwd, "tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": "gap2265"})
				if ctx == nil {
					ctx = gap0545Actor(actor, "claudecode", "PreToolUse", body, nil)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(string(body)))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(rec, req.WithContext(ctx))
				var out struct {
					Action string `json:"action"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &out)
				return out.Action
			}
			rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
			// Rows are reported by id (w<n> writers, s<n> same-answer rows,
			// L<n> link), never by command text.
			check := func(id, got, plain string, exact bool) {
				if rank[got] < rank[plain] || exact && got != plain {
					t.Errorf("%s: %s, plain spelling %s", id, got, plain)
				}
			}
			for _, rows := range []struct {
				prefix    string
				templates []string
				exact     bool
			}{{"w", templates, false}, {"s", same, true}} {
				for n, template := range rows.templates {
					// The sandbox actor works in /sandbox/app; its home is /sandbox.
					plain := hook(nil, sandboxauth.SandboxHome+"/app", spell(template, sandboxauth.SandboxHome))
					for l, link := range links {
						id := fmt.Sprintf("actor %s%02d L%d", rows.prefix, n, l)
						check(id, hook(nil, sandboxauth.SandboxHome+"/app", spell(template, link)), plain, rows.exact)
					}
					if rows.exact {
						continue
					}
					// A Linux laptop call works in ~/app.
					plain = hook(context.Background(), app, spell(template, home))
					id := fmt.Sprintf("laptop %s%02d L0", rows.prefix, n)
					check(id, hook(context.Background(), app, spell(template, links[0])), plain, false)
				}
			}
		})
	}
}
