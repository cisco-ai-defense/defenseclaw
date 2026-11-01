// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r106HookRow is one hook command and its action-mode verdict; perUserOnly
// rows are judged only on a per-user gateway (a managed gateway reads them
// from the client map, outside the row under test).
type r106HookRow struct {
	command     string
	block       bool
	perUserOnly bool
}

// r106HookVerdict posts payload in action mode: managed is the hook peer
// behind ProtectHome (home hidden from the gateway), otherwise a per-user
// gateway, with the real client header when header is set.
func r106HookVerdict(t *testing.T, f b36ManagedHookFixture, managed bool, connector string, payload []byte, header string) string {
	t.Helper()
	if managed {
		return f.post(t, connector, payload, header)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block"
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow"
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body)
}

// judgeR106HookRows runs rows on a fresh project per row, managed and
// per-user (with and without the client header), for Claude Code and Codex.
// prepare adds the row's own files; HOMEDIR in a row is the user's home
// and EXTDIR a directory outside it that the gateway can see.
func judgeR106HookRows(t *testing.T, rows []r106HookRow, prepare func(t *testing.T, f b36ManagedHookFixture)) {
	t.Helper()
	for _, mode := range []struct {
		managed, header bool
	}{{true, true}, {false, true}, {false, false}} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, row := range rows {
				if mode.managed && row.perUserOnly {
					continue
				}
				f := newB36ManagedHookFixture(t)
				prepare(t, f)
				command := strings.NewReplacer("HOMEDIR", f.home, "EXTDIR", filepath.Join(filepath.Dir(f.homes), "ext")).Replace(row.command)
				payload := f.payload(t, command)
				header := ""
				if mode.header {
					header = f.clientHeader(t, payload)
				}
				want := "allow"
				if row.block {
					want = "block"
				}
				if got := r106HookVerdict(t, f, mode.managed, connector, payload, header); got != want {
					t.Errorf("managed=%v header=%v %s %q: %s, want %s", mode.managed, mode.header, connector, row.command, got, want)
				}
				_ = os.Chmod(f.homes, 0o700)
			}
		}
	}
}

// A plain mv onto an existing user link to authorized_keys replaces the link
// and writes neither file, also behind a cd: the directory walk listed the
// move destination after a cd and followed the link, and a ~/ operand in a
// cd list left the move unread on a managed gateway, so cd DIR && mv a lnk
// blocked as a key write (GAP-2559, cell L-ubu-J5-003). A write through the
// link, a move onto the keys name itself or through a linked .ssh directory
// still blocks.
func TestR106MoveOntoKeysLinkAfterCDReplacesTheLink(t *testing.T) {
	judgeR106HookRows(t, []r106HookRow{
		{command: `mv n1.txt lnk`},
		{command: `mv HOMEDIR/project/n1.txt HOMEDIR/project/lnk`},
		{command: `cd ~/ext && mv ~/project/n1.txt HOMEDIR/project/lnk`},
		{command: `cd HOMEDIR/project && mv n1.txt lnk`},
		{command: `cd HOMEDIR/ext && mv HOMEDIR/project/n1.txt HOMEDIR/project/lnk`},
		{command: `cd ~/project && mv -f n1.txt ./lnk`},
		{command: `cd ~/ext && mv ~/project/n1.txt ~/project/lnk`},
		{command: `cd .. && mv project/n1.txt project/lnk`},
		{command: `cd ~/project; mv n1.txt lnk`},
		{command: `cd HOMEDIR/project && mv n1.txt plain.txt`},
		{command: `cat n1.txt > lnk`, block: true},
		{command: `mv n1.txt ~/.ssh/authorized_keys`, block: true},
		{command: `cd HOMEDIR/project && cat n1.txt > lnk`, block: true},
		{command: `cd HOMEDIR/project && cp n1.txt lnk`, block: true},
		{command: `cd HOMEDIR/project && tee lnk < n1.txt`, block: true},
		{command: `cd HOMEDIR/project && mv n1.txt s/authorized_keys`, block: true},
		{command: `cd ~/project && mv n1.txt ./s/authorized_keys`, block: true},
		{command: `cd ~/ext && mv ~/project/n1.txt HOMEDIR/project/s/authorized_keys`, block: true},
		{command: `cd ~/.ssh && mv HOMEDIR/project/n1.txt authorized_keys`, block: true},
		{command: `cd HOMEDIR/project && mv n1.txt lnk; echo x >> lnk`, block: true},
		{command: `cd ~/ext && cat ~/x >> ~/project/lnk && mv ~/project/n1.txt HOMEDIR/project/lnk`, block: true},
		// A link outside the home that the gateway can see, to the keys
		// file a managed gateway cannot read.
		{command: `cd EXTDIR && mv ~/project/n1.txt c`},
		{command: `cd EXTDIR && mv -f ~/project/n1.txt ./c`},
		{command: `cd EXTDIR && cat ~/project/n1.txt > c`, block: true},
		{command: `cd EXTDIR && cp ~/project/n1.txt c`, block: true},
		// Pre-existing managed limit (moving an existing disk link, then a
		// write through the new name), judged per-user only here.
		{command: `cd HOMEDIR/project && mv lnk lnk2; echo x >> lnk2`, block: true, perUserOnly: true},
	}, func(t *testing.T, f b36ManagedHookFixture) {
		for _, dir := range []string{filepath.Join(f.home, "ext"), filepath.Join(f.home, ".defenseclaw")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(f.project, "n1.txt"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for link, target := range map[string]string{"lnk": f.keys, "s": filepath.Dir(f.keys)} {
			if err := os.Symlink(target, filepath.Join(f.project, link)); err != nil {
				t.Fatal(err)
			}
		}
		ext := filepath.Join(filepath.Dir(f.homes), "ext")
		if err := os.MkdirAll(ext, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(f.keys, filepath.Join(ext, "c")); err != nil {
			t.Fatal(err)
		}
	})
}
