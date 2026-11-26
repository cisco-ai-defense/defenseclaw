// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP2267EvalBodyDotglobBlocksFiveTiers pins rel-1-0-10:GAP-2267: a
// shopt -s dotglob or setopt globdots inside an eval body applies to that
// body's own globs. The gateway judges each statement of the eval body on its
// own, and rm -rf * does not spell the option its body turned on: the laptop
// alerted [CMD-EVAL] on eval 'cd ~; shopt -s dotglob; rm -rf *' while
// cd ~; eval 'shopt -s dotglob'; rm -rf * blocked, and after FOLD-3 (guest =
// laptop) the sandbox guest gave back rel's block on every actor shape
// (CHK-BAR410 TST-17379). Every statement is now read with the dotglob its
// whole call may turn on: laptop and guest block, on all six actor shapes and
// five tiers. The benign twins (a listing, a project build folder) keep
// their answer: no persistence block. The double-quoted and nested-shell
// spellings are never weaker than rel (alert or block).
func TestGAP2267EvalBodyDotglobBlocksFiveTiers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	q := "\x27"
	seed := "cd ~; shopt -s dotglob; rm -rf *"
	block := []string{
		"eval " + q + seed + q,
		"cd ~; eval " + q + "shopt -s dotglob; rm -rf *" + q,
		"eval " + q + "cd ~; setopt globdots; rm -rf *" + q,
		"eval " + q + "cd ~; setopt GLOB_DOTS; rm -rf *" + q,
		"echo $(eval " + q + seed + q + ")",
		"echo `eval " + q + seed + q + "`",
		"cd ~; eval " + q + "shopt -s dotglob" + q + "; rm -rf *",
	}
	// rel alerts [CMD-EVAL] on these on the laptop and in the guest: the
	// statements of a double-quoted body with a * are not split out.
	notWeaker := []string{
		"eval \"" + seed + "\"",
		"eval " + q + "bash -c \"" + seed + "\"" + q,
		"bash -c \"eval " + q + seed + q + "\"",
		"eval " + q + "eval \"" + seed + "\"" + q,
	}
	benignHome := []string{"eval " + q + "cd ~; shopt -s dotglob; ls *" + q}
	benignProject := []string{"eval " + q + "shopt -s dotglob; rm -rf ./build/*" + q}
	for _, p := range gap0437Packs {
		for _, s := range gap0545Shapes() {
			t.Run(p.name+"/"+s.name, func(t *testing.T) {
				api, actor, home, _ := gap0545API(t, s.connector, p.pack)
				if p.managed {
					cfg := api.scannerCfg
					cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
					cfg.Enterprise.Profile = managed.ProfileStandalone
					// A managed gateway refuses a hook it cannot audit.
					store, logger := testStoreAndLogger(t)
					api = NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
					prev := liveGeneration.Load()
					liveGeneration.Store(&Generation{Config: api.scannerCfg})
					t.Cleanup(func() { liveGeneration.Store(prev) })
				}
				gap0922Layout(t, home)
				project := filepath.Join(home, "project")
				if err := os.MkdirAll(filepath.Join(project, "build"), 0o700); err != nil {
					t.Fatal(err)
				}
				verdicts := func(command, laptopCWD, guestCWD string) (int, []string, int, []string) {
					body := func(cwd string) []byte { b, _ := json.Marshal(s.body(command, cwd)); return b }
					la, lr := gap0545Verdict(t, api, context.Background(), s, body(laptopCWD))
					ca, cr := gap0545Verdict(t, api, actor, s, body(guestCWD))
					return gap0545Rank(la, lr), lr, gap0545Rank(ca, cr), cr
				}
				guestProject := filepath.Join(sandboxauth.SandboxHome, "project")
				for _, command := range block {
					lr, lrules, cr, crules := verdicts(command, filepath.Join(home, "src"), sandboxauth.SandboxHome)
					if lr != 3 || cr != 3 {
						t.Errorf("%q: laptop rank %d %v, guest rank %d %v; want block", command, lr, lrules, cr, crules)
					}
				}
				for _, command := range notWeaker {
					lr, lrules, cr, crules := verdicts(command, filepath.Join(home, "src"), sandboxauth.SandboxHome)
					if lr < 2 || cr < 2 {
						t.Errorf("%q: laptop rank %d %v, guest rank %d %v; want alert or block", command, lr, lrules, cr, crules)
					}
				}
				for _, command := range benignHome {
					lr, lrules, cr, crules := verdicts(command, filepath.Join(home, "src"), sandboxauth.SandboxHome)
					if slices.Contains(lrules, "persistence.ssh_authorized_keys_command") ||
						slices.Contains(crules, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q: laptop rank %d %v, guest rank %d %v; want no persistence block", command, lr, lrules, cr, crules)
					}
				}
				for _, command := range benignProject {
					lr, lrules, cr, crules := verdicts(command, project, guestProject)
					if slices.Contains(lrules, "persistence.ssh_authorized_keys_command") ||
						slices.Contains(crules, "persistence.ssh_authorized_keys_command") {
						t.Errorf("%q: laptop rank %d %v, guest rank %d %v; want no persistence block", command, lr, lrules, cr, crules)
					}
				}
			})
		}
	}
}
