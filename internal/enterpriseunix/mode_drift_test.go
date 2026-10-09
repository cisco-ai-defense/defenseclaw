// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// writeFreshLedger publishes a current guardian authorization ledger, which
// strict verify requires.
func writeFreshLedger(t *testing.T, h *testHost) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
	h.publishLedger(data)
}

func messagesOf(messages []enterprisestatus.Message, code string) string {
	joined := ""
	for _, m := range messages {
		if m.Code == code {
			joined += m.Message + "\n"
		}
	}
	return joined
}

// A package manager that replaced the binaries while the package's own install
// run failed leaves the record at the previous version. verify names that
// state once instead of calling each binary modified after install
// (GAP-0111).
func TestVerifyNamesAPackageUpgradeThatDidNotFinishApplying(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeFreshLedger(t, h)
	requireOK(t, h.run(Options{Action: ActionVerify}))
	bin := h.env.P(h.env.Layout.BinDir)
	newer := h.payload("1.1.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(newer, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	r := h.run(Options{Action: ActionVerify})
	requireError(t, r, codeVerify)
	got := messagesOf(r.Errors, codeVerify)
	if !strings.Contains(got, "installed package is version 1.1.0 but the deployment applied 1.0.0") ||
		!strings.Contains(got, "--from-package") || strings.Contains(got, "was modified after install") {
		t.Fatalf("verify after a package replaced the binaries: %s", got)
	}
}

// Verify promises every file and permission, but compared only digests: a
// loosened config.yaml (0644) and an installed binary any account could
// replace (0757) went unreported, while repair fixed the first and refused
// the second without saying how to recover.
func TestVerifyReportsInstalledModeDriftAndRepairNamesTheRemedy(t *testing.T) {
	type host struct {
		goos    string
		channel string
		make    func(t *testing.T) (*testHost, Options)
	}
	for _, c := range []host{
		{"linux", ChannelPayload, func(t *testing.T) (*testHost, Options) {
			h := newTestHost(t, "linux")
			return h, Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}
		}},
		{"linux", ChannelPackage, func(t *testing.T) (*testHost, Options) {
			return packageHost(t, "1.0.0"), Options{Action: ActionInstall, FromPackage: true}
		}},
		{"darwin", ChannelPayload, func(t *testing.T) (*testHost, Options) {
			h := newTestHost(t, "darwin")
			return h, Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}
		}},
	} {
		t.Run(c.goos+"-"+c.channel, func(t *testing.T) {
			h, install := c.make(t)
			requireOK(t, h.run(install))
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			configPath := h.env.Layout.ConfigPath
			hook := filepath.Join(h.env.Layout.BinDir, binHook)

			if err := os.Chmod(h.env.P(configPath), 0o644); err != nil {
				t.Fatal(err)
			}
			loosened := h.run(Options{Action: ActionVerify})
			requireError(t, loosened, codeVerify)
			if got := messagesOf(loosened.Errors, codeVerify); !strings.Contains(got, configPath+" is 0644") || !strings.Contains(got, " repair`") {
				t.Fatalf("verify does not report the loosened config: %s", got)
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if mode := h.mode(configPath); mode != 0o640 {
				t.Fatalf("repair left config.yaml at %04o", mode)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))

			if err := os.Chmod(h.env.P(hook), 0o757); err != nil {
				t.Fatal(err)
			}
			writable := h.run(Options{Action: ActionVerify})
			requireError(t, writable, codeVerify)
			if got := messagesOf(writable.Errors, codeVerify); !strings.Contains(got, hook+" is writable by group or other (0757)") || !strings.Contains(got, "`chmod 0755 "+hook+"`") {
				t.Fatalf("verify does not report the replaceable binary: %s", got)
			}
			refused := h.run(Options{Action: ActionRepair})
			requireError(t, refused, codePayload)
			got := messagesOf(refused.Errors, codePayload)
			if !strings.Contains(got, "`chmod 0755 "+hook+"`") {
				t.Fatalf("the repair refusal names no remedy: %s", got)
			}
			if c.channel == ChannelPackage && !strings.Contains(got, "reinstall the DefenseClaw enterprise package") {
				t.Fatalf("the package-channel refusal does not offer a reinstall: %s", got)
			}
			if c.channel == ChannelPayload && !strings.Contains(got, "--payload") {
				t.Fatalf("the payload-channel refusal does not offer --payload: %s", got)
			}
			if err := os.Chmod(h.env.P(hook), 0o755); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}

// A hook binary replaced after the macOS package install (root copied
// /usr/bin/true over it) was recorded as the deployment by repair and by
// ensure --from-package, so verify turned green while agents ran without
// enforcement. Any run but the package's own install refuses it until the
// package is reinstalled (GAP-0522).
func TestRepairRefusesAPackageBinaryReplacedAfterInstall(t *testing.T) {
	h := newTestHost(t, "darwin")
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := h.payload("1.0.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	hook := filepath.Join(bin, binHook)
	if err := os.WriteFile(hook, []byte("replaced\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Options{{Action: ActionRepair}, {Action: ActionEnsure, FromPackage: true}} {
		r := h.run(opts)
		requireError(t, r, codePayload)
		if got := messagesOf(r.Errors, codePayload); !strings.Contains(got, "installer -pkg defenseclaw-enterprise-1.0.0-darwin-arm64.pkg") {
			t.Fatalf("%s refusal names no reinstall: %s", opts.Action, got)
		}
	}
	requireError(t, h.run(Options{Action: ActionVerify}), codeVerify)
	if err := h.env.copyFileAtomic(filepath.Join(staged, binHook), hook, 0o755, rootOwner()); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
}

// A support script ran chown -R root:wheel or chmod -R a+rX over the
// deployment. Repair, ensure and a package reinstall restored only the
// folders: the gateway could not open its audit store or refused its 0644
// key files, every retry rolled back, and a standard user could read
// runtime/device.key (GAP-0746, GAP-0747). status names the entries and
// repair gives each one back its owner and mode.
func TestRepairRestoresStateFilesAfterARecursiveChownOrChmod(t *testing.T) {
	for _, drift := range []string{"chown -R root:wheel", "chmod -R a+rX"} {
		t.Run(drift, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			account := h.accounts.accounts[h.env.Layout.ServiceUser]
			service, rootService := [2]int{account.UID, account.GID}, [2]int{0, account.GID}
			l := h.env.Layout
			hooks := filepath.Join(l.DataDir, "hooks")
			if err := os.Mkdir(h.env.P(hooks), 0o700); err != nil {
				t.Fatal(err)
			}
			h.owners[h.env.P(hooks)] = service
			type state struct {
				mode  os.FileMode
				owner [2]int
			}
			// What the gateway and the hook guardian write, as they write it.
			written := map[string]state{
				filepath.Join(l.DataDir, "audit.db"):                                  {0o600, service},
				filepath.Join(l.DataDir, "device.key"):                                {0o600, service},
				filepath.Join(hooks, ".hook-claudecode.token"):                        {0o600, service},
				filepath.Join(l.DataDir, guardianStateFile):                           {0o640, rootService},
				filepath.Join(filepath.Dir(l.ManifestPath), "eligible-accounts.json"): {0o600, [2]int{0, 0}},
			}
			for canonical, want := range written {
				if err := os.WriteFile(h.env.P(canonical), []byte("state\n"), want.mode); err != nil {
					t.Fatal(err)
				}
				h.owners[h.env.P(canonical)] = want.owner
			}
			requireOK(t, h.run(Options{Action: ActionStatus}))

			_ = filepath.WalkDir(h.env.P(l.InstallRoot), func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.Type()&fs.ModeSymlink != 0 {
					return err
				}
				if drift == "chown -R root:wheel" {
					h.owners[path] = [2]int{0, 0}
					return nil
				}
				info, _ := d.Info()
				add := os.FileMode(0o044)
				if d.IsDir() || info.Mode()&0o111 != 0 {
					add = 0o055
				}
				return os.Chmod(path, info.Mode().Perm()|add)
			})
			status := h.run(Options{Action: ActionStatus})
			requireError(t, status, codeVerify)
			if got := messagesOf(status.Errors, codeVerify); !strings.Contains(got, "under "+l.DataDir) || !strings.Contains(got, " repair`") {
				t.Fatalf("status does not name the state files and the fix: %s", got)
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			written[hooks] = state{0o700, service}
			for canonical, want := range written {
				uid, gid, _ := h.env.OwnerOf(h.env.P(canonical))
				if mode := h.mode(canonical); mode != want.mode || [2]int{uid, gid} != want.owner {
					t.Errorf("after repair %s is %04o %d:%d, want %04o %d:%d", canonical, mode, uid, gid, want.mode, want.owner[0], want.owner[1])
				}
			}
			requireOK(t, h.run(Options{Action: ActionStatus}))
		})
	}
}

// chmod -R a+rX over the deployment fired the apply trigger, and its
// transaction rolled back: the rollback put the loosened folder modes back
// from its snapshot, so runtime stayed 0755 and a standard user could read
// device.key (GAP-0747). A run closes the private folders before anything
// else, so no rollback opens them again.
func TestARolledBackRunLeavesThePrivateFoldersClosed(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	for _, dir := range []string{h.env.Layout.DataDir, h.env.Layout.SecretsDir} {
		if err := os.Chmod(h.env.P(dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.healthy = false
	requireError(t, h.run(Options{Action: ActionRepair}), codeActivate)
	if data, secrets := h.mode(h.env.Layout.DataDir), h.mode(h.env.Layout.SecretsDir); data != 0o700 || secrets != 0o750 {
		t.Fatalf("after the rolled-back repair runtime is %04o and secrets %04o", data, secrets)
	}
}

// macOS grants an ACL entry without changing the owner or the mode bits, so
// write entries for a standard user on the hook binary, bin/, the gateway
// LaunchDaemon plist and the Claude Code drop-in left status, verify and
// repair green and the entries in place (GAP-0946). status names each path
// and repair removes those entries; a deny entry elsewhere stays.
func TestRepairRemovesMacOSACLEntriesThatLetOtherAccountsChangeTheDeployment(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	l := h.env.Layout
	plist := "/Library/LaunchDaemons/" + labelGateway + ".plist"
	dropIn := "/Library/Application Support/ClaudeCode/managed-settings.d/" + enterprisepolicy.DefenseClawDropInName
	writable := map[string]string{
		filepath.Join(l.BinDir, binHook): "user:dcm-w4h2 allow write,append",
		plist:                            "user:dcm-w4h2 allow write,append",
		dropIn:                           "user:dcm-w4h2 allow write,append",
		l.BinDir:                         "user:dcm-w4h2 allow add_file,delete_child",
	}
	denyOnly := h.env.P(l.ConfigDir)
	h.runner.acls = map[string][]string{denyOnly: {"group:everyone deny delete"}}
	for canonical, entry := range writable {
		h.runner.acls[h.env.P(canonical)] = []string{"group:everyone deny delete", entry}
	}
	status := h.run(Options{Action: ActionStatus})
	requireError(t, status, codeVerify)
	got := messagesOf(status.Errors, codeVerify)
	for canonical := range writable {
		if !strings.Contains(got, canonical) || !strings.Contains(got, " repair`") {
			t.Errorf("status does not name %s and the repair: %s", canonical, got)
		}
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if len(h.runner.acls) != 1 || h.runner.acls[denyOnly] == nil {
		t.Fatalf("after repair the ACL entries are %v, want only the deny entry on %s", h.runner.acls, l.ConfigDir)
	}
	requireOK(t, h.run(Options{Action: ActionStatus}))
}
