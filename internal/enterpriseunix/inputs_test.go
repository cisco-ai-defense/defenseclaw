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
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hookedServices runs a callback before the fake service manager stops or
// starts a unit, to change inputs in the middle of a transaction.
type hookedServices struct {
	*fakeServices
	onStop  func(unit string)
	onStart func(unit string)
}

func (s *hookedServices) Stop(ctx context.Context, u Unit) error {
	if s.onStop != nil {
		s.onStop(u.Name)
	}
	return s.fakeServices.Stop(ctx, u)
}

func (s *hookedServices) Start(ctx context.Context, u Unit) error {
	if s.onStart != nil {
		s.onStart(u.Name)
	}
	return s.fakeServices.Start(ctx, u)
}

func unitOf(goos, kind string) string {
	for _, unit := range newServiceManager(&Env{GOOS: goos}).Units() {
		if unit.Kind == kind {
			return unit.Name
		}
	}
	return ""
}

// once returns a hook that writes data to canonical the first time unit is
// stopped or started.
func writeOnce(t *testing.T, h *testHost, unit, canonical string, data []byte) func(string) {
	done := false
	return func(name string) {
		if name != unit || done {
			return
		}
		done = true
		if err := os.WriteFile(h.env.P(canonical), data, 0o640); err != nil {
			t.Errorf("write %s: %v", canonical, err)
		}
	}
}

// An administrator (or configuration management) writes config.yaml while
// another lifecycle run holds the lock. The run used to write the bytes it
// had planned from back over the change (or leave a later write on disk
// unapplied, with the apply trigger stopped), and the next ensure was a
// no-op: the change was silently lost. The run now keeps the newer bytes and
// applies them in a follow-up transaction before it releases the lock. A
// run given --config is no different: it wrote its own file over one
// written in place while it ran, and the later writer lost (GAP-0745).
func TestConfigWrittenDuringATransactionIsApplied(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, moment := range []string{"quiesce", "activation", "quiesce-with-config-flag"} {
			t.Run(goos+"-"+moment, func(t *testing.T) {
				h := newTestHost(t, goos)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				edited := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
				hooked := &hookedServices{fakeServices: h.services}
				if strings.HasPrefix(moment, "quiesce") {
					hooked.onStop = writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, edited)
				} else {
					hooked.onStart = writeOnce(t, h, unitOf(goos, "gateway"), h.env.Layout.ConfigPath, edited)
				}
				h.env.Services = hooked
				opts := Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}
				if moment == "quiesce-with-config-flag" {
					opts.ConfigFile = filepath.Join(t.TempDir(), "pushed.yaml")
					if err := os.WriteFile(opts.ConfigFile, append(DefaultConfig(h.env.Layout), "# pushed\n"...), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				r := h.run(opts)
				requireOK(t, r)
				if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
					t.Fatal("the transaction wrote its planned config over the administrator's change")
				}
				record, _ := h.env.loadDeployment()
				if record.ConfigSHA256 != sha256Bytes(edited) || record.ProductVersion != "1.0.1" {
					t.Fatalf("the change is not applied: config %s version %s", record.ConfigSHA256[:8], record.ProductVersion)
				}
				if !hasWarning(r, "input_changed") {
					t.Fatalf("the result does not say a follow-up applied the change: %+v", r.Warnings)
				}
				again := h.run(Options{Action: ActionEnsure})
				requireOK(t, again)
				if !again.Noop {
					t.Fatal("ensure after the follow-up is not a no-op")
				}
			})
		}
	}
}

// A push left config.yaml 0666 after the run planned and a standard user
// switched enforcement before applyFiles ran. The run restored the managed
// owner and mode of the edited file, and its follow-up transaction applied
// the edit as administrator policy (GAP-1501). Bytes written while another
// account could write the file are refused when the run applies them and
// never kept for a follow-up, for a --config run and for an in-place edit.
// On macOS a write ACL entry does it without a mode change: the transaction
// removes the entry, and the rollback must not keep the bytes written
// through it as a newer config (GAP-1518).
func TestConfigMadeWritableAfterPlanningIsRefused(t *testing.T) {
	for _, tc := range []struct {
		goos       string
		configFlag bool
	}{{"linux", true}, {"linux", false}, {"darwin", true}, {"darwin", false}} {
		goos, configFlag := tc.goos, tc.configFlag
		t.Run(fmt.Sprintf("%s-config-flag-%v", goos, configFlag), func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			installed := h.read(h.env.Layout.ConfigPath)
			path := h.env.P(h.env.Layout.ConfigPath)
			admin := append(DefaultConfig(h.env.Layout), "# pushed\n"...)
			opts := Options{Action: ActionEnsure}
			if configFlag {
				opts.ConfigFile = filepath.Join(t.TempDir(), "pushed.yaml")
				if err := os.WriteFile(opts.ConfigFile, admin, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, admin, 0o640); err != nil {
				t.Fatal(err)
			}
			edited := []byte(strings.Replace(string(admin), "mode: observe", "mode: action", 1))
			done := false
			h.env.Services = &hookedServices{fakeServices: h.services, onStop: func(name string) {
				if name != unitOf(goos, "enumerator") || done {
					return
				}
				done = true
				if goos == "darwin" {
					h.runner.mu.Lock()
					h.runner.acls = map[string][]string{path: {"user:standard allow write"}}
					h.runner.mu.Unlock()
				} else if err := os.Chmod(path, 0o666); err != nil {
					t.Error(err)
				}
				if err := os.WriteFile(path, edited, 0o640); err != nil {
					t.Error(err)
				}
			}}
			requireError(t, h.run(opts), codeConfig)
			if got := h.read(h.env.Layout.ConfigPath); got != installed {
				t.Fatalf("after the rollback config.yaml is not the last applied config (edit kept: %v)", got == string(edited))
			}
			h.env.Services = h.services
			_ = h.run(Options{Action: ActionEnsure})
			record, _ := h.env.loadDeployment()
			if h.read(h.env.Layout.ConfigPath) == string(edited) || record.ConfigSHA256 == sha256Bytes(edited) {
				t.Fatalf("the edit written while another account could write config.yaml was kept or applied (%04o)", h.mode(h.env.Layout.ConfigPath))
			}
		})
	}
}

// GAP-1535: removing the ACL entries can fail before the transaction gets
// to the entry on config.yaml: chmod -a# fails on config.yaml or on a path
// listed before it, ls fails, or an entry on a folder above a vendor
// machine-policy folder refuses the run first. Bytes written through the
// entry on config.yaml are still not kept for a follow-up, for a --config
// run and for an in-place edit. Without a write entry on config.yaml the
// newer config is kept as before.
func TestConfigWrittenThroughAnACLIsRefusedWhenRemovingACLsFails(t *testing.T) {
	denied := fakeReply{result: CommandResult{ExitCode: 1}, err: errors.New("chmod: Operation not permitted")}
	for _, tc := range []struct {
		name  string
		entry string // the entry on config.yaml
		fail  func(h *testHost, config, binDir string)
		kept  bool
	}{
		{"chmod-config", "user:standard allow write", func(h *testHost, config, _ string) {
			h.runner.replies["chmod -h -a# 0 "+config] = denied
		}, false},
		{"chmod-earlier", "user:standard allow write", func(h *testHost, _, binDir string) {
			h.runner.replies["chmod -h -a# 0 "+binDir] = denied
		}, false},
		{"ls", "user:standard allow write", func(h *testHost, config, _ string) {
			h.env.Runner = failingLsRunner{Runner: h.runner, path: config}
		}, false},
		{"ancestor", "user:standard allow write", func(h *testHost, _, _ string) {
			h.runner.acls[h.env.P("/Library/Application Support")] = []string{"user:developer allow add_subdirectory"}
		}, false},
		{"read-entry", "user:standard allow read", func(h *testHost, config, _ string) {
			h.runner.replies["chmod -h -a# 0 "+config] = denied
		}, true},
	} {
		for _, configFlag := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s-config-flag-%v", tc.name, configFlag), func(t *testing.T) {
				h := newTestHost(t, "darwin")
				pushed := machinePolicyConfig(t, h, "claudecode")
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: pushed}))
				installed := h.read(h.env.Layout.ConfigPath)
				path := h.env.P(h.env.Layout.ConfigPath)
				binDir := h.env.P(h.env.Layout.BinDir)
				admin := []byte(installed + "# pushed\n")
				opts := Options{Action: ActionEnsure}
				if configFlag {
					opts.ConfigFile = pushed
					if err := os.WriteFile(pushed, admin, 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, admin, 0o640); err != nil {
					t.Fatal(err)
				}
				edited := []byte(strings.Replace(string(admin), "mode: observe", "mode: action", 1))
				done := false
				h.env.Services = &hookedServices{fakeServices: h.services, onStop: func(name string) {
					if name != unitOf("darwin", "enumerator") || done {
						return
					}
					done = true
					h.runner.mu.Lock()
					h.runner.acls = map[string][]string{path: {tc.entry}, binDir: {"user:standard allow add_file"}}
					h.runner.replies = map[string]fakeReply{}
					h.runner.mu.Unlock()
					tc.fail(h, path, binDir)
					if err := os.WriteFile(path, edited, 0o640); err != nil {
						t.Error(err)
					}
				}}
				requireError(t, h.run(opts), codeApply)
				// A new file stands for config.yaml from here on.
				h.env.Services, h.env.Runner, h.runner.acls, h.runner.replies = h.services, h.runner, nil, nil
				if got := h.read(h.env.Layout.ConfigPath); (got == string(edited)) != tc.kept {
					t.Fatalf("after the rollback config.yaml holds the edit: %v, want %v", got == string(edited), tc.kept)
				}
				if tc.kept {
					return
				}
				_ = h.run(Options{Action: ActionEnsure})
				if record, _ := h.env.loadDeployment(); h.read(h.env.Layout.ConfigPath) == string(edited) || record.ConfigSHA256 == sha256Bytes(edited) {
					t.Fatal("the edit written through a macOS ACL entry was kept or applied")
				}
			})
		}
	}
	// GAP-1553: the ACL is already present when the run plans. A --config
	// ensure reaches replaceWritableConfig, while an in-place edit is
	// refused by buildPlan. Neither path may leave the edited bytes for
	// the next ensure to record as administrator policy.
	for _, failure := range []string{"chmod-config", "chmod-etc", "ls-recheck"} {
		for _, configFlag := range []bool{true, false} {
			t.Run(fmt.Sprintf("plan-time-%s-config-flag-%v", failure, configFlag), func(t *testing.T) {
				h := newTestHost(t, "darwin")
				pushed := machinePolicyConfig(t, h, "claudecode")
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: pushed}))
				installed := h.read(h.env.Layout.ConfigPath)
				config := h.env.P(h.env.Layout.ConfigPath)
				etc := h.env.P(h.env.Layout.ConfigDir)
				edited := []byte(strings.Replace(installed, "mode: observe", "mode: action", 1))
				if err := os.WriteFile(config, edited, 0o640); err != nil {
					t.Fatal(err)
				}
				h.runner.acls = map[string][]string{
					etc:    {"user:standard allow add_file"},
					config: {"user:standard allow write"},
				}
				h.runner.replies = map[string]fakeReply{}
				opts := Options{Action: ActionEnsure}
				if configFlag {
					opts.ConfigFile = pushed
				}
				switch failure {
				case "chmod-config":
					h.runner.replies["chmod -h -a# 0 "+config] = denied
				case "chmod-etc":
					h.runner.replies["chmod -h -a# 0 "+etc] = denied
				case "ls-recheck":
					h.env.Runner = &failingACLRecheckRunner{Runner: h.runner, path: config}
				}
				requireError(t, h.run(opts), codeConfig)

				if configFlag {
					if failure == "ls-recheck" {
						if !h.env.Runner.(*failingACLRecheckRunner).failed {
							t.Fatal("the ACL ls re-check did not fail")
						}
					} else {
						target := map[string]string{"chmod-config": config, "chmod-etc": etc}[failure]
						if !strings.Contains(strings.Join(h.runner.calls, " "), "chmod -h -a# 0 "+target) {
							t.Fatal("the intended chmod -a# failure was not reached")
						}
					}
				}

				if got := h.read(h.env.Layout.ConfigPath); got != installed {
					t.Fatalf("after rejected plan-time ACL cleanup, config.yaml holds edited bytes: %v", got == string(edited))
				}
				h.env.Runner, h.runner.acls, h.runner.replies = h.runner, nil, nil
				requireOK(t, h.run(Options{Action: ActionEnsure}))
				record, _ := h.env.loadDeployment()
				if got := h.read(h.env.Layout.ConfigPath); got == string(edited) || record.ConfigSHA256 == sha256Bytes(edited) {
					t.Fatal("the next ensure kept or applied config written through a macOS ACL")
				}
			})
		}
	}
}

// failingACLRecheckRunner fails the first ls of config.yaml after chmod -a#.
type failingACLRecheckRunner struct {
	Runner
	path    string
	removed bool
	failed  bool
}

func (r *failingACLRecheckRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "ls" && r.removed && !r.failed && strings.Contains(strings.Join(args, "\x00"), r.path) {
		r.failed = true
		return CommandResult{ExitCode: 1}, errors.New("ls: permission denied")
	}
	result, err := r.Runner.Run(ctx, name, args...)
	if name == "chmod" && err == nil && len(args) >= 2 && args[1] == "-a#" {
		r.removed = true
	}
	return result, err
}

// A protected credential written during a transaction is applied the same
// way.
func TestSecretWrittenDuringATransactionIsApplied(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	secret := filepath.Join(h.env.Layout.SecretsDir, "ai-defense-api-key")
	h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitEnumerator, secret, []byte("rotated"))}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	_, secretsSHA, err := h.env.listSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if record, _ := h.env.loadDeployment(); record.SecretsSHA256 != secretsSHA {
		t.Fatal("the credential written during the transaction is not applied")
	}
}

// I-1317: a stop signal (systemd stopping the apply trigger) killed the run
// mid-step with no result. The run now finishes the step it is in, rolls
// back at the next safe point and returns its result; the previous
// deployment runs.
func TestInterruptedTransactionRollsBackAndReports(t *testing.T) {
	for _, moment := range []string{"before", "while-stopping"} {
		t.Run(moment, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			interrupt := make(chan struct{})
			if moment == "before" {
				close(interrupt)
			} else {
				once := false
				h.env.Services = &hookedServices{fakeServices: h.services, onStop: func(name string) {
					if name == unitGateway && !once {
						once = true
						close(interrupt)
					}
				}}
			}
			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), Interrupted: interrupt})
			requireError(t, r, codeInterrupted)
			// A signal before the run started changed nothing to roll back.
			if moment != "before" && !hasWarning(r, codeRolledBack) {
				t.Fatalf("the result does not say it rolled back: %+v", r.Warnings)
			}
			record, _ := h.env.loadDeployment()
			if record == nil || record.ProductVersion != "1.0.0" {
				t.Fatalf("the interrupted upgrade did not keep the previous deployment: %+v", record)
			}
			if !h.services.isActive(unitGateway) {
				t.Fatal("the previous gateway is not running after the rollback")
			}
			if pending, _ := h.env.loadPending(); pending != nil {
				t.Fatalf("the rollback left a pending transaction: %+v", pending)
			}
		})
	}
}

// A SIGTERM to an uninstall that waits for the lifecycle lock (an MDM
// timeout behind a running ensure) ends the wait: the uninstall used to take
// the lock later and remove the deployment after it was told to stop. An
// uninstall or reconcile that got the signal before it started changes
// nothing either.
func TestStopSignalEndsTheWaitForTheLockAndChangesNothing(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	held, err := h.env.acquireLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h.env.LockTimeout = time.Minute
	interrupt := make(chan struct{})
	time.AfterFunc(100*time.Millisecond, func() { close(interrupt) })
	started := time.Now()
	r := h.run(Options{Action: ActionUninstall, Interrupted: interrupt})
	held.release()
	requireError(t, r, codeInterrupted)
	if waited := time.Since(started); waited > 30*time.Second {
		t.Fatalf("the uninstall waited %s for the lock after the stop signal", waited)
	}
	for _, action := range []string{ActionUninstall, ActionReconcile} {
		r := h.run(Options{Action: action, Interrupted: interrupt})
		requireError(t, r, codeInterrupted)
	}
	if record, _ := h.env.loadDeployment(); record == nil || record.ProductVersion != "1.0.0" {
		t.Fatalf("an interrupted run changed the deployment: %+v", record)
	}
	if !h.services.isActive(unitGateway) {
		t.Fatal("an interrupted run stopped the gateway")
	}
}

// After a failed transaction the change is neither reverted by the rollback
// nor lost: the apply trigger is started so it runs ensure once this run
// ends.
func TestConfigWrittenDuringAFailedTransactionRetriggersApply(t *testing.T) {
	for goos, trigger := range map[string]string{
		"linux":  "systemctl start --no-block " + unitApplyService,
		"darwin": "launchctl kickstart system/" + labelApply,
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			edited := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, edited)}
			h.healthy = false
			failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
			requireError(t, failed, codeActivate)
			if !strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
				t.Fatal("the rollback put the previous config.yaml back over the administrator's change")
			}
			found := false
			for _, call := range h.runner.calls {
				if call == trigger {
					found = true
				}
			}
			if !found || !hasWarning(failed, "input_changed") {
				t.Fatalf("the apply trigger was not started (%v): %+v", found, failed.Warnings)
			}
		})
	}
}

// Configuration management pushes config.yaml while a first install starts
// the gateway, and the install fails. The rollback removes the config.yaml
// the install wrote; the push is the administrator's file and stays, with
// the managed mode, for the next install (p0 GAP-1410).
func TestConfigPushedDuringAFailedFirstInstallIsKept(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			pushed := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			h.env.Services = &hookedServices{fakeServices: h.services, onStart: writeOnce(t, h, unitOf(goos, "gateway"), h.env.Layout.ConfigPath, pushed)}
			h.healthy = false
			failed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
			requireError(t, failed, codeActivate)
			if record, _ := h.env.loadDeployment(); record != nil {
				t.Fatal("the failed first install committed a deployment")
			}
			data, err := os.ReadFile(h.env.P(h.env.Layout.ConfigPath))
			if err != nil || string(data) != string(pushed) {
				t.Fatalf("the rollback dropped the config.yaml pushed during the install (err %v)", err)
			}
			if mode := h.mode(h.env.Layout.ConfigPath); mode != 0o640 {
				t.Fatalf("the kept config.yaml has mode %o", mode)
			}
		})
	}
}

// GAP-1379: configuration management pushes config.yaml while a failed
// --config run restarts the previous deployment, after the rollback put the
// previous file back. The push is a newer input: the apply trigger is
// started for it, and putting back a config.yaml written earlier in the run
// must not overwrite it.
func TestConfigPushedAfterAFailedConfigRollbackIsKeptAndRetriggersApply(t *testing.T) {
	trigger := "systemctl start --no-block " + unitApplyService
	for _, earlier := range []bool{false, true} {
		t.Run(map[bool]string{false: "push-after-restore", true: "earlier-push-kept"}[earlier], func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			applied := h.read(h.env.Layout.ConfigPath)
			early := []byte(applied + "# early push\n")
			late := []byte(applied + "# push after the rollback restored config.yaml\n")
			configPath := h.env.P(h.env.Layout.ConfigPath)
			replace := func(data []byte) {
				tmp := configPath + ".push"
				if err := os.WriteFile(tmp, data, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, configPath); err != nil {
					t.Fatal(err)
				}
			}
			hooked := &hookedServices{fakeServices: h.services}
			if earlier {
				pushed := false
				hooked.onStop = func(unit string) {
					if unit == unitEnumerator && !pushed {
						pushed = true
						replace(early)
					}
				}
			}
			// The rollback's restart is the first gateway start that sees
			// the restored file after the transaction's own.
			sawOwn, done := false, false
			hooked.onStart = func(unit string) {
				if unit != unitGateway || done {
					return
				}
				if h.read(h.env.Layout.ConfigPath) != applied {
					sawOwn = true
				} else if sawOwn {
					done = true
					replace(late)
				}
			}
			h.env.Services = hooked
			h.healthy = false
			configFile := filepath.Join(t.TempDir(), "pushed.yaml")
			if err := os.WriteFile(configFile, []byte(applied+"# --config\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0"), ConfigFile: configFile})
			requireError(t, failed, codeActivate)
			if !done {
				t.Fatal("the rollback did not restart the gateway with the restored config.yaml")
			}
			if got := h.read(h.env.Layout.ConfigPath); got != string(late) {
				t.Fatalf("the push made after the restore was overwritten:\n%s", got)
			}
			found := false
			for _, call := range h.runner.calls {
				found = found || call == trigger
			}
			if !found || !hasWarning(failed, "input_changed") {
				t.Fatalf("the apply trigger was not started for the push (%v): %+v", found, failed.Warnings)
			}
		})
	}
}

// The documented MDM flow: edit E1 is written into config.yaml and the apply
// trigger runs ensure; E2 is written while that run is under way and the
// run then fails. The rollback reverts to the last applied config for its
// restart, keeps E1 (the edit it checked) as the rejected file rather than
// E2 (which nothing checked), puts E2 back afterwards and starts the apply
// trigger, so E2 gets its own transaction instead of being reported as
// rejected and dropped.
func TestConfigPushedDuringAFailedInPlaceEditIsAppliedNext(t *testing.T) {
	for goos, trigger := range map[string]string{
		"linux":  "systemctl start --no-block " + unitApplyService,
		"darwin": "launchctl kickstart system/" + labelApply,
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			applied := h.read(h.env.Layout.ConfigPath)
			first := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1))
			second := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1) + "# second push\n")
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), first, 0o640); err != nil {
				t.Fatal(err)
			}
			h.env.Services = &hookedServices{fakeServices: h.services, onStop: writeOnce(t, h, unitOf(goos, "enumerator"), h.env.Layout.ConfigPath, second)}
			h.healthy = false
			failed := h.run(Options{Action: ActionEnsure, Reason: "path"})
			requireError(t, failed, codeActivate)
			if got := h.read(h.env.Layout.ConfigPath); got != string(second) {
				t.Fatalf("config.yaml after the rollback is not the newer push:\n%s", got)
			}
			if kept, err := os.ReadFile(h.env.rejectedConfigPath()); err != nil || string(kept) != string(first) {
				t.Fatalf("rejected-config.yaml = %q (%v), want the edit this run checked", kept, err)
			}
			if h.env.rejectedConfigProblem() != "" {
				t.Fatal("status reports the newer push as rejected")
			}
			found := false
			for _, call := range h.runner.calls {
				if call == trigger {
					found = true
				}
			}
			if !found || !hasWarning(failed, "input_changed") {
				t.Fatalf("the apply trigger was not started for the newer push (%v): %+v", found, failed.Warnings)
			}
			// The retriggered run applies the newer push.
			h.healthy = true
			h.env.Services = h.services
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
			if record, _ := h.env.loadDeployment(); record.ConfigSHA256 != sha256Bytes(second) {
				t.Fatal("the newer push was not applied by the next run")
			}
		})
	}
}

// GAP-1412: configuration management writes the rejected edit's bytes
// again after the failed run reverted them, while the rollback restarts the
// previous deployment. That is a fresh push of the same desired config: the
// apply trigger is started for it, so the retry is not left unapplied.
func TestRejectedEditPushedAgainDuringTheRollbackRetriggersApply(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := h.read(h.env.Layout.ConfigPath)
	edit := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1))
	configPath := h.env.P(h.env.Layout.ConfigPath)
	if err := os.WriteFile(configPath, edit, 0o640); err != nil {
		t.Fatal(err)
	}
	// The rollback's restart is the first gateway start that sees the
	// reverted file after the transaction's own.
	sawOwn, pushed := false, false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != unitGateway || pushed {
			return
		}
		if h.read(h.env.Layout.ConfigPath) != applied {
			sawOwn = true
		} else if sawOwn {
			pushed = true
			tmp := configPath + ".push"
			if err := os.WriteFile(tmp, edit, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, configPath); err != nil {
				t.Fatal(err)
			}
		}
	}}
	h.healthy = false
	failed := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireError(t, failed, codeActivate)
	if !pushed || !hasWarning(failed, codeConfigReverted) {
		t.Fatalf("premise: the edit was reverted and pushed again during the rollback (%v): %+v", pushed, failed.Warnings)
	}
	found := false
	for _, call := range h.runner.calls {
		found = found || call == "systemctl start --no-block "+unitApplyService
	}
	if !found || !hasWarning(failed, codeInputChanged) {
		t.Fatalf("the apply trigger was not started for the same-byte push (%v): %+v", found, failed.Warnings)
	}
}

// When the failed run is the apply trigger itself (the path unit runs
// ensure --reason path), starting that oneshot again from inside it is a
// no-op, so the same-byte push stayed unapplied (GAP-1412). The run
// schedules one deferred start from a transient timer, with a growing delay,
// and stops at the bound with a status line; a healthy run resets the count.
func TestRejectedEditPushedAgainDuringTheTriggerRunIsRetriedBounded(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := h.read(h.env.Layout.ConfigPath)
	edit := []byte(strings.Replace(applied, "mode: observe", "mode: action", 1))
	configPath := h.env.P(h.env.Layout.ConfigPath)
	push := func() {
		tmp := configPath + ".push"
		if err := os.WriteFile(tmp, edit, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, configPath); err != nil {
			t.Fatal(err)
		}
	}
	sawOwn, pushed := false, false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != unitGateway || pushed {
			return
		}
		if h.read(h.env.Layout.ConfigPath) != applied {
			sawOwn = true
		} else if sawOwn {
			pushed = true
			push()
		}
	}}
	h.env.SelfUnit = unitApplyService
	h.healthy = false
	push()
	// A systemd-run that fails schedules nothing, so it keeps no count and
	// the next run still waits the first delay.
	first := fmt.Sprintf("systemd-run --quiet --collect --unit=%s --on-active=%ds --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no systemctl start --no-block %s",
		unitApplyRetry, int(applyRetryDelay/time.Second), unitApplyService)
	h.runner.replies = map[string]fakeReply{first: {result: CommandResult{ExitCode: 1}, err: errors.New("exit 1")}}
	failed := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireError(t, failed, codeActivate)
	if !pushed || exists(h.env.applyRetryPath()) {
		t.Fatalf("a failed systemd-run kept a retry count (pushed again: %v): %+v", pushed, failed.Warnings)
	}
	h.runner.replies = nil
	for attempt := 1; attempt <= maxApplyRetries+1; attempt++ {
		sawOwn, pushed = false, false
		before := len(h.runner.calls)
		failed := h.run(Options{Action: ActionEnsure, Reason: "path"})
		requireError(t, failed, codeActivate)
		if !pushed {
			t.Fatalf("premise: run %d reverted the edit and it was pushed again: %+v", attempt, failed.Warnings)
		}
		var scheduled []string
		for _, call := range h.runner.calls[before:] {
			if strings.HasPrefix(call, "systemd-run ") || strings.HasPrefix(call, "systemctl start") {
				scheduled = append(scheduled, call)
			}
		}
		limit := false
		for _, warning := range failed.Warnings {
			limit = limit || (warning.Code == codeInputChanged && strings.Contains(warning.Message, "retry limit reached"))
		}
		if attempt > maxApplyRetries {
			if len(scheduled) != 0 || !limit {
				t.Fatalf("run %d: retried past the bound (%v) or no retry-limit status: %v %+v", attempt, limit, scheduled, failed.Warnings)
			}
			continue
		}
		delay := fmt.Sprintf("--on-active=%ds", int(applyRetryDelay/time.Second)<<(attempt-1))
		if len(scheduled) != 1 || !strings.Contains(scheduled[0], delay) || !strings.HasSuffix(scheduled[0], " systemctl start --no-block "+unitApplyService) || limit {
			t.Fatalf("run %d: want one deferred apply start %s, got %v %+v", attempt, delay, scheduled, failed.Warnings)
		}
	}
	h.healthy = true
	requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
	if exists(h.env.applyRetryPath()) {
		t.Fatal("a healthy apply kept the retry count")
	}
}

// Every host tool the package runs by name needs a commandCandidates entry:
// the production runner resolves names only through that table, and the
// fake runner of the other tests accepts any name. systemd-run had none, so
// the apply-trigger retry was never scheduled on a real host (GAP-1412).
// Every entry is also run somewhere, so the table keeps no dead names.
func TestEveryCommandRunByNameHasACandidate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	called := map[string]string{}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			index := map[string]int{"Run": 1, "RunEnv": 2}[selector.Sel.Name]
			if index == 0 || len(call.Args) <= index {
				return true
			}
			if literal, ok := call.Args[index].(*ast.BasicLit); ok && literal.Kind == token.STRING {
				if name, err := strconv.Unquote(literal.Value); err == nil {
					called[name] = fset.Position(literal.Pos()).String()
				}
			}
			return true
		})
	}
	if _, ok := called["systemd-run"]; !ok || len(called) < 10 {
		t.Fatalf("premise: the scan found too few commands run by name: %v", called)
	}
	for name, at := range called {
		if len(commandCandidates[name]) == 0 {
			t.Errorf("%s runs %q, which has no commandCandidates entry", at, name)
		}
	}
	for name := range commandCandidates {
		if _, ok := called[name]; !ok {
			t.Errorf("commandCandidates[%q] is never run", name)
		}
	}
}

// The production resolver finds systemd-run where the supported
// distributions install it, and only there.
func TestSystemdRunResolvesFromItsInstalledPaths(t *testing.T) {
	want := []string{"/usr/bin/systemd-run", "/bin/systemd-run"}
	if got := commandCandidates["systemd-run"]; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("systemd-run candidates = %v, want %v", got, want)
	}
	path, err := resolveCommand("systemd-run")
	for _, candidate := range want {
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			if err != nil || path != candidate {
				t.Fatalf("resolveCommand(systemd-run) = %q, %v; want %s", path, err, candidate)
			}
			return
		}
	}
	if !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("resolveCommand(systemd-run) on a host without it = %q, %v", path, err)
	}
}

// A follow-up transaction describes the deployment again; a standing
// warning such as a failed oneshot is reported once in the one result, not
// once per pass.
func TestAFollowUpTransactionReportsEachWarningOnce(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	// The guardian reconcile oneshot: a committing run clears a failed apply
	// or verify oneshot (GAP-0423), not this one.
	h.services.failed[unitGuardianOneshot] = true
	edited := []byte(strings.Replace(h.read(h.env.Layout.ConfigPath), "mode: observe", "mode: action", 1))
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: writeOnce(t, h, unitOf("linux", "gateway"), h.env.Layout.ConfigPath, edited)}
	r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")})
	requireOK(t, r)
	if !hasWarning(r, codeInputChanged) {
		t.Fatalf("premise: a follow-up transaction ran: %+v", r.Warnings)
	}
	count := 0
	for _, warning := range r.Warnings {
		if warning.Code == "unit_failed" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("unit_failed reported %d times: %+v", count, r.Warnings)
	}
}

// lookupHookedAccounts runs onLookup before each account lookup.
type lookupHookedAccounts struct {
	AccountManager
	onLookup func()
}

func (a *lookupHookedAccounts) Lookup(ctx context.Context, name string) (Account, bool, error) {
	if a.onLookup != nil {
		a.onLookup()
	}
	return a.AccountManager.Lookup(ctx, name)
}

// rel-1-0-3 GAP-0142: a second config push that lands while the first run
// verifies the services it just started (after the run last looked for a
// newer input) failed that verify with "config.yaml changed since it was
// applied", rolled the first push back and reverted the second for another
// run. The run now verifies again without the replaced input, commits the
// first push and applies the second in its follow-up transaction.
func TestConfigPushedWhileTheRunVerifiesIsTheFollowUpNotARollback(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			second := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			armed, done := false, false
			hooked := &hookedServices{fakeServices: h.services}
			hooked.onStart = func(unit string) {
				if unit == unitOf(goos, "gateway") {
					armed = true
				}
			}
			h.env.Services = hooked
			h.env.Accounts = &lookupHookedAccounts{AccountManager: h.env.Accounts, onLookup: func() {
				if !armed || done {
					return
				}
				done = true
				if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), second, 0o640); err != nil {
					t.Errorf("write config: %v", err)
				}
			}}
			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")})
			if !done {
				t.Fatal("the second push was not written during the run")
			}
			requireOK(t, r)
			if hasMessageCode(r.Errors, codeVerify) || hasMessageCode(r.Warnings, codeConfigReverted) {
				t.Fatalf("the push during verify failed or reverted the run: errors %+v warnings %+v", r.Errors, r.Warnings)
			}
			record, _ := h.env.loadDeployment()
			if record.ConfigSHA256 != sha256Bytes(second) || record.ProductVersion != "1.0.1" {
				t.Fatalf("the second push is not applied: config %s version %s", record.ConfigSHA256[:8], record.ProductVersion)
			}
			if !hasWarning(r, codeInputChanged) {
				t.Fatalf("the result does not say a follow-up applied the second push: %+v", r.Warnings)
			}
		})
	}
}
