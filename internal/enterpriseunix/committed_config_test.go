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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// editConfigInPlace writes config.yaml the way an MDM file push does.
func editConfigInPlace(t *testing.T, h *testHost, from, to string) string {
	t.Helper()
	edited := strings.Replace(h.read(h.env.Layout.ConfigPath), from, to, 1)
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}
	return edited
}

// An MDM edits config.yaml in place and the apply trigger runs ensure. When
// the lifecycle rejects the edit, the gateway (which follows the file) must
// not keep running it, and a later gateway restart must not pick it up: the
// last applied config goes back in place and the rejected one is kept.
func TestRejectedInPlaceConfigIsReverted(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		applied := h.read(h.env.Layout.ConfigPath)
		edited := editConfigInPlace(t, h, "api_port: 18970", "api_port: 18971")
		r := h.run(Options{Action: ActionEnsure, Reason: "path"})
		requireError(t, r, codeConfig)
		if !hasWarning(r, codeConfigReverted) {
			t.Fatalf("the revert is not reported: %+v", r.Warnings)
		}
		if got := h.read(h.env.Layout.ConfigPath); got != applied {
			t.Fatalf("the rejected config stayed in place:\n%s", got)
		}
		if got, err := os.ReadFile(h.env.rejectedConfigPath()); err != nil || string(got) != edited {
			t.Fatalf("the rejected config was not kept: %v", err)
		}
		// The trigger our revert fires settles to a no-op.
		if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); !again.Noop {
			t.Fatalf("ensure after the revert is not a no-op: %+v %+v", again.Errors, again.Warnings)
		}
	})
	// A bad profile push left config.yaml 0666 and a standard user switched
	// enforcement to observe; the apply trigger applied it (GAP-0524).
	t.Run("writable by other accounts", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		applied := h.read(h.env.Layout.ConfigPath)
		if err := os.Chmod(h.env.P(h.env.Layout.ConfigPath), 0o666); err != nil {
			t.Fatal(err)
		}
		editConfigInPlace(t, h, "mode: observe", "mode: action")
		r := h.run(Options{Action: ActionEnsure, Reason: "path"})
		requireError(t, r, codeConfig)
		if got := h.read(h.env.Layout.ConfigPath); got != applied || h.mode(h.env.Layout.ConfigPath) != 0o640 {
			t.Fatalf("the edit written while config.yaml was 0666 was applied (%04o):\n%s", h.mode(h.env.Layout.ConfigPath), got)
		}
	})
	t.Run("activation fails", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		applied := h.read(h.env.Layout.ConfigPath)
		editConfigInPlace(t, h, "mode: observe", "mode: action")
		h.healthy = false
		r := h.run(Options{Action: ActionEnsure, Reason: "path"})
		requireError(t, r, codeActivate)
		if got := h.read(h.env.Layout.ConfigPath); got != applied {
			t.Fatalf("the rollback kept the rejected in-place config:\n%s", got)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		edited := editConfigInPlace(t, h, "mode: observe", "mode: action")
		r := h.run(Options{Action: ActionEnsure, Reason: "path"})
		requireOK(t, r)
		if got := h.read(h.env.Layout.ConfigPath); got != edited {
			t.Fatal("a valid in-place edit was not applied")
		}
		// The result says what the apply did (#1032).
		changes := strings.Join(r.Changes, "\n")
		if !strings.Contains(changes, "applied the edited "+h.env.Layout.ConfigPath) || !strings.Contains(changes, "restarted "+unitGateway) {
			t.Fatalf("the apply result does not say what it changed: %q", r.Changes)
		}
		if got, err := os.ReadFile(h.env.committedConfigPath()); err != nil || string(got) != edited {
			t.Fatalf("the applied config copy was not updated: %v", err)
		}
	})
}

// Configuration management that enforces the administrator's v8 file in
// place puts it back after the upgrade migrated it. ensure keeps those bytes
// instead of migrating them again on every run, which would loop with the
// tool.
func TestReassertedV8ConfigIsNotRewritten(t *testing.T) {
	h := newTestHost(t, "linux")
	v8 := v8AdminConfig(h.env.Layout)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte(v8), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	if !strings.Contains(h.read(h.env.Layout.ConfigPath), "config_version: 9") {
		t.Fatal("the v8 admin config was not migrated on install")
	}
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(v8), 0o640); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
	if got := h.read(h.env.Layout.ConfigPath); got != v8 {
		t.Fatalf("the re-asserted v8 config was rewritten:\n%s", got)
	}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	if !r.Noop {
		t.Fatalf("the kept v8 config does not settle: %+v", r.Changes)
	}
	// The settled run still says the file is version 8 (GAP-0540).
	if !hasWarning(r, codeConfigV8) {
		t.Fatalf("a run that read a config_version 8 file does not say so: %+v", r.Warnings)
	}
}

func hasMessage(messages []enterprisestatus.Message, substring string) bool {
	for _, m := range messages {
		if strings.Contains(m.Message, substring) {
			return true
		}
	}
	return false
}

// pushConfig writes config.yaml the way a later MDM push does: the file's
// modification time moves on even when the bytes are the same.
func pushConfig(t *testing.T, h *testHost, content string) {
	t.Helper()
	path := h.env.P(h.env.Layout.ConfigPath)
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}

// A reverted edit is the administrator's config not running. It stays
// visible (a status warning and a verify failure, which MDM compliance
// checks see) until config.yaml is written again; the apply trigger the
// revert itself fires does not clear it, and neither does an unrelated
// change applied on top of the reverted config.
func TestRejectedConfigStaysReportedUntilConfigIsPushedAgain(t *testing.T) {
	reject := func(t *testing.T) (*testHost, string) {
		t.Helper()
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		applied := h.read(h.env.Layout.ConfigPath)
		editConfigInPlace(t, h, "api_port: 18970", "api_port: 18971")
		requireError(t, h.run(Options{Action: ActionEnsure, Reason: "path"}), codeConfig)
		return h, applied
	}
	requireReported := func(t *testing.T, h *testHost) {
		t.Helper()
		if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); !again.Noop || !hasWarning(again, codeConfigRejected) {
			t.Fatalf("ensure after the revert: noop=%v warnings=%+v", again.Noop, again.Warnings)
		}
		if status := h.run(Options{Action: ActionStatus}); !hasWarning(status, codeConfigRejected) {
			t.Fatalf("status does not report the rejected edit: %+v", status.Warnings)
		}
		if verify := h.run(Options{Action: ActionVerify}); !hasMessage(verify.Errors, "rejected") {
			t.Fatalf("verify does not fail on the rejected edit: %+v", verify.Errors)
		}
	}
	requireCleared := func(t *testing.T, h *testHost) {
		t.Helper()
		if exists(h.env.rejectedConfigPath()) {
			t.Fatal("the superseded rejected edit was kept")
		}
		if status := h.run(Options{Action: ActionStatus}); hasWarning(status, codeConfigRejected) {
			t.Fatalf("status still reports a superseded rejected edit: %+v", status.Warnings)
		}
		if verify := h.run(Options{Action: ActionVerify}); hasMessage(verify.Errors, "rejected") {
			t.Fatalf("verify still fails on a superseded rejected edit: %+v", verify.Errors)
		}
	}

	t.Run("the last applied config pushed back", func(t *testing.T) {
		h, applied := reject(t)
		requireReported(t, h)
		pushConfig(t, h, applied)
		if r := h.run(Options{Action: ActionEnsure, Reason: "path"}); !r.Noop || hasWarning(r, codeConfigRejected) {
			t.Fatalf("ensure after the push: noop=%v warnings=%+v", r.Noop, r.Warnings)
		}
		requireCleared(t, h)
	})
	t.Run("a corrected edit applied", func(t *testing.T) {
		h, applied := reject(t)
		// A transaction that applies the reverted config again (a repair,
		// or a credential change) does not settle the rejected edit.
		requireOK(t, h.run(Options{Action: ActionRepair}))
		requireReported(t, h)
		pushConfig(t, h, strings.Replace(applied, "mode: observe", "mode: action", 1))
		requireOK(t, h.run(Options{Action: ActionEnsure, Reason: "path"}))
		requireCleared(t, h)
	})
	t.Run("uninstall", func(t *testing.T) {
		h, _ := reject(t)
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		requireCleared(t, h)
	})
}
