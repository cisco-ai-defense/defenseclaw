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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1928: a tampered Codex requirements.toml (a comment line appended, a
// managed value changed) was not put back by the hook guardian, repair
// returned ok while the file stayed tampered and pinned the tampered view as
// trusted, and the original file then failed verify until a full ensure.

type codexHealHost struct {
	*testHost
	want, pin string
}

func newCodexHealHost(t *testing.T, goos string) *codexHealHost {
	t.Helper()
	h := newTestHost(t, goos)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex")}))
	ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
	h.publishLedger(ledger)
	c := &codexHealHost{testHost: h, want: h.read(codexRequirements)}
	c.pin = c.trustedPin(t)
	if observed := c.observedView(t); observed != c.pin {
		t.Fatalf("install pinned %q, the published view is %q", c.pin, observed)
	}
	if got := h.env.TamperedFiles(); len(got) != 0 {
		t.Fatalf("a fresh install reports tampered files: %v", got)
	}
	return c
}

func (c *codexHealHost) trustedPin(t *testing.T) string {
	t.Helper()
	descriptor, err := managed.ParseRuntimeDescriptor([]byte(c.read(c.env.Layout.DescriptorPath)))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.PolicyViewDigests["codex"]
}

func (c *codexHealHost) observedView(t *testing.T) string {
	t.Helper()
	opts := enterprisepolicy.LayoutOptions(c.env.Layout, "", "")
	opts.GOOS, opts.Root, opts.SkipTrustChecks = c.env.GOOS, c.env.Root, true
	digest, err := enterprisepolicy.PolicyViewDigest(opts, "codex")
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func (c *codexHealHost) write(t *testing.T, data string) {
	t.Helper()
	if err := os.WriteFile(c.env.P(codexRequirements), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// requireHealed checks that the file is byte for byte what DefenseClaw
// published, the trusted pin did not move, and verify passes.
func (c *codexHealHost) requireHealed(t *testing.T, step string) {
	t.Helper()
	if got := c.read(codexRequirements); got != c.want {
		t.Fatalf("%s: requirements.toml is not the published file:\n%s", step, got)
	}
	if pin := c.trustedPin(t); pin != c.pin {
		t.Fatalf("%s: the trusted policy-view pin moved from %q to %q", step, c.pin, pin)
	}
	if got := c.env.TamperedFiles(); len(got) != 0 {
		t.Fatalf("%s: still tampered: %v", step, got)
	}
	requireOK(t, c.run(Options{Action: ActionVerify}))
}

func codexTampers(want string) map[string]string {
	return map[string]string{
		// The live tamper: one comment line appended, after DefenseClaw's
		// hooks block (TOML reads a key there as part of DefenseClaw's last
		// table).
		"appended comment": want + "# tampered\n",
		// A managed value changed inside DefenseClaw's block.
		"changed managed value": strings.Replace(want, "allow_managed_hooks_only = true", "allow_managed_hooks_only = false", 1),
		// A managed hook command changed.
		"changed hook command": strings.Replace(want, "defenseclaw-hook", "defenseclaw-hookx", 1),
	}
}

func TestGAP1928TamperedCodexRequirementsIsFoundAndPutBackByEnsure(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for name := range codexTampers("") {
			t.Run(goos+"/"+name, func(t *testing.T) {
				c := newCodexHealHost(t, goos)
				tampered := codexTampers(c.want)[name]
				if tampered == c.want {
					t.Fatalf("the %s tamper does not change the published file", name)
				}
				c.write(t, tampered)
				// The guardian lists it, so it starts the restore.
				if got := c.env.TamperedFiles(); !reflect.DeepEqual(got, []string{codexRequirements}) {
					t.Fatalf("the guardian check found %v", got)
				}
				if verify := c.run(Options{Action: ActionVerify}); verify.OK {
					t.Fatalf("verify passed a tampered requirements.toml: %+v", verify)
				}
				ensure := c.run(Options{Action: ActionEnsure, Reason: "path"})
				requireOK(t, ensure)
				// The tampered file is kept beside it (GAP-1967).
				if !strings.Contains(strings.Join(ensure.Changes, "\n"), "restored the published codex machine policy") {
					t.Fatalf("ensure did not report the restore: changes %v noop %v %q warnings %v\n%s", ensure.Changes, ensure.Noop, ensure.NoopReason, ensure.Warnings, c.read(codexRequirements))
				}
				c.requireHealed(t, "ensure")
			})
		}
	}
}

func TestGAP1928RepairPutsBackTamperedCodexRequirements(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for name := range codexTampers("") {
			t.Run(goos+"/"+name, func(t *testing.T) {
				c := newCodexHealHost(t, goos)
				c.write(t, codexTampers(c.want)[name])
				requireOK(t, c.run(Options{Action: ActionRepair}))
				c.requireHealed(t, "repair")
			})
		}
	}
}

// An edit of the administrator's own text (between DefenseClaw's blocks) is
// left to verify, not the guardian; ensure and repair put back the
// published file and never pin the edit; reconcile is how an administrator
// accepts it.
func TestGAP1928AdministratorTextEditIsNeverPinnedByEnsureOrRepair(t *testing.T) {
	for _, action := range []string{ActionEnsure, ActionRepair} {
		t.Run(action, func(t *testing.T) {
			c := newCodexHealHost(t, "linux")
			edited := adminNote(c.want)
			if edited == c.want {
				t.Fatal("the published file has no managed settings block to write after")
			}
			c.write(t, edited)
			if got := c.env.TamperedFiles(); len(got) != 0 {
				t.Fatalf("the guardian treats an administrator text edit as tamper: %v", got)
			}
			verify := c.run(Options{Action: ActionVerify})
			if verify.OK || !hasWarningContaining(verify, codeMachinePolicyIncomplete, "to put back the requirements DefenseClaw published") {
				t.Fatalf("verify did not report the edit with its way out: %+v", verify.Warnings)
			}
			requireOK(t, c.run(Options{Action: action}))
			c.requireHealed(t, action)
			// Reconcile accepts the same edit as the trusted view.
			c.write(t, edited)
			requireOK(t, c.run(Options{Action: ActionReconcile}))
			if got := c.read(codexRequirements); !strings.Contains(got, "# administrator note\n") {
				t.Fatalf("reconcile dropped the administrator's edit:\n%s", got)
			}
			if pin := c.trustedPin(t); pin == c.pin || pin != c.observedView(t) {
				t.Fatalf("reconcile did not pin the accepted view: pin %q, observed %q", pin, c.observedView(t))
			}
			requireOK(t, c.run(Options{Action: ActionVerify}))
			// Later heals keep the accepted text.
			c.write(t, c.read(codexRequirements)+"# tampered\n")
			requireOK(t, c.run(Options{Action: action}))
			if got := c.read(codexRequirements); !strings.Contains(got, "# administrator note\n") || strings.Contains(got, "# tampered") {
				t.Fatalf("%s after reconcile did not restore the accepted file:\n%s", action, got)
			}
		})
	}
}

// After a tamper and a repair, putting the original file back passes verify
// with no ensure: the pin is still the published view (repair pinned the
// tampered one before).
func TestGAP1928RestoredOriginalVerifiesWithoutEnsure(t *testing.T) {
	c := newCodexHealHost(t, "linux")
	c.write(t, c.want+"# tampered\n")
	requireOK(t, c.run(Options{Action: ActionRepair}))
	c.write(t, c.want+"# tampered again\n")
	if verify := c.run(Options{Action: ActionVerify}); verify.OK {
		t.Fatal("verify passed a tampered requirements.toml")
	}
	c.write(t, c.want)
	requireOK(t, c.run(Options{Action: ActionVerify}))
	if pin := c.trustedPin(t); pin != c.pin {
		t.Fatalf("the trusted pin moved from %q to %q", c.pin, pin)
	}
}

// A repair that cannot write the file fails; it never reports ok while
// verify would fail.
func TestGAP1928RepairFailsWhenItCannotPutBackCodexRequirements(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	c := newCodexHealHost(t, "linux")
	c.write(t, c.want+"# tampered\n")
	dir := filepath.Dir(c.env.P(codexRequirements))
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	repair := c.run(Options{Action: ActionRepair})
	if repair.OK || len(repair.Errors) == 0 {
		t.Fatalf("repair returned ok while requirements.toml stayed tampered: %+v", repair)
	}
	// The connector it could not publish loses its pin; it never gets the
	// tampered view's.
	if pin := c.trustedPin(t); pin == c.observedView(t) {
		t.Fatalf("the failed repair pinned the tampered view %q", pin)
	}
	if verify := c.run(Options{Action: ActionVerify}); verify.OK {
		t.Fatal("verify passed a tampered requirements.toml")
	}
}

// codexWriteAfterPublish writes other bytes over requirements.toml right
// after the real publish, before the lifecycle pins the view.
type codexWriteAfterPublish struct {
	MachinePolicyManager
	path, data string
}

func (p *codexWriteAfterPublish) Publish(cfg *config.Config) (enterprisepolicy.Result, error) {
	result, err := p.MachinePolicyManager.Publish(cfg)
	if writeErr := os.WriteFile(p.path, []byte(p.data), 0o644); writeErr != nil {
		return result, writeErr
	}
	return result, err
}

// Ensure pins only the bytes its publish wrote: a file changed between the
// write and the pin is refused, not recorded as trusted.
func TestGAP1928EnsureNeverPinsCodexRequirementsChangedAfterPublish(t *testing.T) {
	c := newCodexHealHost(t, "linux")
	c.write(t, c.want+"# tampered\n")
	c.env.MachinePolicy = &codexWriteAfterPublish{MachinePolicyManager: c.env.MachinePolicy, path: c.env.P(codexRequirements), data: c.want + "# raced\n"}
	ensure := c.run(Options{Action: ActionEnsure})
	if ensure.OK {
		t.Fatalf("ensure returned ok after pinning a changed file: %+v", ensure)
	}
	if pin := c.trustedPin(t); pin != c.pin {
		t.Fatalf("ensure pinned the changed file: pin moved from %q to %q", c.pin, pin)
	}
}

// adminNote adds a comment to the administrator's text of a published
// requirements file, after DefenseClaw's managed settings block.
func adminNote(published string) string {
	const end = "# <<< DefenseClaw managed settings <<<\n"
	return strings.Replace(published, end, end+"# administrator note\n", 1)
}
