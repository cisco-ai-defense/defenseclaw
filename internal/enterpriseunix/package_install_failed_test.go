//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2359: a macOS pkg whose postinstall failed records no pkg receipt, and
// `ensure --from-package` adds none, so receipt-based MDM inventory kept
// reporting a healthy Mac as not installed. On macOS the package_install_failed
// warning must name installing the pkg again as the finish step.
func TestPackageInstallFailedNamesTheFinishStepPerOS(t *testing.T) {
	for _, tc := range []struct{ goos, want, not string }{
		{"linux", "fix that, then finish the install with `", "install the package again"},
		{"darwin", "fix that, then install the package again, which also records the pkg receipt", "fix that, then finish the install with"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			h := newTestHost(t, tc.goos)
			dir := h.env.P(h.env.Layout.LifecycleDir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			last := `{"ok":false,"action":"ensure","errors":[{"code":"config_invalid","message":"rule pack missing"}]}`
			if err := os.WriteFile(filepath.Join(dir, lastPackageResultFile), []byte(last), 0o600); err != nil {
				t.Fatal(err)
			}
			got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codePackageInstallFailed)
			if !strings.Contains(got, "config_invalid: rule pack missing") || !strings.Contains(got, tc.want) || strings.Contains(got, tc.not) {
				t.Fatalf("package_install_failed warning = %q, want %q and not %q", got, tc.want, tc.not)
			}
			if !strings.Contains(got, "ensure --from-package") {
				t.Fatalf("package_install_failed warning must still name ensure --from-package: %q", got)
			}
		})
	}
}

// GAP-2380: after a failed first pkg install, verify's unmanaged_leftovers
// warning still said to activate the deployment with `ensure --from-package
// --config <file>`, beside the package_install_failed warning that says to
// install the pkg again (ensure records no receipt), and that warning opened
// with "the package was installed" although pkgutil has no receipt.
func TestFailedPkgInstallVerifyNextStepsAgree(t *testing.T) {
	h := newTestHost(t, "darwin")
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	last := `{"ok":false,"action":"ensure","errors":[{"code":"config_invalid","message":"rule pack missing"}]}`
	if err := os.WriteFile(filepath.Join(dir, lastPackageResultFile), []byte(last), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, h.env.Layout.DescriptorPath, "{}")
	r := h.run(Options{Action: ActionVerify})
	failed := messagesOf(r.Warnings, codePackageInstallFailed)
	if strings.Contains(failed, "the package was installed") || !strings.Contains(failed, "no pkg receipt") {
		t.Fatalf("package_install_failed warning = %q", failed)
	}
	leftovers := messagesOf(r.Warnings, codeLeftovers)
	if leftovers == "" || strings.Contains(leftovers, "--config <file>") || !strings.Contains(leftovers, "as the "+codePackageInstallFailed+" warning says") {
		t.Fatalf("unmanaged_leftovers warning = %q, want it to defer to the %s advice", leftovers, codePackageInstallFailed)
	}
}

// dnf remove after a first rpm install that failed (config_invalid, rolled
// back) left the rejected config.yaml, the state and log folders, the
// lifecycle result, an empty drop-in folder and the service account: the
// package scriptlet runs uninstall, which found no deployment and did
// nothing (GAP-0421).
func TestUninstallAfterAFailedPackageInstallRemovesItsLeftovers(t *testing.T) {
	h := packageHost(t, "1.0.0")
	h.runner.replies = map[string]fakeReply{"rpm -qf --quiet " + filepath.Join(h.env.Layout.BinDir, binGateway): {}}
	if _, err := h.env.Accounts.Ensure(context.Background(), h.env.Layout.ServiceUser); err != nil {
		t.Fatal(err)
	}
	dropin := "/etc/systemd/system/" + unitGuardian + ".d"
	for _, dir := range []string{h.env.Layout.DataDir, h.env.Layout.LogDir, h.env.Layout.GuardianAuthDir, dropin} {
		if err := os.MkdirAll(h.env.P(dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	writeHostFile(t, h, h.env.Layout.ConfigPath, "config_version: 9\ngateway:\n  api_port: 18971\n")
	writeHostFile(t, h, filepath.Join(h.env.Layout.LifecycleDir, lastPackageResultFile),
		`{"ok":false,"action":"ensure","errors":[{"code":"config_invalid","message":"gateway.api_port must be 18970"}]}`)
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	for _, path := range []string{h.env.Layout.ConfigDir, h.env.Layout.DataDir, h.env.Layout.LogDir, h.env.Layout.GuardianAuthDir, h.env.Layout.LifecycleDir, dropin} {
		if exists(h.env.P(path)) {
			t.Errorf("the uninstall after a failed package install left %s", path)
		}
	}
	if _, ok, _ := h.env.Accounts.Lookup(context.Background(), h.env.Layout.ServiceUser); ok {
		t.Error("the uninstall after a failed package install left the service account")
	}
	if !exists(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))) {
		t.Error("the uninstall removed binaries the package owns")
	}
}

// The same on macOS: the Jamf uninstall script answered noop not_installed
// (with the finish step of GAP-2410) and left bin, the rejected
// etc/config.yaml and lifecycle (GAP-0567).
func TestMacOSUninstallAfterAFailedFirstPackageInstallRemovesItsLeftovers(t *testing.T) {
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
	writeHostFile(t, h, h.env.Layout.ConfigPath, "config_version: 9\ngateway:\n  api_port: 18971\n")
	writeHostFile(t, h, filepath.Join(h.env.Layout.LifecycleDir, lastPackageResultFile),
		`{"ok":false,"action":"ensure","errors":[{"code":"config_invalid","message":"gateway.api_port 18971 must be 18970"}]}`)
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	if r.Noop || exists(h.env.P(h.env.Layout.InstallRoot)) {
		t.Fatalf("the uninstall after a failed first pkg install left %s (noop=%v)", h.env.Layout.InstallRoot, r.Noop)
	}
}

// A failed package run the host recovered from out of band (systemd started
// the gateway again) left its result and the kept gateway output in place:
// ensure --from-package then found the host healthy and did nothing
// (GAP-0174).
func TestHealthyNoopEnsureFromPackageClearsTheFailedPackageResult(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	dir := h.env.P(h.env.Layout.LifecycleDir)
	leftovers := []string{filepath.Join(dir, lastPackageResultFile), filepath.Join(dir, lastPackageLogFile), h.env.activationFailurePath()}
	failed := `{"ok":false,"action":"ensure","errors":[{"code":"activation_failed","message":"gateway exited"}]}`
	for _, path := range leftovers {
		if err := os.WriteFile(path, []byte(failed), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := h.run(Options{Action: ActionEnsure, FromPackage: true})
	requireOK(t, r)
	if !r.Noop {
		t.Fatalf("ensure --from-package on a healthy host was not a no-op: %+v", r.Changes)
	}
	for _, path := range leftovers {
		if exists(path) {
			t.Fatalf("a healthy no-op ensure --from-package left %s", filepath.Base(path))
		}
	}
}

// A package upgrade whose activation was rolled back left

// last-package-result.json at ok:false after ensure recovered the host
// (GAP-0151), and last-activation-failure.log with it (GAP-0162). A later run
// that commits a deployment removes both; the package's own run leaves the
// result to its shell, which writes the document after the lifecycle
// returns.
func TestRecoveringRunClearsTheFailedPackageResult(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	last := filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lastPackageResultFile)
	failed := `{"ok":false,"action":"ensure","errors":[{"code":"activation_failed","message":"gateway exited"}]}`
	if err := os.WriteFile(last, []byte(failed), 0o600); err != nil {
		t.Fatal(err)
	}
	activation := h.env.activationFailurePath()
	if err := os.WriteFile(activation, []byte("gateway exited"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), Reason: "package"}))
	if !exists(last) {
		t.Fatal("the package's own run removed the result its shell writes")
	}
	if exists(activation) {
		t.Fatal("a committed run left the kept output of the failed activation in place")
	}
	if err := os.WriteFile(activation, []byte("gateway exited"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.2")}))
	if exists(last) || exists(activation) {
		t.Fatal("a recovering run left the failed package result or the kept activation output in place")
	}
}
