//go:build !windows

package enterpriseunix

import (
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

// GAP-2410: uninstall (no --purge) after a failed first pkg install found
// nothing to remove and still said to activate the deployment with `ensure
// --from-package --config <file>`; it gives the finish step status and
// verify give: install the pkg again, for its receipt.
func TestFailedPkgInstallUninstallNoopNextStepsAgree(t *testing.T) {
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
	r := h.run(Options{Action: ActionUninstall})
	if !r.Noop || r.NoopReason != "not_installed" {
		t.Fatalf("uninstall noop=%v reason=%q, want a not_installed no-op", r.Noop, r.NoopReason)
	}
	if failed := messagesOf(r.Warnings, codePackageInstallFailed); !strings.Contains(failed, "install the package again") {
		t.Fatalf("package_install_failed warning = %q", failed)
	}
	leftovers := messagesOf(r.Warnings, codeLeftovers)
	if leftovers == "" || strings.Contains(leftovers, "--config <file>") || !strings.Contains(leftovers, "as the "+codePackageInstallFailed+" warning says") {
		t.Fatalf("unmanaged_leftovers warning = %q, want it to defer to the %s advice", leftovers, codePackageInstallFailed)
	}
}

// GAP-1116: after a refused package apply an administrator applied the
// package with `ensure --from-package --allow-downgrade`, the deployment
// was healthy, and last-package-result.json still said ok: false for the
// newer build. An ensure --from-package outside the install script now
// records its own result there; the script's own run (--reason package)
// leaves the file to the script.
func TestEnsureFromPackageRecordsTheLastPackageResult(t *testing.T) {
	h := packageHost(t, "1.0.0")
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, lastPackageResultFile)
	stale := `{"ok":false,"action":"ensure","installed_version":"1.0.1","errors":[{"code":"downgrade_refused","message":"payload version 1.0.0 is older than the installed 1.0.1"}]}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	if data, _ := os.ReadFile(path); string(data) != stale {
		t.Fatalf("the install script's own run rewrote its result file: %s", data)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, AllowDowngrade: true}))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); !strings.Contains(got, `"ok": true`) || !strings.Contains(got, `"installed_version": "1.0.0"`) || strings.Contains(got, "downgrade_refused") {
		t.Fatalf("last-package-result.json after a successful ensure --from-package:\n%s", got)
	}
}
