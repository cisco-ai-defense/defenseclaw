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

// A package upgrade whose activation was rolled back left
// last-package-result.json at ok:false after ensure recovered the host
// (GAP-0151). A later run that commits a deployment removes it; the
// package's own run leaves the file to its shell, which writes the document
// after the lifecycle returns.
func TestRecoveringRunClearsTheFailedPackageResult(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	last := filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lastPackageResultFile)
	failed := `{"ok":false,"action":"ensure","errors":[{"code":"activation_failed","message":"gateway exited"}]}`
	if err := os.WriteFile(last, []byte(failed), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1"), Reason: "package"}))
	if !exists(last) {
		t.Fatal("the package's own run removed the result its shell writes")
	}
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.2")}))
	if exists(last) {
		t.Fatal("a recovering run left the failed package result in place")
	}
}
