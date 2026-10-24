// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// writeLegacyWindowsScannerRuntimeAdmission writes the schema 1 record
// DefenseClaw 1.0.3 wrote, which an --allow-unsigned certification install
// wrote alike for its unsigned scanner, naming path's digest.
func writeLegacyWindowsScannerRuntimeAdmission(t *testing.T, root, path string) (record, digest string) {
	t.Helper()
	digest, err := windowsEnterpriseFileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	record = filepath.Join(root, managed.StandaloneWindowsScannerRuntimeAdmissionName)
	body := `{"schema_version":1,"sha256":"` + digest + `","admitted_at":"2026-10-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return record, digest
}

// legacyWindowsScannerRuntimeAdmits is the check a DefenseClaw 1.0.3 gateway
// makes before it runs the scanner: the record in root names the SHA-256 of
// path, whatever its schema or trust.
func legacyWindowsScannerRuntimeAdmits(t *testing.T, root, path string) bool {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeAdmissionName))
	if errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		t.Fatal(err)
	}
	var record struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(body, &record) != nil || record.SHA256 == "" {
		return false
	}
	digest, err := windowsEnterpriseFileSHA256(path)
	return err == nil && digest == record.SHA256
}

// W2B-G-win review loops 1 to 3: on 1.0.3 an --allow-unsigned
// certification install published its unsigned scanner and a schema 1
// admission record into the shared production runtime. Since round 3 a
// certification run leaves that folder alone, so its uninstall no longer
// removed the scanner and the production gateway kept running it. Every
// mutating certification run that succeeds, of every scope, checks such a
// record against the production deployment's own trust settings, never this
// run's. One they prove, the record of a signed production scanner, stays
// byte-identical (round 2). Every other one is quarantined, and a 1.0.3
// gateway refuses the scanner then too: one they refuse, and one they
// cannot prove, which round 2 left for the 1.0.3 gateway to run (an unsigned
// scanner under a hash-pinned production deployment, which may be the
// certification install's own, and trust settings or files that cannot be
// read; round 3). A failed run, whatever made it fail, changes no shared
// record at all, as a failed run left the runtime before 1.0.4: it
// quarantined the record of a healthy signed 1.0.3 production scanner whose
// signer the config does not pin (fifth review loop, round 1). It never
// touches a record that proves a production admission, makes no lock file
// unless it quarantines, and status and verify stay read-only.
func TestWindowsScannerRuntimeCertificationRunQuarantinesAnUnprovenAdmission(t *testing.T) {
	root, runtimeFile := newWindowsScannerRuntimeRemovalTest(t)
	aclSeam, authenticodeSeam, signersSeam := windowsScannerRuntimeACLCheck, windowsScannerRuntimeAuthenticode, windowsScannerRuntimeProductionSigners
	deploymentSeam := windowsScannerRuntimeDeployment
	t.Cleanup(func() {
		windowsScannerRuntimeACLCheck, windowsScannerRuntimeAuthenticode, windowsScannerRuntimeProductionSigners = aclSeam, authenticodeSeam, signersSeam
		windowsScannerRuntimeDeployment = deploymentSeam
	})
	var (
		aclErr, signersErr, deploymentErr error
		signed                            bool
		signers                           []string
		deployment                        winpath.EnterpriseDeployment
	)
	certificate := []byte("production signer certificate")
	windowsScannerRuntimeACLCheck = func(string, string) error { return aclErr }
	windowsScannerRuntimeAuthenticode = func(string) (string, []byte, error) {
		if !signed {
			return "", nil, errors.New("no valid signature")
		}
		return "Cisco Systems, Inc.", certificate, nil
	}
	windowsScannerRuntimeProductionSigners = func() ([]string, error) { return signers, signersErr }
	windowsScannerRuntimeDeployment = func(opts *windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
		if opts != nil {
			t.Fatal("a certification run read the deployment record as its own")
		}
		return deployment, deploymentErr
	}
	thumbprint := sha256.Sum256(certificate)
	pin := hex.EncodeToString(thumbprint[:])
	installed := func(trust string) winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.3", TrustMode: trust,
			Profile: managed.ProfileStandalone, MetadataPath: `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`}
	}
	scopes := map[string]func(*windowsEnterpriseLifecycleOptions){
		"state root": func(o *windowsEnterpriseLifecycleOptions) {
			o.stateRoot = `C:\ProgramData\Cisco\DefenseClaw-Cert\r1\state`
		},
		"install root": func(o *windowsEnterpriseLifecycleOptions) {
			o.installRoot = `C:\Program Files\Cisco\DefenseClaw-Cert\r1`
		},
		"gateway service name": func(o *windowsEnterpriseLifecycleOptions) { o.gatewayServiceName = "DefenseClawGatewayCert1" },
		"guardian service":     func(o *windowsEnterpriseLifecycleOptions) { o.guardianServiceName = "DefenseClawGuardianCert1" },
		"allow unsigned":       func(o *windowsEnterpriseLifecycleOptions) { o.allowUnsigned = true },
		"codex home":           func(o *windowsEnterpriseLifecycleOptions) { o.certificationCodexHome = `C:\dc-cert\codex-home` },
	}
	// The ways a certification lifecycle run fails before its scanner step:
	// before it changes its own deployment (a refusal, a busy lock, an
	// installer that cannot start) and after it changed some of it.
	failures := []struct{ code, message string }{
		{"installer_launch_failed", "the installer could not be started"},
		{"elevation_required", "run this from an elevated prompt"},
		{"lifecycle_busy", "another DefenseClaw lifecycle run holds the lock"},
		{"invalid_arguments", "the certification scope is not exact"},
		{"installer_failed", "the installer stopped after it replaced the gateway service"},
	}
	run := func(name, action string, failure int) *enterprisestatus.Result {
		opts := &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4"}
		scopes[name](opts)
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed = action != "uninstall"
		if failure >= 0 {
			result.AddError(failures[failure].code, failures[failure].message)
		}
		applyWindowsStandaloneScannerRuntime(result, opts)
		return result
	}
	warning := func(result *enterprisestatus.Result, code string) string {
		for _, w := range result.Warnings {
			if w.Code == code {
				return w.Message
			}
		}
		return ""
	}
	lock := filepath.Join(root, windowsScannerRuntimeLockName)
	const (
		kept = iota
		quarantined
	)
	for _, tc := range []struct {
		name             string
		setup            func()
		changed, missing bool
		want             int
		reason           string
	}{
		{name: "signed by the signer production pins", setup: func() { signed, signers, deployment = true, []string{pin}, installed("authenticode") }, want: kept},
		{name: "signed by a pinned signer, hash-pinned production", want: kept,
			setup: func() {
				signed, signers, deployment = true, []string{pin, strings.Repeat("0", 64)}, installed("hash_pinned")
			}},
		{name: "signed by a pinned signer, production trust not recorded", want: kept,
			setup: func() { signed, signers, deployment = true, []string{pin}, installed("") }},
		// Third review loop, round 1: production pinned its signer with
		// --allowed-signer alone, which nothing records, so a config that
		// pins none (or no config) proves no signed scanner: it may be a
		// certification install's, from a signer production does not pin.
		{name: "signed, production config pins no signer", want: quarantined, reason: "cannot prove the signer",
			setup: func() { signed, signers, deployment = true, []string{}, installed("authenticode") }},
		{name: "signed, no production config", want: quarantined, reason: "cannot prove the signer",
			setup: func() { signed, deployment = true, installed("authenticode") }},
		{name: "signed, hash-pinned production, config pins no signer", want: quarantined, reason: "cannot prove the signer",
			setup: func() { signed, deployment = true, installed("hash_pinned") }},
		{name: "signed, production trust not recorded, config pins no signer", want: quarantined, reason: "cannot prove the signer",
			setup: func() { signed, deployment = true, installed("") }},
		{name: "signed by a signer production does not pin", want: quarantined, reason: "does not pin",
			setup: func() {
				signed, signers, deployment = true, []string{strings.Repeat("0", 64)}, installed("authenticode")
			}},
		{name: "unsigned, authenticode production", setup: func() { deployment = installed("authenticode") }, want: quarantined,
			reason: "admits only Authenticode-signed payloads"},
		{name: "unsigned, hash-pinned production", setup: func() { deployment = installed("hash_pinned") }, want: quarantined,
			reason: "cannot prove it"},
		{name: "unsigned, production trust not recorded", setup: func() { deployment = installed("") }, want: quarantined,
			reason: "cannot prove it"},
		{name: "no production deployment", want: quarantined, reason: "no production deployment is installed",
			setup: func() {
				signed, deployment = true, winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentAbsent}
			}},
		{name: "production uninstalled", want: quarantined, reason: "no production deployment is installed",
			setup: func() {
				signed, deployment = true, winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone}
			}},
		{name: "production record unreadable", want: quarantined, reason: "cannot be read",
			setup: func() {
				signed, deployment = true, winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentUnknown}
			}},
		{name: "production record read fails", want: quarantined, reason: "read the production deployment record",
			setup: func() { signed, deploymentErr = true, errors.New("access denied") }},
		{name: "production signer pins unreadable", want: quarantined, reason: "read the production signer pins",
			setup: func() {
				signed, signersErr, deployment = true, errors.New("config is writable by Users"), installed("authenticode")
			}},
		{name: "folder fails the trust check", want: quarantined, reason: "Users can write",
			setup: func() {
				signed, aclErr, deployment = true, errors.New("Users can write the runtime folder"), installed("authenticode")
			}},
		{name: "executable changed since its record", changed: true, want: quarantined, reason: "is not the executable its record names",
			setup: func() { signed, deployment = true, installed("authenticode") }},
		{name: "executable missing", missing: true, want: quarantined, reason: "hash ",
			setup: func() { signed, deployment = true, installed("authenticode") }},
	} {
		for name := range scopes {
			for i, action := range []string{"install", "upgrade", "repair", "ensure", "uninstall"} {
				for _, failure := range []int{-1, i % len(failures), (i + 2) % len(failures)} {
					failed := failure >= 0
					label := fmt.Sprintf("%s: %s %s (failure=%d)", tc.name, name, action, failure)
					aclErr, signersErr, deploymentErr, signed, signers, deployment = nil, nil, nil, false, nil, winpath.EnterpriseDeployment{}
					tc.setup()
					if err := os.Remove(lock); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
					if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
						t.Fatal(err)
					}
					record, _ := writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
					if tc.changed {
						if err := os.WriteFile(runtimeFile, []byte("another program"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if tc.missing {
						if err := os.Remove(runtimeFile); err != nil {
							t.Fatal(err)
						}
					}
					before, err := os.ReadFile(record)
					if err != nil {
						t.Fatal(err)
					}
					result := run(name, action, failure)
					if windowsEnterpriseResultHasError(result, "scanner_runtime_admission_unproven") {
						t.Fatalf("%s: errors %+v", label, result.Errors)
					}
					if _, err := os.Stat(runtimeFile); err != nil && !tc.missing {
						t.Fatalf("%s removed the production runtime: %v", label, err)
					}
					after, readErr := os.ReadFile(record)
					switch {
					case failed:
						// A failed run leaves the shared record as it found it,
						// whatever production trust says of it.
						if readErr != nil || string(after) != string(before) {
							t.Fatalf("%s: a failed certification run changed the production admission record (%v): %q", label, readErr, after)
						}
						if !tc.missing && !tc.changed && !legacyWindowsScannerRuntimeAdmits(t, root, runtimeFile) {
							t.Fatalf("%s: after a failed certification run a 1.0.3 gateway no longer runs the production scanner", label)
						}
						if len(result.Warnings) != 0 || len(result.Errors) != 1 || result.Errors[0].Code != failures[failure].code {
							t.Fatalf("%s: a failed run reported the scanner step: errors %+v warnings %+v", label, result.Errors, result.Warnings)
						}
						if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("%s: a failed certification run made a lock file in the production runtime (%v)", label, err)
						}
					case tc.want == quarantined:
						if !errors.Is(readErr, os.ErrNotExist) {
							t.Fatalf("%s kept the record production trust refuses (%v): the production gateway still runs the scanner it names", label, readErr)
						}
						if message := warning(result, "scanner_runtime_admission_quarantined"); !strings.Contains(message, tc.reason) {
							t.Fatalf("%s: quarantine warning %q, want the reason %q", label, message, tc.reason)
						}
						if err := managed.CheckScannerRuntimeAdmitted(root, runtimeFile); !tc.missing && !errors.Is(err, managed.ErrScannerRuntimeNotAdmitted) {
							t.Fatalf("%s: the scanner is still admitted: %v", label, err)
						}
						if legacyWindowsScannerRuntimeAdmits(t, root, runtimeFile) {
							t.Fatalf("%s: a 1.0.3 gateway still runs the scanner the record named", label)
						}
					default:
						if readErr != nil || string(after) != string(before) {
							t.Fatalf("%s changed a record production trust does not refuse (%v): %q", label, readErr, after)
						}
						if message := warning(result, "scanner_runtime_admission_quarantined"); message != "" {
							t.Fatalf("%s: %s", label, message)
						}
						if !legacyWindowsScannerRuntimeAdmits(t, root, runtimeFile) {
							t.Fatalf("%s: a 1.0.3 gateway no longer runs the production scanner", label)
						}
						if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("%s made a lock file in the production runtime (%v)", label, err)
						}
					}
				}
			}
		}
	}
	aclErr, signersErr, deploymentErr, signed, signers, deployment = nil, nil, nil, false, nil, installed("authenticode")
	// The last case may have removed the executable.
	if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name := range scopes {
		for _, action := range []string{"status", "verify"} {
			record, _ := writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
			result := run(name, action, -1)
			if _, err := os.Lstat(record); err != nil || windowsEnterpriseResultHasWarning(result, "scanner_runtime_admission_quarantined") {
				t.Fatalf("%s %s is read-only but quarantined the record (%v)", name, action, err)
			}
		}
	}
	// A record that proves a production admission is the production
	// deployment's: no certification run changes it or makes a lock file.
	if err := os.Remove(lock); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	digest, err := windowsEnterpriseFileSHA256(runtimeFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeAdmissionName)
	want, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for name := range scopes {
		for _, action := range []string{"install", "uninstall"} {
			result := run(name, action, -1)
			got, err := os.ReadFile(record)
			if err != nil || string(got) != string(want) || len(result.Errors) != 0 ||
				windowsEnterpriseResultHasWarning(result, "scanner_runtime_admission_quarantined") {
				t.Fatalf("%s %s changed a production admission record (%v): %q, errors %+v", name, action, err, got, result.Errors)
			}
			if _, err := os.Lstat(lock); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s %s made a lock file in the production runtime (%v)", name, action, err)
			}
		}
	}
}

// W2B-G-win review loop round 2: the installer accepts a root or service
// name override only as an exact certification scope or as the exact
// production layout, and runs the production lifecycle for the latter. An
// override that names the production layout (in any spelling the installer
// resolves to it) is therefore a production run: its upgrade, repair, ensure
// or install installs and proves the scanner runtime. Before, any non-empty
// override skipped the scanner step, and a 1.0.3 host's schema 1 record was
// quarantined, so scans failed closed after a successful upgrade.
func TestWindowsScannerRuntimeExplicitProductionLayoutIsAProductionRun(t *testing.T) {
	rootsSeam := windowsEnterpriseProductionRoots
	t.Cleanup(func() { windowsEnterpriseProductionRoots = rootsSeam })
	const install, state = `C:\Program Files\Cisco\DefenseClaw`, `C:\ProgramData\Cisco\DefenseClaw`
	windowsEnterpriseProductionRoots = func() (string, string, error) { return install, state, nil }
	certInstall, certState := `C:\Program Files\Cisco\DefenseClaw-Cert\0123456789`, `C:\ProgramData\Cisco\DefenseClaw-Cert\0123456789`
	for name, tc := range map[string]struct {
		opts          windowsEnterpriseLifecycleOptions
		certification bool
	}{
		"install root":                         {opts: windowsEnterpriseLifecycleOptions{installRoot: install}},
		"state root":                           {opts: windowsEnterpriseLifecycleOptions{stateRoot: state}},
		"state root, other case and separator": {opts: windowsEnterpriseLifecycleOptions{stateRoot: `c:\programdata\cisco\defenseclaw\`}},
		"state root, forward slashes":          {opts: windowsEnterpriseLifecycleOptions{stateRoot: `C:/ProgramData/Cisco/DefenseClaw`}},
		"state root, dot segments":             {opts: windowsEnterpriseLifecycleOptions{stateRoot: `C:\ProgramData\Cisco\DefenseClaw-Cert\..\DefenseClaw\.`}},
		"gateway service name":                 {opts: windowsEnterpriseLifecycleOptions{gatewayServiceName: "DefenseClawGateway"}},
		"gateway service name, other case":     {opts: windowsEnterpriseLifecycleOptions{gatewayServiceName: "defenseclawgateway"}},
		"guardian service name":                {opts: windowsEnterpriseLifecycleOptions{guardianServiceName: "DefenseClawHookGuardian"}},
		"every override": {opts: windowsEnterpriseLifecycleOptions{installRoot: install, stateRoot: state,
			gatewayServiceName: "DefenseClawGateway", guardianServiceName: "DefenseClawHookGuardian"}},
		"certification scope": {certification: true, opts: windowsEnterpriseLifecycleOptions{installRoot: certInstall, stateRoot: certState,
			gatewayServiceName: "DefenseClawCertGateway_0123456789", guardianServiceName: "DefenseClawCertGuardian_0123456789"}},
		"certification state root":                    {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: certState}},
		"production root, certification gateway":      {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: state, gatewayServiceName: "DefenseClawCertGateway_0123456789"}},
		"production names, another install root":      {certification: true, opts: windowsEnterpriseLifecycleOptions{installRoot: `D:\DefenseClaw`, gatewayServiceName: "DefenseClawGateway"}},
		"a folder below the production state root":    {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: state + `\cert`}},
		"a sibling with the production prefix":        {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: state + `-Cert`}},
		"production layout, --allow-unsigned":         {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: state, allowUnsigned: true}},
		"production layout, certification Codex home": {certification: true, opts: windowsEnterpriseLifecycleOptions{stateRoot: state, certificationCodexHome: `C:\dc-cert\codex`}},
	} {
		opts := tc.opts
		if got := windowsScannerRuntimeCertificationRun(&opts); got != tc.certification {
			t.Errorf("%s: certification run = %v, want %v", name, got, tc.certification)
		}
	}
	windowsEnterpriseProductionRoots = func() (string, string, error) { return "", "", errors.New("no known folder") }
	if !windowsScannerRuntimeCertificationRun(&windowsEnterpriseLifecycleOptions{stateRoot: state}) {
		t.Error("an override was taken for the production layout while the production roots could not be resolved")
	}
	windowsEnterpriseProductionRoots = func() (string, string, error) { return install, state, nil }

	// The whole run from the installed CLI on an upgraded 1.0.3 host: the
	// schema 1 record of the payload-pinned scanner is proven and recorded
	// as a production admission, as without the overrides, and the run is
	// not reported as a certification scope.
	root, runtimeFile := newWindowsScannerRuntimeRemovalTest(t)
	aclSeam, sourceSeam, authenticodeSeam := windowsScannerRuntimeACLCheck, windowsScannerSourceCheck, windowsScannerRuntimeAuthenticode
	readerSeam, serviceSeam := windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeACLCheck, windowsScannerSourceCheck, windowsScannerRuntimeAuthenticode = aclSeam, sourceSeam, authenticodeSeam
		windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck = readerSeam, serviceSeam
	})
	windowsScannerRuntimeACLCheck = func(string, string) error { return nil }
	windowsScannerSourceCheck = func(string, string) error { return nil }
	windowsScannerRuntimeAuthenticode = func(string) (string, []byte, error) { return "", nil, errors.New("no valid signature") }
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime { return &enterprisestatus.ScannerRuntime{State: "ready"} }
	windowsScannerRuntimeServiceCheck = func() error { return nil }
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4", TrustMode: "hash_pinned"}
	})
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		for name, set := range map[string]func(*windowsEnterpriseLifecycleOptions){
			"state root":   func(o *windowsEnterpriseLifecycleOptions) { o.stateRoot = state },
			"install root": func(o *windowsEnterpriseLifecycleOptions) { o.installRoot = install },
			"service names": func(o *windowsEnterpriseLifecycleOptions) {
				o.gatewayServiceName, o.guardianServiceName = "DefenseClawGateway", "DefenseClawHookGuardian"
			},
		} {
			_, digest := writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
			opts := &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4", trustMode: windowsEnterpriseTrustHashPinned,
				payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: digest}}
			set(opts)
			result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
			result.Installed = true
			applyWindowsStandaloneScannerRuntime(result, opts)
			if got, err := managed.ReadScannerRuntimeAdmission(root); err != nil || got != digest {
				t.Fatalf("%s with the production %s: the pinned scanner was not proven (%q, %v); warnings %+v", action, name, got, err, result.Warnings)
			}
			if windowsEnterpriseResultHasWarning(result, "scanner_runtime_not_scoped") ||
				windowsEnterpriseResultHasWarning(result, "scanner_runtime_admission_quarantined") ||
				len(result.Errors) != 0 || result.Scanners == nil || result.Scanners.State != "ready" {
				t.Fatalf("%s with the production %s skipped the scanner step: scanners %+v errors %+v warnings %+v",
					action, name, result.Scanners, result.Errors, result.Warnings)
			}
		}
	}
}

// W2B-G-win review loop round 1: a production repair or ensure from the
// installed CLI meets a schema 1 admission record before it runs the
// scanner. It records the executable again as a production admission only
// when the runtime passes the trust check, the executable still has the
// recorded digest and this run's payload trust policy admits it; any other
// record is quarantined, so the scanner is not run (prepare included) until
// a production /repair admits the payload copy. A run whose deployment is
// no longer installed leaves the record to the run that owns the runtime.
func TestWindowsScannerRuntimeProductionRunProvesOrQuarantinesAnUnprovenAdmission(t *testing.T) {
	root, runtimeFile := newWindowsScannerRuntimeRemovalTest(t)
	aclSeam, sourceSeam := windowsScannerRuntimeACLCheck, windowsScannerSourceCheck
	t.Cleanup(func() { windowsScannerRuntimeACLCheck, windowsScannerSourceCheck = aclSeam, sourceSeam })
	windowsScannerSourceCheck = func(string, string) error { return nil }
	aclErr := error(nil)
	windowsScannerRuntimeACLCheck = func(string, string) error { return aclErr }
	deployment := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment { return deployment })
	digest, err := windowsEnterpriseFileSHA256(runtimeFile)
	if err != nil {
		t.Fatal(err)
	}
	pinned := func(pin string) *windowsEnterpriseLifecycleOptions {
		return &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4", trustMode: windowsEnterpriseTrustHashPinned,
			payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: pin}}
	}
	authenticode := &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4", trustMode: windowsEnterpriseTrustAuthenticode}
	for _, tc := range []struct {
		name       string
		opts       *windowsEnterpriseLifecycleOptions
		acl        error
		changed    bool
		quarantine string
	}{
		{name: "unsigned, authenticode", opts: authenticode, quarantine: "not admitted by the standalone payload trust policy"},
		{name: "not pinned", opts: pinned(strings.Repeat("0", 64)), quarantine: "not admitted by the standalone payload trust policy"},
		{name: "changed since its record", opts: pinned(""), changed: true, quarantine: "is not the executable its record names"},
		{name: "untrusted folder", opts: pinned(digest), acl: errors.New("Users can write the runtime folder"), quarantine: "Users can write"},
		{name: "pinned by this payload", opts: pinned(digest)},
	} {
		if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
			t.Fatal(err)
		}
		record, _ := writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
		if tc.changed {
			if err := os.WriteFile(runtimeFile, []byte("another program"), 0o600); err != nil {
				t.Fatal(err)
			}
			changed, err := windowsEnterpriseFileSHA256(runtimeFile)
			if err != nil {
				t.Fatal(err)
			}
			tc.opts.payloadPins[managed.StandaloneWindowsScannerRuntimeName] = changed
		}
		aclErr = tc.acl
		why, err := settleUnprovenWindowsScannerRuntimeAdmission("repair", tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.quarantine == "" {
			if got, err := managed.ReadScannerRuntimeAdmission(root); err != nil || got != digest || why != "" {
				t.Fatalf("%s: the pinned executable was not recorded as a production admission: %q, %v (%s)", tc.name, got, err, why)
			}
			continue
		}
		if _, err := os.Lstat(record); !errors.Is(err, os.ErrNotExist) || !strings.Contains(why, tc.quarantine) {
			t.Fatalf("%s: record kept (%v) or reason %q, want it quarantined because %q", tc.name, err, why, tc.quarantine)
		}
	}
	aclErr = nil

	// The whole repair from the installed CLI: the unsigned scanner is not
	// prepared (run) and the run says why.
	if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeAdmissionName)
	for _, action := range []string{"repair", "ensure"} {
		writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4", trustMode: windowsEnterpriseTrustAuthenticode})
		if _, err := os.Lstat(record); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s kept the unproven record: %v", action, err)
		}
		if strings.Contains(fmt.Sprint(result.Errors), "could not be prepared") || result.Scanners == nil || result.Scanners.State != "untrusted" ||
			!windowsEnterpriseResultHasWarning(result, "scanner_runtime_admission_quarantined") ||
			!windowsEnterpriseResultHasWarning(result, "scanner_runtime_unavailable") {
			t.Fatalf("%s ran or accepted the unproven scanner: scanners %+v errors %+v warnings %+v", action, result.Scanners, result.Errors, result.Warnings)
		}
	}

	// Not this run's deployment any more: left to the run that owns it.
	for _, later := range []winpath.EnterpriseDeployment{
		{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.5"},
		{State: winpath.EnterpriseDeploymentTombstone},
	} {
		deployment = later
		record, _ := writeLegacyWindowsScannerRuntimeAdmission(t, root, runtimeFile)
		if why, err := settleUnprovenWindowsScannerRuntimeAdmission("repair", authenticode); err != nil || why != "" {
			t.Fatalf("%+v: %q, %v", later, why, err)
		}
		if _, err := os.Lstat(record); err != nil {
			t.Fatalf("%+v: a superseded run changed the record: %v", later, err)
		}
	}
}

// W2B-G-win review loop round 1: a production install, upgrade, repair or
// ensure with a staged payload settles a schema 1 record before it admits
// the staged copy, so a staged copy the trust policy refuses does not leave
// the unproven record (and the unsigned scanner it names) behind.
func TestWindowsScannerRuntimeStagedRunQuarantinesAnUnprovenAdmission(t *testing.T) {
	root, installer, _ := stageWindowsScannerRuntimeTest(t)
	aclSeam := windowsScannerRuntimeACLCheck
	t.Cleanup(func() { windowsScannerRuntimeACLCheck = aclSeam })
	windowsScannerRuntimeACLCheck = func(string, string) error { return nil }
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}
	})
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		if err := os.WriteFile(target, []byte("unsigned certification scanner"), 0o755); err != nil {
			t.Fatal(err)
		}
		record, _ := writeLegacyWindowsScannerRuntimeAdmission(t, root, target)
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.4")
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer,
			trustMode: windowsEnterpriseTrustAuthenticode, productVersion: "1.0.4"})
		if _, err := os.Lstat(record); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s kept the unproven record beside a refused staged copy: %v", action, err)
		}
		if !windowsEnterpriseResultHasError(result, "scanner_runtime_unavailable") {
			t.Fatalf("%s: errors %+v, want the staged copy refused", action, result.Errors)
		}
	}
}
