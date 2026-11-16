// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

func coworkTestFile(t *testing.T, h *testHost, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(h.env.P(path)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(path), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for current := path; ; current = filepath.Dir(current) {
		h.owners[h.env.P(current)] = [2]int{0, 0}
		if current == "/" {
			break
		}
	}
}

func coworkTestConfig(t *testing.T, h *testHost, mode string, signed bool) config.EnterpriseCoworkVMSensorConfig {
	t.Helper()
	// These are existing system-owned ancestors on a real Mac. The fake
	// filesystem creates them as the unprivileged Go test runner.
	if err := os.MkdirAll(h.env.P("/Library/Application Support"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/Library", "/Library/Application Support"} {
		h.owners[h.env.P(path)] = [2]int{0, 0}
	}
	for path := filepath.Dir(h.env.Layout.InstallRoot); path != "/"; path = filepath.Dir(path) {
		h.owners[h.env.P(path)] = [2]int{0, 0}
	}
	c := config.EnterpriseCoworkVMSensorConfig{
		Mode: mode, Tenant: "tenant_1", Device: "device-42", Collector: "edr.example.test:443",
		Vendor: "testvendor", SourceDir: "/staged-cowork",
	}
	name, err := h.env.coworkPackageName()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(c.SourceDir, name)
	coworkTestFile(t, h, archive, "release archive "+h.env.GOARCH)
	if signed {
		coworkTestFile(t, h, archive+".sig", "detached test signature")
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(h.read(h.env.Layout.ConfigPath)), &document); err != nil {
		t.Fatal(err)
	}
	block := map[string]any{
		"mode": mode, "tenant": c.Tenant, "device": c.Device, "collector": c.Collector,
		"vendor": c.Vendor, "source_dir": c.SourceDir,
	}
	// Approved release digests, rather than trusting a source-directory name.
	block["package_sha256"], _ = sha256File(h.env.P(archive))
	if signed {
		block["signature_sha256"], _ = sha256File(h.env.P(archive + ".sig"))
	}
	document["enterprise"].(map[string]any)["cowork_vm_sensor"] = block
	body, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), body, 0o640); err != nil {
		t.Fatal(err)
	}
	return c
}

func coworkTestProfile(t *testing.T, h *testHost, c config.EnterpriseCoworkVMSensorConfig, path string, values map[string]string) {
	t.Helper()
	if values == nil {
		name, _ := h.env.coworkPackageName()
		values = map[string]string{"coworkEDRIntegration": filepath.Join(macCoworkDir, name), "coworkEDRIntegrationVendor": c.Vendor}
	}
	coworkTestFile(t, h, path, "managed preferences test input")
	body, _ := json.Marshal(values)
	if h.runner.replies == nil {
		h.runner.replies = map[string]fakeReply{}
	}
	h.runner.replies["plutil -convert json -o - -- "+h.env.P(path)] = fakeReply{result: CommandResult{Stdout: body}}
}

func TestCoworkMacLifecycle(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			h.env.GOARCH = arch
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			c := coworkTestConfig(t, h, "on", true)
			coworkTestProfile(t, h, c, macCoworkPreferences, nil)
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			name, _ := h.env.coworkPackageName()
			dest := filepath.Join(macCoworkDir, name)
			if got := h.read(dest); got != "release archive "+arch {
				t.Fatalf("wrong architecture delivered: %q", got)
			}
			if got := h.read(dest + ".args"); got != "tenant=tenant_1,device=device-42,collector=edr.example.test:443" {
				t.Fatalf("arguments (must be ASCII, no BOM or newline): %q", got)
			}
			for _, suffix := range []string{"", ".args", ".sig"} {
				if h.mode(dest+suffix) != 0o644 || h.owners[h.env.P(dest+suffix)][0] != 0 {
					t.Fatalf("unsafe delivered metadata: %s", dest+suffix)
				}
			}
			again := h.run(Options{Action: ActionEnsure})
			requireOK(t, again)
			if !again.Noop {
				t.Fatalf("repeated ensure changed files: %+v", again.Changes)
			}
			verify := h.run(Options{Action: ActionVerify})
			if verify.CoworkVMSensor == nil || !verify.CoworkVMSensor.HostReady || !verify.CoworkVMSensor.SettingsReady || hasWarning(verify, codeCoworkIncomplete) {
				t.Fatalf("Cowork verify not ready: %+v, %+v", verify.CoworkVMSensor, verify.Warnings)
			}
			if err := os.WriteFile(h.env.P(dest+".args"), []byte("bad arguments"), 0o644); err != nil {
				t.Fatal(err)
			}
			damaged := h.run(Options{Action: ActionVerify})
			if damaged.OK || damaged.CoworkVMSensor.HostReady {
				t.Fatal("changed arguments passed verify")
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if got := h.read(dest + ".args"); strings.HasPrefix(got, "bad") {
				t.Fatal("repair did not restore arguments")
			}
			if err := os.Chmod(h.env.P(macCoworkDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if r := h.run(Options{Action: ActionVerify}); r.OK || r.CoworkVMSensor.HostReady {
				t.Fatal("untraversable Cowork folder passed verify")
			}
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			if h.mode(macCoworkDir) != 0o755 {
				t.Fatal("ensure did not restore directory traversal")
			}
			// An administrator's later replacement remains when disabled.
			if err := os.WriteFile(h.env.P(dest), []byte("administrator replacement"), 0o644); err != nil {
				t.Fatal(err)
			}
			coworkTestConfig(t, h, "off", true)
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			if got := h.read(dest); got != "administrator replacement" {
				t.Fatal("disable removed an administrator's replacement")
			}
			for _, suffix := range []string{".args", ".sig"} {
				if exists(h.env.P(dest + suffix)) {
					t.Fatalf("disable left owned file %s", dest+suffix)
				}
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !exists(h.env.P(dest)) || !exists(h.env.P(macCoworkPreferences)) {
				t.Fatal("uninstall removed administrator or MDM state")
			}
		})
	}
}

func TestCoworkMacRollbackAndUninstallRemoveOnlyOwnedFiles(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	h.services.failReloadOnce = true
	failed := h.run(Options{Action: ActionEnsure})
	if failed.OK || !hasWarning(failed, codeRolledBack) {
		t.Fatalf("failure did not roll back: %+v", failed)
	}
	name, _ := h.env.coworkPackageName()
	dest := filepath.Join(macCoworkDir, name)
	if exists(h.env.P(dest)) || exists(h.env.P(dest+".args")) || exists(h.env.P(dest+".sig")) {
		t.Fatal("rollback left delivery files")
	}
	// Restore the approved request after rollback restored the committed config.
	coworkTestConfig(t, h, "on", true)
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	unknown := filepath.Join(macCoworkDir, "administrator.txt")
	coworkTestFile(t, h, unknown, "keep")
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if exists(h.env.P(dest)) || exists(h.env.P(dest+".args")) || exists(h.env.P(dest+".sig")) || !exists(h.env.P(unknown)) || !exists(h.env.P(macCoworkPreferences)) {
		t.Fatal("uninstall removed administrator state or left unchanged owned files")
	}
}

func TestCoworkDisabledDoesNoDeliveryWorkOnAnyUnixPlatform(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		e := &Env{GOOS: goos, Trust: func(string, TrustKind) error { return errors.New("off path must not probe") }}
		l := &lifecycle{env: e}
		p := &plan{config: &validatedConfig{Loaded: &config.Config{}}}
		if err := l.planCoworkVM(p, nil); err != nil || len(p.files) != 0 || len(p.dirs) != 0 {
			t.Fatalf("%s off path did work: %v", goos, err)
		}
		p.config.Loaded.Enterprise.CoworkVMSensor.Mode = "on"
		if goos == "linux" {
			if err := l.planCoworkVM(p, nil); errorCode(err, "") != codeCoworkUnsupported {
				t.Fatalf("Linux mode on = %v, want %s", err, codeCoworkUnsupported)
			}
		}
	}
}

// Linux has no Cowork VM host delivery: ensure refuses mode on with its own
// code (not payload_invalid) and status names the platform.
func TestCoworkLinuxModeOnRefusedWithItsOwnCode(t *testing.T) {
	h := newTestHost(t, "linux")
	h.env.GOARCH = "amd64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	coworkTestConfig(t, h, "on", true)
	r := h.run(Options{Action: ActionEnsure})
	requireError(t, r, codeCoworkUnsupported)
	if messagesOf(r.Errors, codePayload) != "" {
		t.Fatalf("Linux mode on also reported %s: %+v", codePayload, r.Errors)
	}
	coworkTestConfig(t, h, "on", true)
	status := h.run(Options{Action: ActionStatus})
	if status.CoworkVMSensor == nil || !status.CoworkVMSensor.Enabled || status.CoworkVMSensor.HostReady ||
		!slices.Contains(status.CoworkVMSensor.ReasonCodes, "platform_unsupported") {
		t.Fatalf("Linux status: %+v", status.CoworkVMSensor)
	}
}

// ensureNoop's read-only plan must not report a kept administrator file:
// only the plan that removes files does, once.
func TestCoworkMacKeptReplacementWarnsOncePerEnsure(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	dest := filepath.Join(macCoworkDir, "defenseclaw-cowork-arm64.tar.gz")
	if err := os.WriteFile(h.env.P(dest), []byte("administrator replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	coworkTestConfig(t, h, "off", true)
	r := h.run(Options{Action: ActionEnsure})
	requireOK(t, r)
	kept := 0
	for _, warning := range r.Warnings {
		if warning.Code == codeCoworkIncomplete && strings.Contains(warning.Message, "kept "+dest) {
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("kept replacement reported %d times: %+v", kept, r.Warnings)
	}
	again := h.run(Options{Action: ActionEnsure})
	requireOK(t, again)
	if !again.Noop || hasWarning(again, codeCoworkIncomplete) {
		t.Fatalf("compliant ensure after disable: noop=%v warnings=%+v", again.Noop, again.Warnings)
	}
}

func TestCoworkMacMissingSignatureAndMDMRemainIncomplete(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	coworkTestConfig(t, h, "on", false)
	// Staging succeeds while the production signing key and MDM arrive.
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.CoworkVMSensor == nil || r.CoworkVMSensor.HostReady || r.CoworkVMSensor.SettingsReady || !hasWarning(r, codeCoworkIncomplete) || r.CoverageComplete {
			t.Fatalf("%s claimed coverage: %+v", action, r)
		}
		if action == ActionVerify && r.OK {
			t.Fatal("verify must fail while enabled delivery is incomplete")
		}
	}
}

func TestCoworkMacRefusesUnownedDestinationAndUnsafeSource(t *testing.T) {
	for _, unsafe := range []string{"unowned destination", "writable source", "symlink source", "wrong architecture"} {
		t.Run(unsafe, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			h.env.GOARCH = "arm64"
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			c := coworkTestConfig(t, h, "on", true)
			archive := c.SourceDir + "/defenseclaw-cowork-arm64.tar.gz"
			switch unsafe {
			case "unowned destination":
				coworkTestFile(t, h, macCoworkDir+"/defenseclaw-cowork-arm64.tar.gz", "admin file")
			case "writable source":
				if err := os.Chmod(h.env.P(c.SourceDir), 0o777); err != nil {
					t.Fatal(err)
				}
			case "symlink source":
				if err := os.Rename(h.env.P(archive), h.env.P(archive+".original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(h.env.P(archive+".original"), h.env.P(archive)); err != nil {
					t.Fatal(err)
				}
			case "wrong architecture":
				h.env.GOARCH = "386"
			}
			if r := h.run(Options{Action: ActionEnsure}); r.OK {
				t.Fatal("unsafe delivery was accepted")
			}
		})
	}
}

func TestCoworkMacPerUserProfileOverride(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	coworkTestProfile(t, h, c, "/Library/Managed Preferences/testuser/com.anthropic.claudefordesktop.plist", map[string]string{"coworkEDRIntegrationVendor": "different"})
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	r := h.run(Options{Action: ActionVerify})
	if r.CoworkVMSensor == nil || r.CoworkVMSensor.SettingsReady || !strings.Contains(messagesOf(r.Warnings, codeCoworkIncomplete), "testuser") {
		t.Fatal("per-user override was not reported")
	}
}

func TestCoworkMacExplicitInputsSurviveWrapperScratchRemoval(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", false)
	name, _ := h.env.coworkPackageName()
	cache := filepath.Join(h.env.Layout.InstallRoot, "share", "cowork")
	update := func(key, value string) {
		t.Helper()
		var document map[string]any
		if err := yaml.Unmarshal([]byte(h.read(h.env.Layout.ConfigPath)), &document); err != nil {
			t.Fatal(err)
		}
		document["enterprise"].(map[string]any)["cowork_vm_sensor"].(map[string]any)[key] = value
		body, err := yaml.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), body, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	update("source_dir", cache)
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	input := h.env.P(filepath.Join(c.SourceDir, name))
	requireOK(t, h.run(Options{Action: ActionEnsure, CoworkPackage: input}))
	if err := os.RemoveAll(h.env.P(c.SourceDir)); err != nil {
		t.Fatal(err)
	}
	if !exists(h.env.P(filepath.Join(cache, name))) || h.mode(filepath.Join(cache, name)) != 0o600 {
		t.Fatal("explicit input was not retained in the private cache")
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	// A later key delivery supplies only the signature; the package stays cached.
	sig := "/signature-scratch/release.sig"
	coworkTestFile(t, h, sig, "new release signature")
	digest, _ := sha256File(h.env.P(sig))
	update("signature_sha256", digest)
	requireOK(t, h.run(Options{Action: ActionEnsure, CoworkSignature: h.env.P(sig)}))
	if err := os.RemoveAll(h.env.P("/signature-scratch")); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", ".sig"} {
		if !exists(h.env.P(filepath.Join(cache, name+suffix))) {
			t.Fatalf("signature-only update lost cached %s", name+suffix)
		}
	}
	if err := os.WriteFile(h.env.P(filepath.Join(macCoworkDir, name)), []byte("damaged delivery"), 0o644); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if got := h.read(filepath.Join(macCoworkDir, name)); got != "release archive arm64" {
		t.Fatal("repair depended on deleted MDM scratch")
	}
	verify := h.run(Options{Action: ActionVerify})
	if verify.CoworkVMSensor == nil || !verify.CoworkVMSensor.HostReady {
		t.Fatalf("cached delivery not ready: %+v", verify.Warnings)
	}
}

func TestCoworkMacExplicitInputValidationAndRollback(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", false)
	name, _ := h.env.coworkPackageName()
	input := h.env.P(filepath.Join(c.SourceDir, name))
	// Explicit input may not turn an arbitrary configured read-only source
	// directory into a lifecycle-owned write destination.
	if r := h.run(Options{Action: ActionEnsure, CoworkPackage: input}); r.OK {
		t.Fatal("accepted arbitrary cache destination")
	}
	coworkTestConfig(t, h, "on", false)
	cache := filepath.Join(h.env.Layout.InstallRoot, "share", "cowork")
	raw := strings.Replace(h.read(h.env.Layout.ConfigPath), "source_dir: /staged-cowork", "source_dir: "+cache, 1)
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	h.services.failReloadOnce = true
	if r := h.run(Options{Action: ActionEnsure, CoworkPackage: input}); r.OK || !hasWarning(r, codeRolledBack) {
		t.Fatalf("explicit input failure did not roll back: %+v", r)
	}
	if exists(h.env.P(filepath.Join(cache, name))) || exists(h.env.P(filepath.Join(macCoworkDir, name))) {
		t.Fatal("rollback retained cached or public new files")
	}
}

func TestCoworkMacNativeArchitectureProbe(t *testing.T) {
	for value, want := range map[string]string{"1\n": "arm64", "0\n": "amd64"} {
		runner := &fakeRunner{replies: map[string]fakeReply{"sysctl -in hw.optional.arm64": {result: CommandResult{Stdout: []byte(value)}}}}
		e := &Env{GOOS: "darwin", Runner: runner}
		name, err := e.coworkPackageName()
		if err != nil || name != "defenseclaw-cowork-"+want+".tar.gz" {
			t.Fatalf("native architecture = %s, %v", name, err)
		}
	}
}

// A fleet-wide config without device gives each Mac its IOPlatformUUID; a
// Mac that cannot report one refuses delivery instead of sharing an ID.
func TestCoworkMacDeviceDerivedFromIOPlatformUUID(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.env.GOARCH = "arm64"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	c := coworkTestConfig(t, h, "on", true)
	var document map[string]any
	if err := yaml.Unmarshal([]byte(h.read(h.env.Layout.ConfigPath)), &document); err != nil {
		t.Fatal(err)
	}
	delete(document["enterprise"].(map[string]any)["cowork_vm_sensor"].(map[string]any), "device")
	body, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), body, 0o640); err != nil {
		t.Fatal(err)
	}
	coworkTestProfile(t, h, c, macCoworkPreferences, nil)
	const ioreg = "ioreg -rd1 -c IOPlatformExpertDevice"
	h.runner.replies[ioreg] = fakeReply{err: errors.New("ioreg failed")}
	refused := h.run(Options{Action: ActionEnsure})
	requireError(t, refused, codeCoworkDeviceUnavailable)
	if messagesOf(refused.Errors, codePayload) != "" {
		t.Fatalf("device failure also reported %s: %+v", codePayload, refused.Errors)
	}
	h.runner.replies[ioreg] = fakeReply{result: CommandResult{Stdout: []byte("+-o J316sAP  <class IOPlatformExpertDevice>\n    {\n      \"IOPlatformSerialNumber\" = \"C02TEST\"\n      \"IOPlatformUUID\" = \"4C4C4544-0039-5410-8052-B4C04F4E4B32\"\n    }\n")}}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	dest := filepath.Join(macCoworkDir, "defenseclaw-cowork-arm64.tar.gz.args")
	if got := h.read(dest); got != "tenant=tenant_1,device=4C4C4544-0039-5410-8052-B4C04F4E4B32,collector=edr.example.test:443" {
		t.Fatalf("derived arguments: %q", got)
	}
	verify := h.run(Options{Action: ActionVerify})
	if verify.CoworkVMSensor == nil || !verify.CoworkVMSensor.HostReady {
		t.Fatalf("derived device verify: %+v %+v", verify.CoworkVMSensor, verify.Warnings)
	}
}

// GAP-0035: turning delivery off removes the folders DefenseClaw created for
// it (the lifecycle cache, the public Cowork folder and its Application
// Support parents) once they are empty, and keeps a folder an administrator
// created or put a file in.
func TestCoworkMacDisableRemovesTheFoldersDeliveryCreated(t *testing.T) {
	enable := func(t *testing.T, h *testHost) (config.EnterpriseCoworkVMSensorConfig, string) {
		t.Helper()
		c := coworkTestConfig(t, h, "on", true)
		cache := h.env.coworkCacheDir()
		raw := strings.Replace(h.read(h.env.Layout.ConfigPath), "source_dir: /staged-cowork", "source_dir: "+cache, 1)
		if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), []byte(raw), 0o640); err != nil {
			t.Fatal(err)
		}
		coworkTestProfile(t, h, c, macCoworkPreferences, nil)
		name, _ := h.env.coworkPackageName()
		archive := h.env.P(filepath.Join(c.SourceDir, name))
		requireOK(t, h.run(Options{Action: ActionEnsure, CoworkPackage: archive, CoworkSignature: archive + ".sig"}))
		if !exists(h.env.P(filepath.Join(cache, name))) || !exists(h.env.P(filepath.Join(macCoworkDir, name))) {
			t.Fatal("explicit delivery did not fill the cache and the Cowork folder")
		}
		return c, cache
	}
	disable := func(t *testing.T, h *testHost) {
		t.Helper()
		coworkTestConfig(t, h, "off", true)
		requireOK(t, h.run(Options{Action: ActionEnsure}))
	}
	owned := []string{"", macCoworkDir, "/Library/Application Support/Cisco/DefenseClaw", "/Library/Application Support/Cisco"}

	t.Run("created folders go", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		h.env.GOARCH = "arm64"
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		_, cache := enable(t, h)
		owned[0] = cache
		record, err := h.env.loadDeployment()
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range owned {
			if !slices.Contains(record.CreatedDirs, dir) {
				t.Fatalf("delivery did not record that it created %s: %v", dir, record.CreatedDirs)
			}
		}
		disable(t, h)
		for _, dir := range owned {
			if exists(h.env.P(dir)) {
				t.Fatalf("disable left the empty folder %s", dir)
			}
		}
		if !exists(h.env.P("/Library/Application Support")) || !exists(h.env.P(macCoworkPreferences)) {
			t.Fatal("disable removed a system folder or the MDM profile")
		}
		record, err = h.env.loadDeployment()
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range owned {
			if slices.Contains(record.CreatedDirs, dir) {
				t.Fatalf("record still names the removed folder %s", dir)
			}
		}
		if again := h.run(Options{Action: ActionEnsure}); !again.OK || !again.Noop {
			t.Fatalf("ensure after disable is not a noop: %+v", again.Changes)
		}
	})

	t.Run("administrator content and folders stay", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		h.env.GOARCH = "arm64"
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		// The administrator created the cache folder before delivery.
		cache := h.env.coworkCacheDir()
		if err := os.MkdirAll(h.env.P(cache), 0o700); err != nil {
			t.Fatal(err)
		}
		h.owners[h.env.P(cache)] = [2]int{0, 0}
		enable(t, h)
		note := filepath.Join(macCoworkDir, "admin-note.txt")
		coworkTestFile(t, h, note, "keep")
		disable(t, h)
		if !exists(h.env.P(cache)) {
			t.Fatal("disable removed a cache folder the administrator created")
		}
		if entries, _ := os.ReadDir(h.env.P(cache)); len(entries) != 0 {
			t.Fatalf("disable left DefenseClaw's cache files: %v", entries)
		}
		if h.read(note) != "keep" {
			t.Fatal("disable removed the administrator's file")
		}
		if again := h.run(Options{Action: ActionEnsure}); !again.OK || !again.Noop {
			t.Fatalf("ensure with a kept administrator folder is not a noop: %+v", again.Changes)
		}
		// Uninstall still leaves the administrator's file.
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		if h.read(note) != "keep" {
			t.Fatal("uninstall removed the administrator's file")
		}
	})
}
