//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const testGatewayPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.cisco.secureclient.defenseclaw</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`

func notFoundExitError(t *testing.T) error {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "exit 113").Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("could not build an exit error: %v", err)
	}
	return err
}

// fakeLaunchctl records launchctl calls and answers from its fields.
type fakeLaunchctl struct {
	mu       sync.Mutex
	calls    []string
	disabled string
	loaded   map[string]bool
	notFound error
}

func (fake *fakeLaunchctl) run(args ...string) ([]byte, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls = append(fake.calls, strings.Join(args, " "))
	switch args[0] {
	case "print-disabled":
		return []byte(fake.disabled), nil
	case "print":
		if fake.loaded[strings.TrimPrefix(args[1], "system/")] {
			return []byte("state = running"), nil
		}
		return nil, fake.notFound
	}
	return nil, nil
}

func (fake *fakeLaunchctl) called(prefix string) bool {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, call := range fake.calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

type launchdHealFixture struct {
	layout   managed.ManagedServiceLayout
	plist    string
	launchd  *fakeLaunchctl
	btm      string
	now      time.Time
	canonDir string
}

func newLaunchdHealFixture(t *testing.T) *launchdHealFixture {
	t.Helper()
	layout := managedTestLayout(t)
	fixture := &launchdHealFixture{
		layout:  layout,
		launchd: &fakeLaunchctl{loaded: map[string]bool{}, notFound: notFoundExitError(t)},
		now:     time.Unix(1_800_000_000, 0),
	}
	daemons := t.TempDir()
	logs := filepath.Join(t.TempDir(), "Cisco", "SecureClient", "DefenseClaw")
	previous := struct {
		daemons, logs string
		run           func(...string) ([]byte, error)
		btm           func() ([]byte, error)
		now           func() time.Time
		grace         time.Duration
		state         *managedLaunchdHealState
	}{managedLaunchDaemonsDir, managedLogDir, launchctlRunner, btmDumpRunner, managedHealNow, managedPeerAbsentGrace, managedLaunchdHeal}
	t.Cleanup(func() {
		managedLaunchDaemonsDir, managedLogDir = previous.daemons, previous.logs
		launchctlRunner, btmDumpRunner, managedHealNow = previous.run, previous.btm, previous.now
		managedPeerAbsentGrace, managedLaunchdHeal = previous.grace, previous.state
	})
	managedLaunchDaemonsDir, managedLogDir = daemons, logs
	launchctlRunner = fixture.launchd.run
	btmDumpRunner = func() ([]byte, error) { return []byte(fixture.btm), nil }
	managedHealNow = func() time.Time { return fixture.now }
	managedLaunchdHeal = &managedLaunchdHealState{}

	fixture.canonDir = filepath.Join(layout.Home, "etc", "launchd")
	mkdirMode(t, fixture.canonDir, 0o755)
	fixture.writeCanonical(t, testGatewayPlist)
	fixture.plist = filepath.Join(daemons, managedGatewayLabel+".plist")
	if err := os.WriteFile(fixture.plist, []byte(testGatewayPlist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.plist, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{managedGatewayLabel, managedEnumeratorLabel} {
		fixture.launchd.loaded[label] = true
	}
	return fixture
}

func (fixture *launchdHealFixture) writeCanonical(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(fixture.canonDir, managedGatewayLabel+".plist")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	if err := os.WriteFile(path+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+filepath.Base(path)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// heal runs one pass, past the throttle.
func (fixture *launchdHealFixture) heal() {
	fixture.now = fixture.now.Add(time.Hour)
	healManagedLaunchdPlatform(managedServiceGuardian, fixture.layout)
}

func TestGuardianHealsGatewayPlistDrift(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	edited := strings.Replace(testGatewayPlist, "  <key>KeepAlive</key>\n  <true/>\n", "", 1)
	if err := os.WriteFile(fixture.plist, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.plist, 0o664); err != nil {
		t.Fatal(err)
	}
	addACL(t, fixture.plist, "everyone allow write")
	chflags(t, "uchg", fixture.plist)

	fixture.heal()

	data, err := os.ReadFile(fixture.plist)
	if err != nil || string(data) != testGatewayPlist {
		t.Fatalf("plist content not restored: %q %v", data, err)
	}
	if got := modeOf(t, fixture.plist); got != 0o644 {
		t.Fatalf("plist mode = %04o, want 0644", got)
	}
	var restored string
	for _, line := range markers() {
		if strings.HasPrefix(line, managed.MarkerBoundary+" ") && strings.Contains(line, `action="restored"`) {
			restored = line
		}
	}
	if !strings.Contains(restored, `changed_keys="KeepAlive"`) {
		t.Fatalf("markers = %q, want a boundary line naming KeepAlive", markers())
	}
	if countMarker(markers(), managed.MarkerRepair) < 1 {
		t.Fatalf("markers = %q, want the metadata repair", markers())
	}
}

func TestGuardianReenablesAndBootstrapsGateway(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	fixture.launchd.disabled = "disabled services = {\n\t\"" + managedGatewayLabel + "\" => disabled\n\t\"com.apple.other\" => enabled\n}\n"
	fixture.launchd.loaded[managedGatewayLabel] = false
	managedPeerAbsentGrace = 90 * time.Second

	fixture.heal()
	if !fixture.launchd.called("enable system/" + managedGatewayLabel) {
		t.Fatalf("calls = %v, want launchctl enable", fixture.launchd.calls)
	}
	if fixture.launchd.called("bootstrap") {
		t.Fatal("bootstrapped on the first unloaded observation, inside the grace period")
	}
	fixture.heal()
	if !fixture.launchd.called("bootstrap system " + fixture.plist) {
		t.Fatalf("calls = %v, want launchctl bootstrap after the grace period", fixture.launchd.calls)
	}
	found := false
	for _, line := range markers() {
		if strings.Contains(line, `reason="launchd_disabled_override"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("markers = %q, want a launchd_disabled_override repair", markers())
	}
}

func TestBackgroundItemsDisableIsReportedNotOverridden(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	fixture.btm = ` #1:
                 UUID: 1
                 Name: defenseclaw-gateway
          Disposition: [disabled, allowed, visible, notified] (0x2)
           Identifier: 16.` + managedGatewayLabel + `
                  URL: file:///Library/LaunchDaemons/` + managedGatewayLabel + `.plist
`
	fixture.launchd.disabled = "\"" + managedGatewayLabel + "\" => disabled\n"
	fixture.launchd.loaded[managedGatewayLabel] = false
	managedPeerAbsentGrace = 0

	fixture.heal()
	fixture.heal()
	if fixture.launchd.called("enable") || fixture.launchd.called("bootstrap") {
		t.Fatalf("calls = %v; a Background Items disable must not be overridden", fixture.launchd.calls)
	}
	prereqs := 0
	for _, line := range markers() {
		if strings.HasPrefix(line, managed.MarkerPrereq+" ") && strings.Contains(line, "launchd_background_item_disabled") {
			prereqs++
		}
	}
	if prereqs != 1 {
		t.Fatalf("markers = %q, want one prerequisite line for the streak", markers())
	}
}

func TestPlistHealWithoutCanonicalCopyRepairsMetadataOnly(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	if err := os.RemoveAll(fixture.canonDir); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(testGatewayPlist, "<true/>", "<false/>", 1)
	if err := os.WriteFile(fixture.plist, []byte(edited), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.plist, 0o666); err != nil {
		t.Fatal(err)
	}
	fixture.heal()
	if got := modeOf(t, fixture.plist); got != 0o644 {
		t.Fatalf("plist mode = %04o, want 0644", got)
	}
	if data, _ := os.ReadFile(fixture.plist); string(data) != edited {
		t.Fatal("content was changed without a verified canonical copy")
	}
	found := false
	for _, line := range markers() {
		if strings.HasPrefix(line, managed.MarkerAccept+" ") && strings.Contains(line, "plist content not verified") {
			found = true
		}
	}
	if !found {
		t.Fatalf("markers = %q, want a content-not-verified line", markers())
	}
}

func TestTamperedCanonicalCopyIsNeverUsed(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	canonical := filepath.Join(fixture.canonDir, managedGatewayLabel+".plist")
	if err := os.WriteFile(canonical, []byte(strings.Replace(testGatewayPlist, "defenseclaw-gateway", "evil", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(testGatewayPlist, "<true/>", "<false/>", 1)
	if err := os.WriteFile(fixture.plist, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.heal()
	if data, _ := os.ReadFile(fixture.plist); string(data) != edited {
		t.Fatal("a canonical copy that fails its digest was used")
	}
	if countMarker(markers(), managed.MarkerBoundary) < 1 {
		t.Fatalf("markers = %q, want a boundary line for the canonical copy", markers())
	}
}

func TestSymlinkedPlistIsReplacedNeverFollowed(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	victim := filepath.Join(t.TempDir(), "victim.plist")
	writeMode(t, victim, 0o666)
	if err := os.Remove(fixture.plist); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, fixture.plist); err != nil {
		t.Fatal(err)
	}
	managedPeerAbsentGrace = 0
	fixture.heal()
	fixture.heal()
	if got := modeOf(t, victim); got != 0o666 {
		t.Fatalf("symlink target re-stamped to %04o", got)
	}
	if data, _ := os.ReadFile(victim); string(data) != "x" {
		t.Fatal("symlink target content changed")
	}
	info, err := os.Lstat(fixture.plist)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("plist not replaced by a regular file: %v %v", info, err)
	}
	if data, _ := os.ReadFile(fixture.plist); string(data) != testGatewayPlist {
		t.Fatal("plist not restored from the canonical copy")
	}
	if countMarker(markers(), managed.MarkerBoundary) < 1 {
		t.Fatalf("markers = %q", markers())
	}
}

func TestMissingPeerPlistWaitsOutTheGraceBeforeRestore(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	captureMarkers(t)
	if err := os.Remove(fixture.plist); err != nil {
		t.Fatal(err)
	}
	managedPeerAbsentGrace = 90 * time.Second
	fixture.heal()
	if _, err := os.Lstat(fixture.plist); !os.IsNotExist(err) {
		t.Fatal("a plist removed moments ago (an uninstall in progress) was restored at once")
	}
	fixture.heal()
	if data, err := os.ReadFile(fixture.plist); err != nil || string(data) != testGatewayPlist {
		t.Fatalf("plist not restored after the grace period: %v", err)
	}
}

func TestLogFolderRecreatedAndRestamped(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	markers := captureMarkers(t)
	fixture.heal()
	info, err := os.Stat(managedLogDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
		t.Fatalf("log folder not recreated: %v %v", info, err)
	}
	errLog := filepath.Join(managedLogDir, "gateway.err.log")
	writeMode(t, errLog, 0o666)
	chflags(t, "uchg", errLog)
	victim := filepath.Join(t.TempDir(), "victim")
	writeMode(t, victim, 0o666)
	if err := os.Symlink(victim, filepath.Join(managedLogDir, "hook-guardian.err.log")); err != nil {
		t.Fatal(err)
	}
	fixture.heal()
	if got := modeOf(t, errLog); got != 0o640 {
		t.Fatalf("log file mode = %04o, want 0640", got)
	}
	var st = mustStatFlags(t, errLog)
	if st&0x2 != 0 {
		t.Fatal("uchg still set on the log file")
	}
	if got := modeOf(t, victim); got != 0o666 {
		t.Fatal("symlinked log target re-stamped")
	}
	if _, err := os.Lstat(filepath.Join(managedLogDir, "hook-guardian.err.log")); !os.IsNotExist(err) {
		t.Fatal("symlinked log file was not moved aside")
	}
	if countMarker(markers(), managed.MarkerRepair) < 2 {
		t.Fatalf("markers = %q", markers())
	}
}

func mustStatFlags(t *testing.T, path string) uint32 {
	t.Helper()
	output, err := exec.Command("/usr/bin/stat", "-f", "%Xf", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	var flags uint32
	for _, c := range strings.TrimSpace(string(output)) {
		flags <<= 4
		switch {
		case c >= '0' && c <= '9':
			flags |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			flags |= uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			flags |= uint32(c-'A') + 10
		}
	}
	return flags
}

func TestServiceLogRotationCopiesAndTruncates(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	captureMarkers(t)
	previous := managedLogRotateSize
	t.Cleanup(func() { managedLogRotateSize = previous })
	managedLogRotateSize = 16
	fixture.heal()
	log := filepath.Join(managedLogDir, "hook-guardian.err.log")
	for round, content := range []string{"first generation of output\n", "second generation of output\n"} {
		if err := os.WriteFile(log, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.heal()
		if info, _ := os.Stat(log); info.Size() != 0 {
			t.Fatalf("round %d: live log not truncated: %d bytes", round, info.Size())
		}
		if data, _ := os.ReadFile(log + ".1"); string(data) != content {
			t.Fatalf("round %d: .1 = %q", round, data)
		}
	}
	if data, _ := os.ReadFile(log + ".2"); string(data) != "first generation of output\n" {
		t.Fatalf(".2 = %q", data)
	}
}

func TestParseLaunchctlDisabled(t *testing.T) {
	got := parseLaunchctlDisabled([]byte("disabled services = {\n\t\"a\" => disabled\n\t\"b\" => enabled\n\t\"c\" => true\n\t\"d\" => false\n}\n"))
	want := map[string]bool{"a": true, "b": false, "c": true, "d": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
}

func TestParseBackgroundItemsDisabled(t *testing.T) {
	output := ` #1:
           Disposition: [enabled, allowed, visible, notified] (0x1)
            Identifier: 16.` + managedGuardianLabel + `
 #2:
           Disposition: [enabled, disallowed, visible, notified] (0x0)
                   URL: file:///Library/LaunchDaemons/` + managedEnumeratorLabel + `.plist
 #3:
           Disposition: [disabled, allowed, visible, notified] (0x2)
            Identifier: 16.com.example.other
`
	got := parseBackgroundItemsDisabled([]byte(output), []string{managedGatewayLabel, managedGuardianLabel, managedEnumeratorLabel})
	want := map[string]bool{managedGuardianLabel: false, managedEnumeratorLabel: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
}

func TestManagedRestartLedger(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var ledger managedServiceStartLedger
	for i := 0; i < managedRestartLoopThreshold-1; i++ {
		ledger.record(now.Add(time.Duration(i) * 10 * time.Second))
	}
	if ledger.inLoop(now.Add(time.Minute)) {
		t.Fatal("two starts counted as a loop")
	}
	ledger.record(now.Add(time.Minute))
	if !ledger.inLoop(now.Add(time.Minute)) {
		t.Fatal("three rapid starts not counted as a loop")
	}
	if ledger.inLoop(now.Add(managedRestartLoopWindow + 2*time.Minute)) {
		t.Fatal("old starts still counted")
	}
	if managedRestartHoldDelay(3) != managedRestartHoldMinDelay || managedRestartHoldDelay(50) != managedRestartHoldMaxDelay {
		t.Fatal("hold delay bounds wrong")
	}
}

// A deterministic failure that would loop under launchd keeps the process
// up: one degraded line per cause, a repair, then an in-place re-exec.
func TestRestartLoopHoldsInsteadOfExiting(t *testing.T) {
	layout := managedTestLayout(t)
	markers := captureMarkers(t)
	mkdirMode(t, layout.RuntimeDir, 0o750)
	previous := struct {
		reexec func() error
		delay  func(int) time.Duration
	}{managedServiceReexec, managedRestartHoldDelayFor}
	t.Cleanup(func() { managedServiceReexec, managedRestartHoldDelayFor = previous.reexec, previous.delay })
	managedRestartHoldDelayFor = func(int) time.Duration { return time.Millisecond }
	reexecs := 0
	managedServiceReexec = func() error { reexecs++; return nil }

	cause := errors.New("observability bootstrap failed")
	if holdManagedServiceAfterFailurePlatform(context.Background(), managedServiceGateway, cause) {
		t.Fatal("held without a restart loop")
	}
	for i := 0; i < managedRestartLoopThreshold; i++ {
		noteManagedServiceStartPlatform(managedServiceGateway)
	}
	if !holdManagedServiceAfterFailurePlatform(context.Background(), managedServiceGateway, cause) || reexecs != 1 {
		t.Fatalf("held = false or reexecs = %d, want one in-place re-exec", reexecs)
	}
	noteManagedServiceStartPlatform(managedServiceGateway)
	holdManagedServiceAfterFailurePlatform(context.Background(), managedServiceGateway, cause)
	if got := countMarker(markers(), managed.MarkerDegraded); got != 1 {
		t.Fatalf("degraded lines = %d, want one for the same cause: %q", got, markers())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	managedRestartHoldDelayFor = func(int) time.Duration { return time.Hour }
	if !holdManagedServiceAfterFailurePlatform(ctx, managedServiceGateway, errors.New("other cause")) {
		t.Fatal("a stopped hold did not report a clean stop")
	}
	if holdManagedServiceAfterFailurePlatform(context.Background(), managedServiceNone, cause) {
		t.Fatal("a non-service command was held")
	}
}

func TestChangedPlistKeys(t *testing.T) {
	edited := strings.Replace(testGatewayPlist, "  <key>RunAtLoad</key>\n  <true/>\n", "", 1)
	edited = strings.Replace(edited, "bin/defenseclaw-gateway", "bin/other", 1)
	got := changedPlistKeys([]byte(edited), []byte(testGatewayPlist))
	if !reflect.DeepEqual(got, []string{"ProgramArguments", "RunAtLoad"}) {
		t.Fatalf("changed keys = %v", got)
	}
	if got := changedPlistKeys([]byte("not xml"), []byte(testGatewayPlist)); !reflect.DeepEqual(got, []string{"unparseable"}) {
		t.Fatalf("unparseable = %v", got)
	}
}

func TestGuardianPassSweepsInstallTreeAndThrottles(t *testing.T) {
	fixture := newLaunchdHealFixture(t)
	captureMarkers(t)
	previous := enterpriseHookInstallSweepLast
	t.Cleanup(func() { enterpriseHookInstallSweepLast = previous })
	enterpriseHookInstallSweepLast = time.Time{}
	bin := filepath.Join(fixture.layout.Home, "bin")
	mkdirMode(t, bin, 0o775)
	gateway := filepath.Join(bin, "defenseclaw-gateway")
	writeMode(t, gateway, 0o777)
	chflags(t, "uchg", gateway)

	repairEnterpriseHookManagedInstallPlatform()
	if modeOf(t, bin) != 0o755 || modeOf(t, gateway) != 0o755 {
		t.Fatalf("install tree modes = %04o %04o, want 0755", modeOf(t, bin), modeOf(t, gateway))
	}
	if modeOf(t, fixture.layout.RuntimeDir) != 0o750 {
		t.Fatal("the pass did not recreate the runtime folder")
	}
	if err := os.Chmod(gateway, 0o777); err != nil {
		t.Fatal(err)
	}
	repairEnterpriseHookManagedInstallPlatform()
	if modeOf(t, gateway) != 0o777 {
		t.Fatal("a pass inside the sweep interval swept again")
	}
}
