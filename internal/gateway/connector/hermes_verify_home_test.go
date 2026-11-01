// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0499: Verify proves the hooks of the Hermes home the account's Hermes
// reads, or fails. A home that cannot be resolved left the generic reader
// with no config to read, and it reported the hooks present.
func TestHermesVerifyFailsWhenTheHermesHomeCannotBeResolved(t *testing.T) {
	previousOverride, previousResolver := HermesConfigPathOverride, hermesConfigPathResolver
	HermesConfigPathOverride = ""
	hermesConfigPathResolver = func() string { return "" }
	t.Cleanup(func() { HermesConfigPathOverride, hermesConfigPathResolver = previousOverride, previousResolver })

	dataDir := filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
	for _, managed := range []bool{false, true} {
		present, err := OwnedHooksPresent(NewHermesConnector(), SetupOpts{DataDir: dataDir, ManagedEnterprise: managed})
		if present || err == nil || !strings.Contains(err.Error(), "not verified") {
			t.Fatalf("managed=%v: OwnedHooksPresent = %v, %v; want an unverified error for an unresolved Hermes home", managed, present, err)
		}
	}
	if err := NewHermesConnector().VerifyClean(SetupOpts{DataDir: dataDir}); err == nil {
		t.Fatal("VerifyClean must not report an unresolved Hermes home clean")
	}
}

// GAP-0499: Hermes started without HERMES_HOME runs from the profile its
// active_profile selects. Hooks in the default profile do not guard it, so
// Verify fails instead of reporting the default profile's hooks.
func TestHermesVerifyFailsWhenHermesRunsANamedProfile(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after Setup = %v, %v; want present", present, err)
	}

	activeProfile := filepath.Join(filepath.Dir(configPath), "active_profile")
	if err := os.WriteFile(activeProfile, []byte("coder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if present || err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), `"coder"`) {
		t.Fatalf("OwnedHooksPresent with active profile coder = %v, %v; want an unverified error naming the profile", present, err)
	}
	if err := os.Remove(activeProfile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(configPath), "profiles", "coder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); present || err == nil {
		t.Fatalf("OwnedHooksPresent with a named profile = %v, %v; want unverified", present, err)
	}
}

// Hermes lists profiles/coder\n as a named profile (Python's $ matches
// before a final newline). After it appears, Verify (per user and managed)
// fails and Setup (the ensure, upgrade and repair path) refuses, so neither
// reports the default profile sealed while that profile runs unhooked.
func TestHermesVerifyAndSetupRefuseANamedProfileWithATrailingNewline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file names cannot hold a newline")
	}
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	profile := filepath.Join(filepath.Dir(configPath), "profiles", "coder\n")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "config.yaml"), []byte("model: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{false, true} {
		check := opts
		check.ManagedEnterprise = managed
		if present, err := OwnedHooksPresent(conn, check); present || err == nil {
			t.Fatalf("managed=%v: OwnedHooksPresent with profiles/coder\\n = %v, %v; want unverified", managed, present, err)
		}
	}
	if err := conn.Setup(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "named profile") {
		t.Fatalf("Setup with profiles/coder\\n = %v; want the named profile refused", err)
	}
}

// 'hermes profile delete' leaves profiles/.deleted behind. An intact
// default-profile registration stays verified, per user and managed, and a
// second Setup (the no-op ensure) succeeds without changing it.
func TestHermesVerifyAndEnsureAcceptDeletedProfileMetadata(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })

	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after Setup = %v, %v; want present", present, err)
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(configPath), "profiles", ".deleted", "coder"), 0o700); err != nil {
		t.Fatal(err)
	}
	registered, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{false, true} {
		check := opts
		check.ManagedEnterprise = managed
		if present, err := OwnedHooksPresent(conn, check); err != nil || !present {
			t.Fatalf("managed=%v: OwnedHooksPresent with profiles/.deleted = %v, %v; want present", managed, present, err)
		}
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup with profiles/.deleted: %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || string(after) != string(registered) {
		t.Fatalf("second Setup changed the registration (err %v)", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after the second Setup = %v, %v; want present", present, err)
	}
}

// GAP-0499: a service acting for an account (the managed guardian) sets up
// and verifies the Hermes home the account configured. When that home
// cannot be resolved, Setup refuses and Verify fails; only the lists of
// folders to watch or grant keep the profile default.
func TestManagedHermesSetupAndVerifyUseTheAccountsHermesHome(t *testing.T) {
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	home := filepath.Join(testenv.PrivateTempDir(t), "Users", "target")
	custom := filepath.Join(home, "hermes-work")
	defaultConfig := hermespath.ConfigPathForUserHome(home)
	dataDir := filepath.Join(home, ".defenseclaw")

	restore := hermespath.OverrideAccountHomeForTest(func(string) (string, error) { return custom, nil })
	var got string
	if err := WithUserHomeDir(home, func() error { got = hermesConfigPath(SetupOpts{}); return nil }); err != nil {
		t.Fatal(err)
	}
	restore()
	if want := filepath.Join(custom, "config.yaml"); got != want {
		t.Fatalf("managed Hermes config = %q, want the account's configured home %q, not the default %q", got, want, defaultConfig)
	}

	restore = hermespath.OverrideAccountHomeForTest(func(string) (string, error) {
		return "", errors.New("the registry hive is not loaded")
	})
	t.Cleanup(restore)
	if err := WithUserHomeDir(home, func() error {
		if err := NewHermesConnector().Setup(context.Background(), SetupOpts{DataDir: dataDir, ManagedEnterprise: true}); err == nil || !strings.Contains(err.Error(), "registry hive") {
			t.Errorf("Setup = %v, want a refusal naming why the home cannot be resolved", err)
		}
		present, err := OwnedHooksPresent(NewHermesConnector(), SetupOpts{DataDir: dataDir, ManagedEnterprise: true})
		if present || err == nil || !strings.Contains(err.Error(), "not verified") {
			t.Errorf("OwnedHooksPresent = %v, %v; want not verified", present, err)
		}
		if got := hermesConfigPath(SetupOpts{}); got != defaultConfig {
			t.Errorf("watch and grant lists use %q, want the profile default %q", got, defaultConfig)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Fatalf("a refused Setup must not write: %v", statErr)
	}
}

// GAP-0499: the guardian verifies the Hermes home it resolved for an
// account only while nothing names another one. A HERMES_HOME the
// DefenseClaw hooks recorded the account's agents running with, or (on
// Linux and macOS) one the account's environment.d sets, makes Verify fail
// instead of reporting the hooks of the resolved home.
func TestManagedHermesVerifyFailsWhenTheAccountNamesAnotherHermesHome(t *testing.T) {
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	root := testenv.PrivateTempDir(t)
	t.Cleanup(hermespath.OverrideAccountHomeForTest(nil))
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "Users", "target")
	other := filepath.Join(home, "work-hermes")
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(home, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	stubHermesAdmissionInstalledVersion(t)
	answerHermesProbeForTest(t)
	conn := NewHermesConnector()
	evidence := []struct{ name, file, body string }{
		{"recorded redirect", filepath.Join(home, ".defenseclaw", "foreign-hook-env.json"),
			`{"v":1,"connectors":{"claudecode":[{"vars":{"HERMES_HOME":"` + strings.ReplaceAll(other, `\`, `\\`) + `"}}]}}`},
	}
	if runtime.GOOS != "windows" {
		evidence = append(evidence, struct{ name, file, body string }{
			"environment.d", filepath.Join(home, ".config", "environment.d", "hermes.conf"), "HERMES_HOME=$HOME/work-hermes\n"})
	}
	if err := WithUserHomeDir(home, func() error {
		if err := conn.Setup(context.Background(), opts); err != nil {
			return err
		}
		if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Fatalf("OwnedHooksPresent after Setup = %v, %v; want present", present, err)
		}
		for _, tc := range evidence {
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(tc.file, []byte(tc.body), 0o600); err != nil {
				return err
			}
			present, err := OwnedHooksPresent(conn, opts)
			if present || err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), other) {
				t.Errorf("%s: OwnedHooksPresent = %v, %v; want not verified naming %s", tc.name, present, err, other)
			}
			if err := os.Remove(tc.file); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// GAP-2374: the Linux and macOS guardian verifies an account in a worker
// that runs with the account's uid and HOME, so the account home is the
// process home there. Managed Verify skipped the account's HERMES_HOME
// evidence for it and reported the hooks of ~/.hermes verified while the
// account's environment.d or a recorded redirect named another home. A
// per-user check, whose own environment is the account's, still resolves
// the home from that environment and reads no account evidence.
func TestManagedHermesVerifyRunAsTheAccountFailsWhenTheAccountNamesAnotherHermesHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows guardian verifies every account from the service, never as the account")
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	root := testenv.PrivateTempDir(t)
	t.Cleanup(hermespath.OverrideAccountHomeForTest(nil))
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "Users", "target")
	other := filepath.Join(home, "work-hermes")
	// The worker's process home is the account's (enterpriseHookWorkerEnvironment).
	t.Setenv("HOME", home)
	t.Setenv("HERMES_HOME", "")
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(home, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	stubHermesAdmissionInstalledVersion(t)
	answerHermesProbeForTest(t)
	conn := NewHermesConnector()
	managed, perUser := opts, opts
	managed.ManagedEnterprise = true
	evidence := []struct{ name, file, body string }{
		{"environment.d", filepath.Join(home, ".config", "environment.d", "hermes.conf"), "HERMES_HOME=" + other + "\n"},
		{"recorded redirect", filepath.Join(home, ".defenseclaw", "foreign-hook-env.json"),
			`{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":"` + other + `"}}]}}`},
	}
	if err := WithUserHomeDir(home, func() error {
		if err := conn.Setup(context.Background(), opts); err != nil {
			return err
		}
		if present, err := OwnedHooksPresent(conn, managed); err != nil || !present {
			t.Fatalf("managed OwnedHooksPresent after Setup = %v, %v; want present", present, err)
		}
		for _, tc := range evidence {
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(tc.file, []byte(tc.body), 0o600); err != nil {
				return err
			}
			present, err := OwnedHooksPresent(conn, managed)
			if present || err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), other) {
				t.Errorf("%s, managed check as the account: OwnedHooksPresent = %v, %v; want not verified naming %s", tc.name, present, err, other)
			}
			if present, err := OwnedHooksPresent(conn, perUser); err != nil || !present {
				t.Errorf("%s, per-user check: OwnedHooksPresent = %v, %v; want present (its own environment resolves the home)", tc.name, present, err)
			}
			if err := os.Remove(tc.file); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A recorded redirect stops failing Verify once a Setup of the home
// supersedes it: the DefenseClaw hooks refresh a redirect they see again
// after a day, so one last seen a day or more before Setup has not been
// used since. One `HERMES_HOME=/tmp/h hermes` run left Hermes unverified
// forever. A redirect seen since, or less than a day before Setup, still
// fails.
func TestManagedHermesVerifyIgnoresARedirectSetupSuperseded(t *testing.T) {
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	root := testenv.PrivateTempDir(t)
	t.Cleanup(hermespath.OverrideAccountHomeForTest(nil))
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "Users", "target")
	other := filepath.Join(root, "tmp", "h")
	record := filepath.Join(home, ".defenseclaw", "foreign-hook-env.json")
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(home, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	stubHermesAdmissionInstalledVersion(t)
	answerHermesProbeForTest(t)
	conn := NewHermesConnector()
	writeRecord := func(seen time.Time) error {
		body := `{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":"` + strings.ReplaceAll(other, `\`, `\\`) + `"},"seen":"` + seen.UTC().Format(time.RFC3339) + `"}]}}`
		if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
			return err
		}
		return os.WriteFile(record, []byte(body), 0o600)
	}
	if err := WithUserHomeDir(home, func() error {
		if err := writeRecord(time.Now().Add(-48 * time.Hour)); err != nil {
			return err
		}
		if err := conn.Setup(context.Background(), opts); err != nil {
			return err
		}
		if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Errorf("a redirect last seen two days before Setup: OwnedHooksPresent = %v, %v; want present", present, err)
		}
		for name, seen := range map[string]time.Time{
			"seen after Setup":          time.Now(),
			"seen an hour before Setup": time.Now().Add(-time.Hour),
		} {
			if err := writeRecord(seen); err != nil {
				return err
			}
			present, err := OwnedHooksPresent(conn, opts)
			if present || err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), other) {
				t.Errorf("%s: OwnedHooksPresent = %v, %v; want not verified naming %s", name, present, err, other)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// GAP-0499 upgrade: up to 1.0.3 the Windows guardian set up the profile
// default Hermes home whatever HERMES_HOME the account configured, and
// bound the receipts to it. Setup of the configured home then failed on the
// receipt's target mismatch, and the default home kept hooks that run a
// removed executable after uninstall. Setup releases the earlier home, and
// Teardown, VerifyClean and the orphan scan cover the profile default.
func TestManagedHermesReleasesTheEarlierDefaultHome(t *testing.T) {
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	root := testenv.PrivateTempDir(t)
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "Users", "target")
	custom := filepath.Join(home, "hermes-work")
	defaultConfig := hermespath.ConfigPathForUserHome(home)
	customConfig := filepath.Join(custom, "config.yaml")
	allowlist := func(config string) string { return filepath.Join(filepath.Dir(config), hermesAllowlistFileName) }
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(home, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	stubHermesAdmissionInstalledVersion(t)
	answerHermesProbeForTest(t)
	conn := NewHermesConnector()
	// The hook command names the account's executable, so it is resolved
	// for the account (WithUserHomeDir) as Setup and Teardown resolve it.
	var hookScript, command string
	if err := os.MkdirAll(filepath.Dir(defaultConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultConfig, []byte("model: default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := func(config string) bool {
		t.Helper()
		hooks, approvals, err := hermesHomeHoldsOwnedEntries(config, hookScript, command)
		if err != nil {
			t.Fatal(err)
		}
		return hooks || approvals
	}

	if err := WithUserHomeDir(home, func() error {
		hookScript = conn.hookCommand(opts)
		command = hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
		// The 1.0.3 guardian: the profile default home.
		restore := hermespath.OverrideAccountHomeForTest(nil)
		if err := conn.Setup(context.Background(), opts); err != nil {
			restore()
			return err
		}
		restore()
		if !owned(defaultConfig) {
			t.Fatal("fixture: Setup did not register the default home")
		}

		// 1.0.4 resolves the account's HERMES_HOME.
		t.Cleanup(hermespath.OverrideAccountHomeForTest(func(string) (string, error) { return custom, nil }))
		if err := conn.Setup(context.Background(), opts); err != nil {
			t.Fatalf("Setup of the configured home after the default one: %v", err)
		}
		if owned(defaultConfig) {
			t.Fatal("Setup left DefenseClaw's entries in the earlier default home")
		}
		if data, err := os.ReadFile(defaultConfig); err != nil || string(data) != "model: default\n" {
			t.Fatalf("the earlier default home's config = %q, %v; want the account's copy back", data, err)
		}
		if !owned(customConfig) {
			t.Fatal("Setup did not register the configured home")
		}
		if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Fatalf("OwnedHooksPresent = %v, %v; want present", present, err)
		}

		// Entries no receipt is bound to in the profile default.
		for _, path := range []string{customConfig, allowlist(customConfig)} {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			target := defaultConfig
			if path != customConfig {
				target = allowlist(defaultConfig)
			}
			if err := os.WriteFile(target, data, 0o600); err != nil {
				return err
			}
		}
		orphans, err := OrphanedHookConfigPaths(conn, opts)
		if err != nil || !slices.Contains(orphans, defaultConfig) {
			t.Fatalf("OrphanedHookConfigPaths = %v, %v; want the profile default %s", orphans, err, defaultConfig)
		}
		if err := conn.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("Teardown: %v", err)
		}
		if owned(defaultConfig) || owned(customConfig) {
			t.Fatal("Teardown left DefenseClaw's entries in a Hermes home")
		}
		if err := conn.VerifyClean(opts); err != nil {
			t.Fatalf("VerifyClean after Teardown: %v", err)
		}
		if err := os.WriteFile(allowlist(defaultConfig), []byte(`{"approvals":[{"event":"pre_tool_call","command":`+strconv.Quote(command)+`,"`+hermesAllowlistOwnerField+`":true}]}`), 0o600); err != nil {
			return err
		}
		if err := conn.VerifyClean(opts); err == nil || !strings.Contains(err.Error(), defaultConfig) {
			t.Fatalf("VerifyClean with an approval left in the default home = %v; want incomplete naming it", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// stubHermesAdmissionInstalledVersion reports the admission fixture's
// release as the installed one: a service acting for an account reads the
// updater's install stamp on Windows instead of probing the executable.
func stubHermesAdmissionInstalledVersion(t *testing.T) {
	t.Helper()
	previous := hermesInstalledVersionReader
	hermesInstalledVersionReader = func(string) (string, error) { return hermesAdmissionTestRawVersion, nil }
	t.Cleanup(func() { hermesInstalledVersionReader = previous })
}

// GAP-2374: the managed Linux and macOS guardian verifies each account in a
// worker that runs as that account, so the account home is the process's
// own home. A persistent HERMES_HOME redirect of the account (its
// environment.d, or a redirect the DefenseClaw hooks recorded) still fails
// managed verification there. A per-user check of its own home is
// unchanged: the HERMES_HOME of its environment decides which home it
// checks.
func TestManagedHermesVerifyAsTheAccountFailsOnAPersistentRedirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows resolves the account's persistent environment for every check")
	}
	previousOverride, previousResolver := HermesConfigPathOverride, hermesConfigPathResolver
	HermesConfigPathOverride = ""
	t.Cleanup(func() { HermesConfigPathOverride, hermesConfigPathResolver = previousOverride, previousResolver })
	root := testenv.PrivateTempDir(t)
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(filepath.Join(root, "system")))
	home := filepath.Join(root, "home", "eng1")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("HERMES_HOME", "")
	hermesConfigPathResolver = func() string { return filepath.Join(home, ".hermes", "config.yaml") }
	other := filepath.Join(home, ".hermes-other")
	evidence := []struct{ name, file, body string }{
		{"environment.d", filepath.Join(home, ".config", "environment.d", "x.conf"), "HERMES_HOME=" + other + "\n"},
		{"recorded redirect", filepath.Join(home, ".defenseclaw", "foreign-hook-env.json"),
			`{"v":1,"connectors":{"hermes":[{"vars":{"HERMES_HOME":"` + other + `"}}]}}`},
	}
	dataDir := filepath.Join(home, ".defenseclaw")
	managed := SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
	perUser := SetupOpts{DataDir: dataDir}
	if err := WithUserHomeDir(home, func() error {
		if !isProcessUserHome(home) {
			t.Fatalf("fixture: %s must be the process home", home)
		}
		if _, err := hermesVerifiedConfigPath(managed); err != nil {
			t.Fatalf("managed verify with no redirect = %v; want verified", err)
		}
		for _, tc := range evidence {
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(tc.file, []byte(tc.body), 0o600); err != nil {
				return err
			}
			_, err := hermesVerifiedConfigPath(managed)
			if err == nil || !strings.Contains(err.Error(), "not verified") || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), other) {
				t.Errorf("%s: managed verify as the account = %v; want not verified naming %s", tc.name, err, other)
			}
			if _, err := hermesVerifiedConfigPath(perUser); err != nil {
				t.Errorf("%s: per-user verify of its own home = %v; want unchanged (verified)", tc.name, err)
			}
			if err := os.Remove(tc.file); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
