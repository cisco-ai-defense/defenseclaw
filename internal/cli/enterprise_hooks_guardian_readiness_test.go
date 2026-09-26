// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// guardianReadinessLayout is one shipped managed_enterprise layout, re-rooted
// under a test temp directory. authDir is the value both the gateway and the
// guardian service receive in DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR.
type guardianReadinessLayout struct {
	name     string
	dataDir  string
	authDir  string
	manifest string
}

func readPackagingFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shipped packaging file %s: %v", path, err)
	}
	return string(data)
}

func plistStringAfter(t *testing.T, body, name, pattern string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("%s: shipped launchd plist no longer matches %q", name, pattern)
	}
	return strings.TrimSpace(match[1])
}

func psm1Leaf(t *testing.T, body, pattern string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("DefenseClawEnterprise.psm1 layout no longer matches %q", pattern)
	}
	return match[1]
}

// shippedGuardianReadinessLayouts derives the Windows and macOS layouts from
// the packaging sources that install them, so the regression test exercises
// the real directories rather than a hand-picked pair that happens to match.
func shippedGuardianReadinessLayouts(t *testing.T) []guardianReadinessLayout {
	t.Helper()
	root := t.TempDir()

	const authEnv = `<key>DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR</key>\s*<string>([^<]+)</string>`
	guardianPlist := readPackagingFile(t, "packaging", "launchd", "com.cisco.secureclient.defenseclaw.hook-guardian.plist")
	gatewayPlist := readPackagingFile(t, "packaging", "launchd", "com.cisco.secureclient.defenseclaw.plist")
	macManifest := plistStringAfter(t, guardianPlist, "hook-guardian", `<string>--manifest</string>\s*<string>([^<]+)</string>`)
	macGuardianAuth := plistStringAfter(t, guardianPlist, "hook-guardian", authEnv)
	macGatewayAuth := plistStringAfter(t, gatewayPlist, "gateway", authEnv)
	if macGuardianAuth != macGatewayAuth {
		t.Fatalf("macOS gateway and guardian LaunchDaemons disagree on %s: %q vs %q",
			managed.HookGuardianAuthorizationDirEnv, macGatewayAuth, macGuardianAuth)
	}
	// installer_lib.sh renders data_dir as "${support_dir}/runtime" and the
	// support dir is the parent of hook-guardian/targets.yaml.
	macSupport := filepath.Dir(filepath.Dir(macManifest))

	module := readPackagingFile(t, "packaging", "windows", "DefenseClawEnterprise.psm1")
	winGuardianLeaf := psm1Leaf(t, module, `\$guardianDirectory = Microsoft\.PowerShell\.Management\\Join-Path \$StateRoot '([^']+)'`)
	winAuthLeaf := psm1Leaf(t, module, `AuthorizationDirectory = \(Microsoft\.PowerShell\.Management\\Join-Path \$StateRoot '([^']+)'\)`)
	winRuntimeLeaf := psm1Leaf(t, module, "\\$runtimeDirectory = Microsoft\\.PowerShell\\.Management\\\\Join-Path `\\s*\\$StateRoot `\\s*'([^']+)'")
	winManifestLeaf := psm1Leaf(t, module, `ManifestPath = \(Microsoft\.PowerShell\.Management\\Join-Path \$guardianDirectory '([^']+)'\)`)
	for _, want := range []string{
		`"DEFENSECLAW_HOME=$RuntimeDirectory"`,
		`"DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=$AuthorizationDirectory"`,
	} {
		if !strings.Contains(module, want) {
			t.Fatalf("Windows service environment no longer sets %s for the gateway and guardian", want)
		}
	}
	winStateRoot := filepath.Join(root, "windows", "ProgramData", "Cisco", "Cisco Secure Client", "DefenseClaw")

	return []guardianReadinessLayout{
		{
			name:     "windows",
			dataDir:  filepath.Join(winStateRoot, winRuntimeLeaf),
			authDir:  filepath.Join(winStateRoot, winAuthLeaf),
			manifest: filepath.Join(winStateRoot, winGuardianLeaf, winManifestLeaf),
		},
		{
			name:     "darwin",
			dataDir:  filepath.Join(root, "darwin", filepath.FromSlash(macSupport), "runtime"),
			authDir:  filepath.Join(root, "darwin", filepath.FromSlash(macGuardianAuth)),
			manifest: filepath.Join(root, "darwin", filepath.FromSlash(macManifest)),
		},
	}
}

type guardianReadinessSeams struct {
	ownershipCalls []string
	fileTrustCalls []string
}

// stubGuardianReadinessTrust replaces the root/Administrators trust and
// ownership primitives (temp dirs are owned by the test user) while keeping
// the writer's real directory, publication, and path-resolution logic.
func stubGuardianReadinessTrust(t *testing.T) *guardianReadinessSeams {
	t.Helper()
	seams := &guardianReadinessSeams{}
	previousCfg := cfg
	previousManifest := enterpriseHookManifest
	previousDirTrust := enterpriseHookAuthorizationDirTrustCheck
	previousFileTrust := enterpriseHookAuthorizationFileTrustCheck
	previousOwnership := enterpriseHookAuthorizationOwnershipSetter
	previousReaderTrust := guardianReadinessStateTrustCheck
	t.Cleanup(func() {
		cfg = previousCfg
		enterpriseHookManifest = previousManifest
		enterpriseHookAuthorizationDirTrustCheck = previousDirTrust
		enterpriseHookAuthorizationFileTrustCheck = previousFileTrust
		enterpriseHookAuthorizationOwnershipSetter = previousOwnership
		guardianReadinessStateTrustCheck = previousReaderTrust
	})
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(path string) error {
		seams.fileTrustCalls = append(seams.fileTrustCalls, path)
		return nil
	}
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		seams.ownershipCalls = append(seams.ownershipCalls, path)
		return nil
	}
	guardianReadinessStateTrustCheck = func(string) error { return nil }
	return seams
}

// TestGuardianReadinessWriterAndReaderAgreeOnShippedLayouts is the #896
// regression: in the shipped Windows and macOS layouts the manifest
// directory, the gateway data_dir, and the protected authorization directory
// are three different directories. The guardian used to write .state beside
// the manifest while the gateway read <data_dir>/hook-guardian/.state, so the
// collapsed configuration state (and Secure Client GetHealth
// configuration_state) stayed waiting_for_targets forever.
func TestGuardianReadinessWriterAndReaderAgreeOnShippedLayouts(t *testing.T) {
	for _, layout := range shippedGuardianReadinessLayouts(t) {
		t.Run(layout.name, func(t *testing.T) {
			seams := stubGuardianReadinessTrust(t)
			for _, dir := range []string{layout.dataDir, layout.authDir, filepath.Dir(layout.manifest)} {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(layout.manifest, []byte("version: 1\ntargets: []\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			// Both services receive the same authorization directory.
			t.Setenv(managed.HookGuardianAuthorizationDirEnv, layout.authDir)
			cfg = &config.Config{DataDir: layout.dataDir, DeploymentMode: managed.DeploymentModeManagedEnterprise}
			enterpriseHookManifest = layout.manifest

			health := gateway.NewSidecarHealth()
			health.SetDaemonConfigLoaded(true)
			health.SetGuardianStateReader(newGuardianReadinessStateReader(cfg.DataDir))
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
				t.Fatalf("before any guardian write: configuration state = %q, want waiting_for_targets", got)
			}

			var log bytes.Buffer
			writeGuardianStateOrLog(&log, guardianstate.StateReady)
			if strings.Contains(log.String(), "warn") {
				t.Fatalf("guardian readiness write warned: %s", log.String())
			}
			health.RefreshConfiguration()
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateReady {
				t.Fatalf("after guardian ready: configuration state = %q, want ready", got)
			}

			wantPath := filepath.Join(layout.authDir, guardianstate.FileName)
			if _, err := os.Stat(wantPath); err != nil {
				t.Fatalf("readiness state not published in the protected authorization dir: %v", err)
			}
			for _, stale := range []string{
				filepath.Join(filepath.Dir(layout.manifest), guardianstate.FileName),
				filepath.Join(layout.dataDir, "hook-guardian", guardianstate.FileName),
				filepath.Join(layout.dataDir, guardianstate.FileName),
			} {
				if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("readiness state leaked to %s (err=%v)", stale, err)
				}
			}
			if len(seams.ownershipCalls) == 0 || seams.ownershipCalls[len(seams.ownershipCalls)-1] != wantPath {
				t.Fatalf("protected ownership not applied to %s: %v", wantPath, seams.ownershipCalls)
			}
			if len(seams.fileTrustCalls) != 1 || seams.fileTrustCalls[0] != wantPath {
				t.Fatalf("published readiness state not re-verified: %v", seams.fileTrustCalls)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(wantPath)
				if err != nil {
					t.Fatal(err)
				}
				if perm := info.Mode().Perm(); perm != 0o640 {
					t.Fatalf("readiness state mode = %04o, want 0640 (owner-write only)", perm)
				}
			}

			writeGuardianStateOrLog(&log, guardianstate.StateWaitingForTargets)
			health.RefreshConfiguration()
			if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
				t.Fatalf("after guardian waiting: configuration state = %q, want waiting_for_targets", got)
			}
		})
	}
}

// TestGuardianReadinessReaderIgnoresUntrustedState pins that the gateway does
// not honor a readiness file failing the administrator-only trust contract
// (for example one a gateway-writable location could supply): it collapses to
// the waiting_for_targets safe default instead of ready.
func TestGuardianReadinessReaderIgnoresUntrustedState(t *testing.T) {
	stubGuardianReadinessTrust(t)
	authDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authDir)
	dataDir := t.TempDir()
	if err := guardianstate.WriteState(guardianstate.PathForDataDir(dataDir), guardianstate.StateReady); err != nil {
		t.Fatal(err)
	}
	guardianReadinessStateTrustCheck = func(string) error {
		return errors.New("writable by the gateway service account")
	}

	reader := newGuardianReadinessStateReader(dataDir)
	if got := reader(); got != guardianstate.StateUnknown {
		t.Fatalf("untrusted readiness state = %q, want unknown", got)
	}
	health := gateway.NewSidecarHealth()
	health.SetDaemonConfigLoaded(true)
	health.SetGuardianStateReader(reader)
	if got := health.Snapshot().Configuration.State; got != gateway.ConfigStateWaitingForTargets {
		t.Fatalf("untrusted readiness state collapsed to %q, want waiting_for_targets", got)
	}
}

// TestGuardianReadinessWriterNeverCreatesOrTrustsForeignDirectory pins that
// the writer does not widen who can write the file: it refuses an absent or
// untrusted authorization directory instead of creating or re-permissioning
// one.
func TestGuardianReadinessWriterNeverCreatesOrTrustsForeignDirectory(t *testing.T) {
	stubGuardianReadinessTrust(t)
	dataDir := t.TempDir()

	missing := filepath.Join(t.TempDir(), "hook-guardian-state")
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, missing)
	if _, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady); err == nil {
		t.Fatal("readiness write succeeded without an existing protected authorization dir")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readiness writer created the authorization dir (err=%v)", err)
	}

	untrusted := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, untrusted)
	enterpriseHookAuthorizationDirTrustCheck = func(string) error {
		return errors.New("authorization dir is writable by the gateway")
	}
	path, err := writeEnterpriseHookGuardianReadinessState(dataDir, guardianstate.StateReady)
	if err == nil {
		t.Fatal("readiness write succeeded into an untrusted authorization dir")
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("readiness state written into an untrusted dir (err=%v)", statErr)
	}

	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	if _, err := writeEnterpriseHookGuardianReadinessState(dataDir, "waiting_for_config"); err == nil {
		t.Fatal("readiness writer accepted a literal the sidecar cannot map")
	}
}
