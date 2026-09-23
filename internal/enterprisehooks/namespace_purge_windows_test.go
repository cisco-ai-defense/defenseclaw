//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const windowsNamespacePurgeTestGatewaySID = "S-1-5-80-123456789-234567890-345678901-456789012-567890123"

func TestValidateWindowsNamespacePurgeProductionRootAcceptsOnlyExactLayouts(t *testing.T) {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		t.Fatalf("resolve trusted Program Files: %v", err)
	}
	base := filepath.Join(programFiles, "Cisco", "Cisco Secure Client")
	production := filepath.Join(base, "DefenseClaw")
	certification := filepath.Join(base, "DefenseClaw-Cert", "0a1b2c3d4e")
	for name, path := range map[string]string{
		"production":    production,
		"certification": certification,
	} {
		t.Run("accept_"+name, func(t *testing.T) {
			if err := validateWindowsNamespacePurgeProductionRoot(path); err != nil {
				t.Fatalf("validate trusted namespace root %s: %v", path, err)
			}
		})
	}

	for name, path := range map[string]string{
		"sibling":              filepath.Join(base, "DefenseClaw-Other"),
		"production parent":    base,
		"certification parent": filepath.Join(base, "DefenseClaw-Cert"),
		"uppercase run ID":     filepath.Join(base, "DefenseClaw-Cert", "0A1B2C3D4E"),
		"short run ID":         filepath.Join(base, "DefenseClaw-Cert", "0a1b2c3d4"),
		"long run ID":          filepath.Join(base, "DefenseClaw-Cert", "00a1b2c3d4e"),
		"nonhex run ID":        filepath.Join(base, "DefenseClaw-Cert", "0a1b2c3d4g"),
		"arbitrary root":       filepath.Join(programFiles, "Unrelated", "DefenseClaw"),
	} {
		t.Run("reject_"+name, func(t *testing.T) {
			if err := validateWindowsNamespacePurgeProductionRoot(path); err == nil {
				t.Fatalf("untrusted namespace root was accepted: %s", path)
			}
		})
	}
}

func TestValidateWindowsNamespacePurgeRequestRejectsInvalidGatewayServiceSID(t *testing.T) {
	oldRootScope := windowsNamespacePurgeRootScope
	windowsNamespacePurgeRootScope = func(string) error { return nil }
	t.Cleanup(func() { windowsNamespacePurgeRootScope = oldRootScope })

	request := WindowsNamespacePurgeRequest{
		SchemaVersion:     WindowsNamespacePurgeSchemaVersion,
		Root:              filepath.Join(t.TempDir(), "managed-root"),
		GatewayServiceSID: windowsNamespacePurgeTestGatewaySID,
	}
	if descriptors, err := validateWindowsNamespacePurgeRequest(request); err != nil || descriptors == nil {
		t.Fatalf("validate canonical namespace purge request: descriptors=%v error=%v", descriptors, err)
	}

	for name, sid := range map[string]string{
		"empty":               "",
		"local system":        "S-1-5-18",
		"builtin admins":      "S-1-5-32-544",
		"user SID":            "S-1-5-21-1-2-3-1001",
		"lowercase prefix":    "s-1-5-80-1-2-3-4-5",
		"too few components":  "S-1-5-80-1-2-3-4",
		"too many components": "S-1-5-80-1-2-3-4-5-6",
		"leading zero":        "S-1-5-80-01-2-3-4-5",
		"overflow":            "S-1-5-80-4294967296-2-3-4-5",
		"nonnumeric":          "S-1-5-80-one-2-3-4-5",
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			invalid.GatewayServiceSID = sid
			if descriptors, err := validateWindowsNamespacePurgeRequest(invalid); err == nil || descriptors != nil {
				t.Fatalf("invalid gateway SID accepted: %q descriptors=%v", sid, descriptors)
			}
		})
	}
}

func TestPurgeWindowsNamespaceRootValidatesThenRemovesPinnedTree(t *testing.T) {
	request, root := newWindowsNamespacePurgeTestTree(t)
	request.ValidateOnly = true
	report, err := PurgeWindowsNamespaceRoot(request)
	if err != nil {
		t.Fatalf("validate namespace purge tree: %v", err)
	}
	if !report.OK || report.Removed || report.EntriesRemoved != 0 || report.Error != "" {
		t.Fatalf("validate-only report = %#v", report)
	}
	if _, err := os.Stat(filepath.Join(root, "nested", "payload.bin")); err != nil {
		t.Fatalf("validate-only mutated tree: %v", err)
	}

	request.ValidateOnly = false
	report, err = PurgeWindowsNamespaceRoot(request)
	if err != nil {
		t.Fatalf("purge namespace tree: %v", err)
	}
	if !report.OK || !report.Removed || report.EntriesRemoved != 3 || report.Error != "" {
		t.Fatalf("purge report = %#v", report)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purged root remains: %v", err)
	}
}

func TestPurgeWindowsNamespaceRootExclusivePinRejectsSharedReadHandle(t *testing.T) {
	request, root := newWindowsNamespacePurgeTestTree(t)
	payload := filepath.Join(root, "nested", "payload.bin")
	handle, err := openWindowsTargetsManifestObject(payload, false, windows.GENERIC_READ)
	if err != nil {
		t.Fatalf("open ordinary shared read handle: %v", err)
	}
	t.Cleanup(func() {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	})

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 ||
		(!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.STATUS_SHARING_VIOLATION)) {
		t.Fatalf("shared-read purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(payload); readErr != nil || string(got) != "payload" {
		t.Fatalf("failed exclusive preflight mutated payload: %q, %v", got, readErr)
	}
	if err := validateWindowsTargetsManifestObject(root, true); err != nil {
		t.Fatalf("failed exclusive preflight mutated root descriptor: %v", err)
	}

	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close ordinary shared read handle: %v", err)
	}
	handle = 0
	report, err = PurgeWindowsNamespaceRoot(request)
	if err != nil || !report.OK || !report.Removed || report.EntriesRemoved != 3 {
		t.Fatalf("purge after closing shared reader report=%#v error=%v", report, err)
	}
}

func TestPurgeWindowsNamespaceRootValidateOnlyRequiresExclusivePinsWithoutMutation(t *testing.T) {
	request, root := newWindowsNamespacePurgeTestTree(t)
	payload := filepath.Join(root, "nested", "payload.bin")
	handle, err := openWindowsTargetsManifestObject(payload, false, windows.GENERIC_READ)
	if err != nil {
		t.Fatalf("open ordinary shared read handle: %v", err)
	}
	t.Cleanup(func() {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	})

	request.ValidateOnly = true
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 ||
		(!errors.Is(err, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(err, windows.STATUS_SHARING_VIOLATION)) {
		t.Fatalf("shared-read validate-only report=%#v error=%v", report, err)
	}
	for path, directory := range map[string]bool{
		root:                          true,
		filepath.Join(root, "nested"): true,
		payload:                       false,
	} {
		if err := validateWindowsTargetsManifestObject(path, directory); err != nil {
			t.Fatalf("validate-only failure mutated %s: %v", path, err)
		}
	}
	if got, readErr := os.ReadFile(payload); readErr != nil || string(got) != "payload" {
		t.Fatalf("validate-only failure mutated payload: %q, %v", got, readErr)
	}

	if err := windows.CloseHandle(handle); err != nil {
		t.Fatalf("close ordinary shared read handle: %v", err)
	}
	handle = 0
	report, err = PurgeWindowsNamespaceRoot(request)
	if err != nil || !report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("validate-only after closing shared reader report=%#v error=%v", report, err)
	}
	if _, err := os.Stat(payload); err != nil {
		t.Fatalf("successful validate-only removed payload: %v", err)
	}
}

func TestPurgeWindowsNamespaceRootRejectsRunningExecutableIdentity(t *testing.T) {
	request, root := newWindowsNamespacePurgeTestTree(t)
	payload := filepath.Join(root, "nested", "payload.bin")
	handle, err := openWindowsTargetsManifestObject(payload, false, 0)
	if err != nil {
		t.Fatalf("pin in-tree executable identity fixture: %v", err)
	}
	identity, err := windowsNamespacePurgeHandleIdentity(handle, false, true)
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatalf("inspect in-tree executable identity fixture: %v", err)
	}

	oldExecutable := windowsNamespacePurgeExecutable
	windowsNamespacePurgeExecutable = func() (windows.Handle, string, error) {
		returned := handle
		handle = 0
		return returned, identity, nil
	}
	t.Cleanup(func() {
		windowsNamespacePurgeExecutable = oldExecutable
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	})

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 ||
		!strings.Contains(err.Error(), "running executable identity") {
		t.Fatalf("in-tree executable purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(payload); readErr != nil || string(got) != "payload" {
		t.Fatalf("in-tree executable rejection mutated payload: %q, %v", got, readErr)
	}
}

func TestPurgeWindowsNamespaceRootRejectsHardLinkedFile(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	outside := filepath.Join(filepath.Dir(root), "outside.bin")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsTargetsManifestObject(outside, false); err != nil {
		t.Fatalf("protect outside file: %v", err)
	}
	linked := filepath.Join(root, "linked.bin")
	if err := os.Link(outside, linked); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 ||
		!strings.Contains(strings.ToLower(err.Error()), "hard link") {
		t.Fatalf("hard-link purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(outside); readErr != nil || string(got) != "outside" {
		t.Fatalf("outside hard-link peer changed: %q, %v", got, readErr)
	}
	if _, statErr := os.Stat(root); statErr != nil {
		t.Fatalf("rejected root was removed: %v", statErr)
	}
}

func TestPurgeWindowsNamespaceRootRejectsSymbolicLinkChild(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	outside := filepath.Join(filepath.Dir(root), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "redirect")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("Windows symbolic-link fixtures are unavailable: %v", err)
	}

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("reparse purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(sentinel); readErr != nil || string(got) != "preserve" {
		t.Fatalf("symbolic-link target changed: %q, %v", got, readErr)
	}
}

func TestPurgeWindowsNamespaceRootRejectsJunctionChild(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	outside := filepath.Join(filepath.Dir(root), "outside-junction-target")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Skipf("Windows junction fixtures are unavailable: %v (%s)", err, output)
	}

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("junction purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(sentinel); readErr != nil || string(got) != "preserve" {
		t.Fatalf("junction target changed: %q, %v", got, readErr)
	}
}

func TestPurgeWindowsNamespaceRootRejectsForeignDescriptor(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	foreign := filepath.Join(root, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 ||
		!strings.Contains(strings.ToLower(err.Error()), "foreign descriptor") {
		t.Fatalf("foreign-descriptor purge report=%#v error=%v", report, err)
	}
	if got, readErr := os.ReadFile(foreign); readErr != nil || string(got) != "preserve" {
		t.Fatalf("foreign file changed: %q, %v", got, readErr)
	}
}

func TestPurgeWindowsNamespaceRootRejectsWrongIdentityAndAbsentClaims(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	request.ExpectedIdentity = differentWindowsNamespacePurgeIdentity(request.ExpectedIdentity)
	request.ValidateOnly = false
	report, err := PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("wrong-identity purge report=%#v error=%v", report, err)
	}
	if _, statErr := os.Stat(root); statErr != nil {
		t.Fatalf("wrong-identity root was removed: %v", statErr)
	}

	request.ExpectedIdentity = ""
	report, err = PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("present absent-claim report=%#v error=%v", report, err)
	}

	absent := filepath.Join(filepath.Dir(root), "absent")
	request.Root = absent
	report, err = PurgeWindowsNamespaceRoot(request)
	if err != nil || !report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("absent no-op report=%#v error=%v", report, err)
	}
	request.ExpectedIdentity = "00000000:0000000000000000"
	report, err = PurgeWindowsNamespaceRoot(request)
	if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
		t.Fatalf("missing authenticated-root report=%#v error=%v", report, err)
	}
}

func TestPurgeWindowsNamespaceRootDetectsPostPinNameRace(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	request.ValidateOnly = false
	created := false
	windowsNamespacePurgePostPin = func(_ string) error {
		if err := os.WriteFile(filepath.Join(root, "late.txt"), []byte("late"), 0o600); err != nil {
			// A sharing denial is an equally safe outcome: the pinned root
			// prevented the competing namespace write entirely.
			return nil
		}
		created = true
		return nil
	}
	t.Cleanup(func() { windowsNamespacePurgePostPin = nil })
	report, err := PurgeWindowsNamespaceRoot(request)
	if created {
		if err == nil || report.OK || report.Removed || report.EntriesRemoved != 0 {
			t.Fatalf("post-pin race report=%#v error=%v", report, err)
		}
		if _, statErr := os.Stat(filepath.Join(root, "late.txt")); statErr != nil {
			t.Fatalf("post-pin race fixture was unexpectedly removed: %v", statErr)
		}
	} else if err != nil || !report.OK || !report.Removed || report.EntriesRemoved != 1 {
		t.Fatalf("sharing-denied race report=%#v error=%v", report, err)
	}
}

func TestPurgeWindowsNamespaceRootPinsRootAgainstRename(t *testing.T) {
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	request.ValidateOnly = false
	renameDenied := false
	windowsNamespacePurgePostPin = func(_ string) error {
		err := os.Rename(root, root+"-moved")
		if err == nil {
			return fmt.Errorf("root rename unexpectedly succeeded")
		}
		renameDenied = true
		return nil
	}
	t.Cleanup(func() { windowsNamespacePurgePostPin = nil })
	report, err := PurgeWindowsNamespaceRoot(request)
	if err != nil || !renameDenied || !report.OK || !report.Removed || report.EntriesRemoved != 1 {
		t.Fatalf("rename-pinned purge report=%#v denied=%v error=%v", report, renameDenied, err)
	}
}

func newWindowsNamespacePurgeTestTree(t *testing.T) (WindowsNamespacePurgeRequest, string) {
	t.Helper()
	request, root := newWindowsNamespacePurgeEmptyTestRoot(t)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(nested, "payload.bin")
	if err := os.WriteFile(payload, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsTargetsManifestObject(payload, false); err != nil {
		t.Fatalf("protect test payload: %v", err)
	}
	if err := protectWindowsTargetsManifestObject(nested, true); err != nil {
		t.Fatalf("protect test directory: %v", err)
	}
	return request, root
}

func newWindowsNamespacePurgeEmptyTestRoot(t *testing.T) (WindowsNamespacePurgeRequest, string) {
	t.Helper()
	if err := requireWindowsEnterpriseAdministrator(); err != nil {
		t.Skipf("native namespace purge test requires elevation: %v", err)
	}
	oldAncestorTrust := windowsNamespacePurgeAncestorTrust
	oldRootScope := windowsNamespacePurgeRootScope
	windowsNamespacePurgeAncestorTrust = func(string) error { return nil }
	windowsNamespacePurgeRootScope = func(string) error { return nil }
	t.Cleanup(func() {
		windowsNamespacePurgeAncestorTrust = oldAncestorTrust
		windowsNamespacePurgeRootScope = oldRootScope
	})

	root := filepath.Join(t.TempDir(), "managed-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsTargetsManifestObject(root, true); err != nil {
		t.Fatalf("protect test root: %v", err)
	}
	handle, err := openWindowsTargetsManifestObject(
		root,
		true,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, identityErr := windowsManagedRuntimeHandleIdentity(handle, true)
	closeErr := windows.CloseHandle(handle)
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return WindowsNamespacePurgeRequest{
		SchemaVersion:     WindowsNamespacePurgeSchemaVersion,
		Root:              root,
		ExpectedIdentity:  identity,
		GatewayServiceSID: windowsNamespacePurgeTestGatewaySID,
	}, root
}

func differentWindowsNamespacePurgeIdentity(identity string) string {
	if strings.HasPrefix(identity, "0") {
		return "1" + identity[1:]
	}
	return "0" + identity[1:]
}
