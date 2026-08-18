// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

type atomicTransformV2ReplaceTestInfo struct{ mode os.FileMode }

func (i atomicTransformV2ReplaceTestInfo) Name() string       { return "replace-test" }
func (i atomicTransformV2ReplaceTestInfo) Size() int64        { return 0 }
func (i atomicTransformV2ReplaceTestInfo) Mode() os.FileMode  { return i.mode }
func (i atomicTransformV2ReplaceTestInfo) ModTime() time.Time { return time.Time{} }
func (i atomicTransformV2ReplaceTestInfo) IsDir() bool        { return false }
func (i atomicTransformV2ReplaceTestInfo) Sys() any           { return nil }

func atomicTransformV2ReplaceTestState(
	identity, digest, protection, ownerGroup, preserved, stageOwned string,
	creation, lastWrite uint64, size int64,
) atomicTransformArtifactState {
	return atomicTransformArtifactState{
		exists: true, identity: identity, digest: digest, size: size,
		protectionDigest:         protection,
		ownerGroupDigest:         ownerGroup,
		preservedMetadataDigest:  preserved,
		stageOwnedMetadataDigest: stageOwned,
		creationTime:             creation, lastWriteTime: lastWrite,
		linkCount: 1,
		info:      atomicTransformV2ReplaceTestInfo{mode: 0o600},
	}
}

func TestClassifyAtomicTransformV2ReplaceObservation(t *testing.T) {
	old := atomicTransformV2Artifact{
		Identity: "old-id", SHA256: "old-sha", Size: 3, Mode: uint32(0o600),
		ProtectionSHA256:        "old-acl",
		OwnerGroupSHA256:        "old-owner-group",
		PreservedMetadataSHA256: "old-preserved",
		CreationTime:            100, LastWriteTime: 200, LinkCount: 1,
	}
	stage := atomicTransformV2Artifact{
		Identity: "stage-id", SHA256: "new-sha", Size: 3, Mode: uint32(0o600),
		ProtectionSHA256:         "stage-acl",
		OwnerGroupSHA256:         "stage-owner-group",
		StageOwnedMetadataSHA256: "stage-owned",
		CreationTime:             400, LastWriteTime: 300, LinkCount: 1,
	}
	receipt := atomicTransformV2Receipt{OldExists: true, Old: old, Stage: stage}
	oldState := atomicTransformV2ReplaceTestState("old-id", "old-sha", "old-acl", "old-owner-group", "old-preserved", "old-owned", 100, 200, 3)
	stageState := atomicTransformV2ReplaceTestState("stage-id", "new-sha", "old-acl", "stage-owner-group", "old-preserved", "stage-owned", 100, 300, 3)
	stagedState := atomicTransformV2ReplaceTestState("stage-id", "new-sha", "stage-acl", "stage-owner-group", "stage-preserved", "stage-owned", 400, 300, 3)
	foreign := atomicTransformV2ReplaceTestState("foreign-id", "foreign-sha", "foreign-acl", "foreign-owner-group", "foreign-preserved", "foreign-owned", 500, 600, 7)
	editedStage := atomicTransformV2ReplaceTestState("stage-id", "edited-sha", "old-acl", "stage-owner-group", "old-preserved", "stage-owned", 100, 300, 6)
	wrongOwnerGroup := stageState
	wrongOwnerGroup.ownerGroupDigest = "foreign-owner-group"
	stageUnknownMetadata := stagedState
	stageUnknownMetadata.protectionDigest = "merged-unknown-acl"
	stageUnknownMetadata.preservedMetadataDigest = "merged-unknown-preserved"
	stageWrongOwnerGroup := stageUnknownMetadata
	stageWrongOwnerGroup.ownerGroupDigest = "merged-unknown-owner-group"
	oldEquivalentProtection := oldState
	oldEquivalentProtection.protectionDigest = "equivalent-full-sddl-format"

	tests := []struct {
		name string
		code atomicTransformV2ReplaceCode
		obs  atomicTransformV2ReplaceObservation
		want atomicTransformV2ReplaceDisposition
	}{
		{
			name: "success", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: stageState, Backup: oldState},
			want: atomicTransformV2ReplaceReadyForPublication,
		},
		{
			name: "backup equivalent raw SDDL format is publication ready", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: stageState, Backup: oldEquivalentProtection},
			want: atomicTransformV2ReplaceReadyForPublication,
		},
		{
			name: "operator edit same published inode", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: editedStage, Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "published owner group race is not publication ready", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: wrongOwnerGroup, Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "operator replacement with explicit success", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: foreign, Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "operator deletion with explicit success", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "foreign live without durable success is ambiguous", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Target: foreign, Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "absent live without durable success is ambiguous", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "1175 retry", code: atomicTransformV2ReplaceUnableToRemoveReplaced,
			obs:  atomicTransformV2ReplaceObservation{Target: oldState, Stage: stagedState},
			want: atomicTransformV2ReplaceRetryUntouched,
		},
		{
			name: "1176 retry", code: atomicTransformV2ReplaceUnableToMoveReplacement,
			obs:  atomicTransformV2ReplaceObservation{Target: oldState, Stage: stagedState},
			want: atomicTransformV2ReplaceRetryUntouched,
		},
		{
			name: "generic partial metadata merge retry", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Target: oldState, Stage: stageState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "1177 restore old", code: atomicTransformV2ReplaceUnableToMoveReplacement2,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState, Stage: stageState},
			want: atomicTransformV2ReplaceRestoreOldThenRetry,
		},
		{
			name: "foreign target displaced by replacement", code: atomicTransformV2ReplaceSuccess,
			obs:  atomicTransformV2ReplaceObservation{Target: stageState, Backup: foreign},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "continue displaced foreign rollback", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Backup: foreign, Stage: stageState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "displaced foreign restored", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Target: foreign, Stage: stageState},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "1177 recorded Stage content with unknown metadata restores old", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState, Stage: stageUnknownMetadata},
			want: atomicTransformV2ReplaceRestoreOldThenRetry,
		},
		{
			name: "1177 wholly foreign Stage is preserved ambiguous", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState, Stage: foreign},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "1177 Stage owner group race is preserved ambiguous", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Backup: oldState, Stage: stageWrongOwnerGroup},
			want: atomicTransformV2ReplaceAmbiguous,
		},
		{
			name: "unknown partial state", code: atomicTransformV2ReplaceOtherFailure,
			obs:  atomicTransformV2ReplaceObservation{Target: stageState, Backup: oldState, Stage: foreign},
			want: atomicTransformV2ReplaceAmbiguous,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyAtomicTransformV2ReplaceObservation(receipt, test.code, test.obs)
			if got != test.want {
				t.Fatalf("classification = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAtomicTransformV2ReplaceCodeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want atomicTransformV2ReplaceCode
	}{
		{"success", nil, atomicTransformV2ReplaceSuccess},
		{"1175", windowsErrorForAtomicTransformV2Test(1175), atomicTransformV2ReplaceUnableToRemoveReplaced},
		{"1176", windowsErrorForAtomicTransformV2Test(1176), atomicTransformV2ReplaceUnableToMoveReplacement},
		{"1177", windowsErrorForAtomicTransformV2Test(1177), atomicTransformV2ReplaceUnableToMoveReplacement2},
		{"generic", windowsErrorForAtomicTransformV2Test(5), atomicTransformV2ReplaceOtherFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := atomicTransformV2ReplaceCodeForError(test.err); got != test.want {
				t.Fatalf("code = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAtomicTransformV2WindowsCanonicalDACLFromSDDL(t *testing.T) {
	want := "D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)"
	for _, test := range []struct {
		name string
		sddl string
	}{
		{"DACL only", want},
		{"auto inheritance flags", "D:PAIAR(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)"},
		{"optional owner and group prefix", "O:S-1-5-21-1-2-3-1001G:S-1-5-18D:PAI(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)"},
		{"optional owner group and SACL", "O:S-1-5-21-1-2-3-1001G:S-1-5-18D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)S:(AU;SA;FA;;;WD)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(test.sddl)
			if err != nil || got != want {
				t.Fatalf("canonical DACL = %q, %v; want %q", got, err, want)
			}
		})
	}
	if got, err := atomicTransformV2WindowsCanonicalDACLFromSDDL("O:S-1-5-18G:S-1-5-18"); err == nil || got != "" {
		t.Fatalf("missing DACL canonicalization = %q, %v; want error", got, err)
	}
	inherited := "D:P(A;CIOIID;FA;;;SY)(A;IOID;GR;;;WD)"
	if got, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(
		inherited + "O:S-1-5-18G:S-1-5-18",
	); err != nil || got != inherited {
		t.Fatalf("D-before-O/G inherited ACE canonicalization = %q, %v; want %q", got, err, inherited)
	}
	for _, malformed := range []string{
		"D:P(A;;FA;;;SY)O:S-1-5-18D:P(A;;FA;;;SY)",
		"D:P(A;;FA;;;SY",
		"D:PA;;FA;;;SY)",
	} {
		if got, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(malformed); err == nil || got != "" {
			t.Errorf("malformed DACL %q canonicalization = %q, %v; want error", malformed, got, err)
		}
	}
}

func TestAtomicTransformCanonicalPrivateDACLOrderIsNarrow(t *testing.T) {
	user := "S-1-5-21-1-2-3-1001"
	systemFirst := "D:P(A;;FA;;;SY)(A;;FA;;;" + user + ")"
	userFirst := "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)"
	if got := atomicTransformCanonicalPrivateDACLOrder(userFirst, user); got != systemFirst {
		t.Fatalf("private user-first DACL = %q, want %q", got, systemFirst)
	}
	for _, dacl := range []string{
		systemFirst,
		"D:(A;;FA;;;" + user + ")(A;;FA;;;SY)",
		"D:P(A;;GR;;;" + user + ")(A;;FA;;;SY)",
		"D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;GR;;;BA)",
		"D:P(A;;FA;;;S-1-5-21-9-8-7-1002)(A;;FA;;;SY)",
	} {
		if got := atomicTransformCanonicalPrivateDACLOrder(dacl, user); got != dacl {
			t.Errorf("custom DACL changed from %q to %q", dacl, got)
		}
	}
}

func TestAtomicTransformV2WindowsDACLIsReplaceNormalization(t *testing.T) {
	explicit := "D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;OI;GR;;;SY)"
	inherited := "D:AI(A;ID;FA;;;S-1-5-21-1-2-3-1001)(A;OIID;GR;;;SY)"
	if got, err := atomicTransformV2WindowsDACLIsReplaceNormalization(inherited, explicit); err != nil || !got {
		t.Fatalf("one-way ReplaceFileW normalization = %t, %v; want true", got, err)
	}
	for name, pair := range map[string][2]string{
		"reverse protection":     {explicit, inherited},
		"old already inherited":  {inherited, inherited},
		"target still protected": {explicit, explicit},
		"partial inherited": {
			"D:(A;ID;FA;;;S-1-5-21-1-2-3-1001)(A;OI;GR;;;SY)", explicit,
		},
		"changed access": {
			"D:(A;ID;GR;;;S-1-5-21-1-2-3-1001)(A;OIID;GR;;;SY)", explicit,
		},
		"changed trustee": {
			"D:(A;ID;FA;;;S-1-5-21-9-9-9-1001)(A;OIID;GR;;;SY)", explicit,
		},
		"changed order": {
			"D:(A;OIID;GR;;;SY)(A;ID;FA;;;S-1-5-21-1-2-3-1001)", explicit,
		},
		"changed other flag": {
			"D:(A;CIID;FA;;;S-1-5-21-1-2-3-1001)(A;OIID;GR;;;SY)", explicit,
		},
	} {
		got, err := atomicTransformV2WindowsDACLIsReplaceNormalization(pair[0], pair[1])
		if err != nil || got {
			t.Errorf("%s normalization = %t, %v; want false", name, got, err)
		}
	}
}

func TestRestoreAtomicTransformBoundRenameProtectionRepairsNTFSNormalization(t *testing.T) {
	directory := t.TempDir()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		t.Fatalf("resolve current user: %v", err)
	}
	parentDescriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", currentUser.User.Sid,
	))
	if err != nil {
		t.Fatal(err)
	}
	parentDACL, _, err := parentDescriptor.DACL()
	if err != nil || parentDACL == nil {
		t.Fatalf("extract private parent DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, parentDACL, nil,
	); err != nil {
		t.Fatal(err)
	}
	dir, err := bindAtomicTransformDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	const name = "bound-rename-dacl"
	if _, err := atomicTransformBoundCreate(dir, name, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openAtomicTransformBoundFilePlatform(dir.file, name, true)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	before, err := captureAtomicTransformBoundRenameProtectionPlatform(file)
	if err != nil {
		t.Fatal(err)
	}
	prefix, aces, err := atomicTransformV2WindowsDACLParts(before.canonical)
	if err != nil || prefix != "D:P" {
		t.Fatalf("captured private DACL = %q/%v, %v", prefix, aces, err)
	}
	var inherited strings.Builder
	inherited.WriteString("D:")
	for _, ace := range aces {
		first := strings.IndexByte(ace, ';')
		secondRelative := -1
		if first >= 0 {
			secondRelative = strings.IndexByte(ace[first+1:], ';')
		}
		if first < 0 || secondRelative < 0 {
			t.Fatalf("invalid captured ACE %q", ace)
		}
		second := first + 1 + secondRelative
		if strings.Contains(ace[first+1:second], "ID") {
			t.Fatalf("captured ACE is already inherited: %q", ace)
		}
		inherited.WriteString(ace[:second])
		inherited.WriteString("ID")
		inherited.WriteString(ace[second:])
	}

	normalizedDescriptor, err := windows.SecurityDescriptorFromString(inherited.String())
	if err != nil {
		t.Fatal(err)
	}
	normalizedDACL, _, err := normalizedDescriptor.DACL()
	if err != nil || normalizedDACL == nil {
		t.Fatalf("extract normalized DACL: %v", err)
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, normalizedDACL, nil,
	); err != nil {
		t.Fatal(err)
	}
	actualNormalized, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		t.Fatal(err)
	}
	if normalized, normalizeErr := atomicTransformV2WindowsDACLIsReplaceNormalization(
		actualNormalized, before.canonical,
	); normalizeErr != nil || !normalized {
		t.Fatalf(
			"fixture is not exact NTFS rename normalization: %t, %v\nbefore=%q\nafter=%q",
			normalized, normalizeErr, before.canonical, actualNormalized,
		)
	}

	if err := restoreAtomicTransformBoundRenameProtectionPlatform(file, before); err != nil {
		t.Fatal(err)
	}
	restored, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		t.Fatal(err)
	}
	if restored != before.canonical {
		t.Fatalf("restored DACL = %q, want %q", restored, before.canonical)
	}
	if err := validateAtomicTransformWindowsPrivateHandle(windows.Handle(file.Fd())); err != nil {
		t.Fatalf("restored file is not private: %v", err)
	}
}

func windowsErrorForAtomicTransformV2Test(code uintptr) error {
	return os.NewSyscallError("replace", syscall.Errno(code))
}

type atomicTransformV2WindowsSecurityPartsForTest struct {
	owner string
	group string
	dacl  string
}

func atomicTransformV2ReadWindowsSecurityPartsForTest(
	path string,
) (atomicTransformV2WindowsSecurityPartsForTest, error) {
	var parts atomicTransformV2WindowsSecurityPartsForTest
	file, err := os.Open(path)
	if err != nil {
		return parts, err
	}
	defer file.Close()
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return parts, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return parts, fmt.Errorf("read exact Windows owner: %w", err)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return parts, fmt.Errorf("read exact Windows group: %w", err)
	}
	parts.owner = owner.String()
	parts.group = group.String()
	parts.dacl, err = atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	return parts, err
}

// atomicTransformV2ForcePreRepairShortNamesForTest makes the otherwise
// filesystem-dependent raw-Replace/pre-publication alias state deterministic.
// The hook receives exact, revalidated target and backup handles from the
// production seam and may only replace aliases recorded in Rp.
func atomicTransformV2ForcePreRepairShortNamesForTest(
	dir *atomicTransformBoundDirectory, target, backup *os.File,
	receipt atomicTransformV2Receipt,
) error {
	oldShort := strings.ToUpper(receipt.TargetShortName)
	stageShort := strings.ToUpper(receipt.StageShortName)
	if oldShort != "" && atomicTransformPathsEqual(oldShort, stageShort) {
		return fmt.Errorf("test fixture requires distinct Old and Stage short names")
	}
	targetCurrent, err := atomicTransformV2WindowsShortNameFromOpen(target)
	if err != nil {
		return err
	}
	backupCurrent, err := atomicTransformV2WindowsShortNameFromOpen(backup)
	if err != nil {
		return err
	}
	// These names were queried from exact target/backup handles already proven
	// by the production seam. Clear whatever ordinal NTFS regenerated on those
	// exact inodes; never resolve or mutate an alias by its path spelling.
	if targetCurrent != "" {
		if err := setAtomicTransformV2WindowsShortNameOnOpen(target, ""); err != nil {
			return err
		}
	}
	if backupCurrent != "" {
		if err := setAtomicTransformV2WindowsShortNameOnOpen(backup, ""); err != nil {
			return err
		}
	}
	if oldShort != "" {
		if err := setAtomicTransformV2WindowsShortNameOnOpen(backup, oldShort); err != nil {
			return err
		}
	}
	if stageShort != "" {
		if err := setAtomicTransformV2WindowsShortNameOnOpen(target, stageShort); err != nil {
			return err
		}
	}
	if err := windows.FlushFileBuffers(windows.Handle(backup.Fd())); err != nil {
		return err
	}
	if err := windows.FlushFileBuffers(windows.Handle(target.Fd())); err != nil {
		return err
	}
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return err
	}
	gotTarget, err := atomicTransformV2WindowsShortNameFromOpen(target)
	if err != nil || !atomicTransformPathsEqual(gotTarget, stageShort) {
		return fmt.Errorf("forced target short name = %q, %v; want %q", gotTarget, err, stageShort)
	}
	gotBackup, err := atomicTransformV2WindowsShortNameFromOpen(backup)
	if err != nil || !atomicTransformPathsEqual(gotBackup, oldShort) {
		return fmt.Errorf("forced backup short name = %q, %v; want %q", gotBackup, err, oldShort)
	}
	return nil
}

func TestAtomicTransformV2WindowsMetadataWitnessDetectsADSRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	readWitness := func() atomicTransformV2WindowsMetadataWitness {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		witness, err := atomicTransformV2WindowsMetadataFromOpen(file)
		if err != nil {
			t.Fatal(err)
		}
		return witness
	}
	before := readWitness()
	if err := os.WriteFile(path+":defenseclaw-race", []byte("foreign ADS"), 0o600); err != nil {
		t.Skipf("NTFS alternate streams unavailable: %v", err)
	}
	// Restore the Stage-owned timestamp so this assertion isolates the named
	// stream witness instead of succeeding because ADS I/O also touched mtime.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	creation := windows.Filetime{LowDateTime: uint32(before.CreationTime), HighDateTime: uint32(before.CreationTime >> 32)}
	lastWrite := windows.Filetime{LowDateTime: uint32(before.LastWriteTime), HighDateTime: uint32(before.LastWriteTime >> 32)}
	if err := windows.SetFileTime(windows.Handle(file.Fd()), &creation, nil, &lastWrite); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	after := readWitness()
	if before.Digest == after.Digest || before.PreservedDigest == after.PreservedDigest {
		t.Fatalf("ADS-only mutation was not witnessed: full %s/%s preserved %s/%s",
			before.Digest, after.Digest, before.PreservedDigest, after.PreservedDigest)
	}
	if before.StageOwnedDigest != after.StageOwnedDigest {
		t.Fatalf("ADS-only mutation changed Stage-owned witness: %s/%s", before.StageOwnedDigest, after.StageOwnedDigest)
	}
	found := false
	for _, stream := range after.Streams {
		if stream.ID == atomicTransformV2BackupAlternateData && strings.Contains(
			strings.ToLower(stream.Name), "defenseclaw-race",
		) {
			found = true
		}
	}
	if !found {
		t.Fatal("named ADS was not enumerated by the held-handle witness")
	}
}

func TestAtomicTransformV2WindowsMetadataWitnessDetectsCompression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compressed.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("compressible", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	before, err := atomicTransformV2WindowsMetadataFromOpen(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	format := uint16(2) // COMPRESSION_FORMAT_LZNT1
	var returned uint32
	if err := windows.DeviceIoControl(
		windows.Handle(file.Fd()), windows.FSCTL_SET_COMPRESSION,
		(*byte)(unsafe.Pointer(&format)), uint32(unsafe.Sizeof(format)), nil, 0, &returned, nil,
	); err != nil {
		_ = file.Close()
		t.Skipf("NTFS compression unavailable: %v", err)
	}
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	after, err := atomicTransformV2WindowsMetadataFromOpen(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if after.Compression == 0 || before.PreservedDigest == after.PreservedDigest {
		t.Fatalf("compression metadata was not witnessed: format=%d preserved=%s/%s",
			after.Compression, before.PreservedDigest, after.PreservedDigest)
	}
}

func TestNativeReplaceFileWPreservesEFSWhenAvailable(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "encrypted-old.json")
	stage := filepath.Join(directory, "plain-stage.json")
	backup := filepath.Join(directory, "encrypted-backup.json")
	if err := os.WriteFile(target, []byte("encrypted-old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("plain-new"), 0o600); err != nil {
		t.Fatal(err)
	}
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	encryptFileW := windows.NewLazySystemDLL("advapi32.dll").NewProc("EncryptFileW")
	result, _, callErr := encryptFileW.Call(uintptr(unsafe.Pointer(targetPointer)))
	if result == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		t.Skipf("EFS capability unavailable: EncryptFileW(%s): %v", target, callErr)
	}
	attributes, err := windows.GetFileAttributes(targetPointer)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		t.Skipf("EFS capability unavailable: EncryptFileW succeeded but ENCRYPTED was not reported (0x%x)", attributes)
	}
	witness := func(path string) atomicTransformV2WindowsMetadataWitness {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		got, err := atomicTransformV2WindowsMetadataFromOpen(file)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	oldBefore, stageBefore := witness(target), witness(stage)
	if err := replaceAtomicTransformV2ExistingFile(target, stage, backup); err != nil {
		t.Fatalf("ReplaceFileW with EFS Old: %v", err)
	}
	targetAfter, backupAfter := witness(target), witness(backup)
	if targetAfter.Identity != stageBefore.Identity ||
		targetAfter.PreservedDigest != oldBefore.PreservedDigest ||
		targetAfter.CreationTime != oldBefore.CreationTime ||
		targetAfter.FileAttributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		t.Fatalf("published EFS composition mismatch: target=%+v Old=%+v Stage=%+v",
			targetAfter, oldBefore, stageBefore)
	}
	if backupAfter.Identity != oldBefore.Identity ||
		backupAfter.PreservedDigest != oldBefore.PreservedDigest ||
		backupAfter.CreationTime != oldBefore.CreationTime ||
		backupAfter.LastWriteTime != oldBefore.LastWriteTime ||
		backupAfter.FileAttributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		t.Fatalf("EFS backup is not exact Old: backup=%+v Old=%+v", backupAfter, oldBefore)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "plain-new" {
		t.Fatalf("read published EFS main stream = %q, %v; want plain-new", data, err)
	}
}

func TestFlushAtomicTransformV2ReplaceArtifactNative(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"live.json", "backup.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := bindAtomicTransformDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, name := range []string{"live.json", "backup.json"} {
		state, err := atomicTransformBoundInspect(dir, name, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		var boundaries []string
		if err := flushAtomicTransformV2ReplaceArtifact(
			dir, name, state, "before", "after",
			func(boundary string) error { boundaries = append(boundaries, boundary); return nil },
		); err != nil {
			t.Fatal(err)
		}
		if strings.Join(boundaries, ",") != "before,after" {
			t.Fatalf("flush boundaries = %v", boundaries)
		}
	}
}

func TestAtomicTransformV2WindowsShortNamePrimitivesNative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Long Configuration Settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 2048)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("8.3 aliases unavailable: length=%d err=%v", length, err)
	}
	shortLeaf := strings.ToUpper(filepath.Base(windows.UTF16ToString(buffer[:length])))
	if !strings.Contains(shortLeaf, "~") {
		t.Skipf("target has no distinct 8.3 alias: %s", shortLeaf)
	}
	dir, err := bindAtomicTransformDirectory(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	state, err := atomicTransformBoundInspect(dir, filepath.Base(path), atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := atomicTransformV2CaptureWindowsShortName(dir, filepath.Base(path), state)
	if err != nil || !atomicTransformPathsEqual(captured, shortLeaf) {
		t.Fatalf("captured short name = %q, %v; want %q", captured, err, shortLeaf)
	}
	file, err := openAtomicTransformV2ReplaceGuard(dir, filepath.Base(path), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := setAtomicTransformV2WindowsShortNameOnOpen(file, ""); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if got, err := atomicTransformV2WindowsShortNameFromOpen(file); err != nil || got != "" {
		_ = file.Close()
		t.Fatalf("short name after clear = %q, %v", got, err)
	}
	if err := setAtomicTransformV2WindowsShortNameOnOpen(file, shortLeaf); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := windows.FlushFileBuffers(windows.Handle(file.Fd())); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if got, err := atomicTransformV2WindowsShortNameFromOpen(file); err != nil ||
		!atomicTransformPathsEqual(got, shortLeaf) {
		_ = file.Close()
		t.Fatalf("short name after restore = %q, %v", got, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	alias, err := atomicTransformBoundInspect(dir, shortLeaf, atomicTransformMaxConfigBytes)
	if err != nil || alias.identity != state.identity {
		t.Fatalf("restored short alias identity = %q, %v; want %q", alias.identity, err, state.identity)
	}
}

func TestRepairAtomicTransformV2ReplacementPreservesEmptyOldShortNameNative(t *testing.T) {
	type fixture struct {
		dir     *atomicTransformBoundDirectory
		receipt atomicTransformV2Receipt
	}
	setup := func(t *testing.T, suffix string) fixture {
		t.Helper()
		directory := t.TempDir()
		targetName := "Long Configuration Without Alias " + suffix + ".json"
		targetPath := filepath.Join(directory, targetName)
		if err := os.WriteFile(targetPath, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir, err := bindAtomicTransformDirectory(directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dir.Close() })
		oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		target, err := openAtomicTransformV2ReplaceGuard(dir, targetName, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := setAtomicTransformV2WindowsShortNameOnOpen(target, ""); err != nil {
			_ = target.Close()
			t.Skipf("8.3 short-name mutation unavailable: %v", err)
		}
		if err := windows.FlushFileBuffers(windows.Handle(target.Fd())); err != nil {
			_ = target.Close()
			t.Fatal(err)
		}
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
		oldState, err = atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		oldShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil || oldShort != "" {
			t.Fatalf("cleared Old short name = %q, %v; want empty", oldShort, err)
		}
		stageName := ".tmp-cas-v2-empty-short-stage-" + suffix
		stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			t.Fatal(err)
		}
		if stageShort == "" {
			t.Skip("8.3 aliases unavailable for the Stage fixture")
		}
		return fixture{dir: dir, receipt: atomicTransformV2Receipt{
			OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
			TargetShortName: "", StageShortName: stageShort,
			TombstoneName: ".tmp-cas-v2-empty-short-old-" + suffix, StageFinalName: stageName,
			Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
		}}
	}
	queryTargetShort := func(t *testing.T, fixture fixture) string {
		t.Helper()
		file, err := openAtomicTransformV2ReplaceGuard(
			fixture.dir, filepath.Base(fixture.receipt.TargetPath), false,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		shortName, err := atomicTransformV2WindowsShortNameFromOpen(file)
		if err != nil {
			t.Fatal(err)
		}
		return shortName
	}

	t.Run("recorded Stage alias is cleared", func(t *testing.T) {
		fixture := setup(t, "clear")
		restore := installAtomicTransformV2PrePublicationHookForTest(
			fixture.receipt.TargetPath, atomicTransformV2ForcePreRepairShortNamesForTest,
		)
		defer restore()
		attempt, err := invokeAtomicTransformV2Replacement(fixture.dir, fixture.receipt, nil)
		if err != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
			t.Fatalf("raw Replace = disposition %d error %v", attempt.Disposition, err)
		}
		if got := queryTargetShort(t, fixture); !atomicTransformPathsEqual(got, fixture.receipt.StageShortName) {
			t.Fatalf("forced pre-publication target short name = %q, want Stage %q",
				got, fixture.receipt.StageShortName)
		}
		if err := flushAtomicTransformV2ReplacementForPublication(
			fixture.dir, fixture.receipt, attempt.Observed,
		); err != nil {
			t.Fatal(err)
		}
		var boundaries []string
		if err := repairAtomicTransformV2ReplacementShortName(
			fixture.dir, filepath.Base(fixture.receipt.TargetPath), fixture.receipt.TombstoneName,
			"", fixture.receipt.StageShortName, attempt.Observed.Target, attempt.Observed.Backup,
			func(boundary string) error { boundaries = append(boundaries, boundary); return nil },
		); err != nil {
			t.Fatal(err)
		}
		if got := queryTargetShort(t, fixture); got != "" {
			t.Fatalf("published target retained Stage short name %q", got)
		}
		if strings.Join(boundaries, ",") != strings.Join([]string{
			atomicTransformV2ReplaceBoundaryTargetShortSet,
			atomicTransformV2ReplaceBoundaryShortFlushed,
		}, ",") {
			t.Fatalf("empty-alias repair boundaries = %v", boundaries)
		}
	})

	t.Run("unexpected alias fails closed", func(t *testing.T) {
		fixture := setup(t, "foreign")
		unexpected := "UNOWND~1"
		restore := installAtomicTransformV2PrePublicationHookForTest(
			fixture.receipt.TargetPath,
			func(dir *atomicTransformBoundDirectory, target, _ *os.File, _ atomicTransformV2Receipt) error {
				current, err := atomicTransformV2WindowsShortNameFromOpen(target)
				if err != nil {
					return err
				}
				if current != "" {
					if err := setAtomicTransformV2WindowsShortNameOnOpen(target, ""); err != nil {
						return err
					}
				}
				if err := setAtomicTransformV2WindowsShortNameOnOpen(target, unexpected); err != nil {
					return err
				}
				if err := windows.FlushFileBuffers(windows.Handle(target.Fd())); err != nil {
					return err
				}
				return syncAtomicTransformBoundDirectoryPlatform(dir.file)
			},
		)
		defer restore()
		attempt, err := invokeAtomicTransformV2Replacement(fixture.dir, fixture.receipt, nil)
		if err != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
			t.Fatalf("raw Replace = disposition %d error %v", attempt.Disposition, err)
		}
		err = repairAtomicTransformV2ReplacementShortName(
			fixture.dir, filepath.Base(fixture.receipt.TargetPath), fixture.receipt.TombstoneName,
			"", fixture.receipt.StageShortName, attempt.Observed.Target, attempt.Observed.Backup,
		)
		if err == nil {
			t.Fatal("unexpected target alias was cleared")
		}
		if got := queryTargetShort(t, fixture); !atomicTransformPathsEqual(got, unexpected) {
			t.Fatalf("unexpected target alias after failed repair = %q, want %q", got, unexpected)
		}
	})
}

func TestAtomicTransformV2PrePublicationHookIsPathScopedConcurrently(t *testing.T) {
	type fixture struct {
		dir     *atomicTransformBoundDirectory
		receipt atomicTransformV2Receipt
	}
	makeFixture := func(root, suffix string) fixture {
		t.Helper()
		targetName := "settings-" + suffix + ".json"
		targetPath := filepath.Join(root, targetName)
		if err := os.WriteFile(targetPath, []byte("old-"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
		dir, err := bindAtomicTransformDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageName := ".tmp-cas-v2-stage-" + suffix
		stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new-"+suffix), 0o600)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		return fixture{dir: dir, receipt: atomicTransformV2Receipt{
			OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
			TargetShortName: targetShort, StageShortName: stageShort,
			TombstoneName: ".tmp-cas-v2-old-" + suffix, StageFinalName: stageName,
			Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
		}}
	}
	firstRoot, secondRoot := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	if err := os.MkdirAll(firstRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fixtures := []fixture{makeFixture(firstRoot, "first"), makeFixture(secondRoot, "second")}
	defer fixtures[0].dir.Close()
	defer fixtures[1].dir.Close()
	called := make(chan string, 2)
	restore := installAtomicTransformV2PrePublicationHookForTest(
		fixtures[0].receipt.TargetPath,
		func(_ *atomicTransformBoundDirectory, _, _ *os.File, receipt atomicTransformV2Receipt) error {
			called <- receipt.TargetPath
			return nil
		},
	)
	defer restore()
	results := make(chan error, len(fixtures))
	for index := range fixtures {
		fixture := fixtures[index]
		go func() {
			attempt, err := invokeAtomicTransformV2Replacement(fixture.dir, fixture.receipt, nil)
			if err == nil && attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
				err = fmt.Errorf("Replace disposition = %d, want ready for publication", attempt.Disposition)
			}
			results <- err
		}()
	}
	for range fixtures {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(called) != 1 {
		t.Fatalf("path-scoped hook call count = %d, want 1", len(called))
	}
	if got := <-called; !atomicTransformPathsEqual(got, fixtures[0].receipt.TargetPath) {
		t.Fatalf("path-scoped hook ran for %q, want %q", got, fixtures[0].receipt.TargetPath)
	}
}

func TestInvokeAtomicTransformV2ReplacementNativeSuccessStress(t *testing.T) {
	directory := t.TempDir()
	targetName := "Long Lived Configuration Settings.json"
	targetPath := filepath.Join(directory, targetName)
	if err := os.WriteFile(targetPath, []byte("generation-000"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Exercise the ADS LastWriteTime composition on every generation when the
	// local filesystem supports named streams; the gate remains useful without it.
	_ = os.WriteFile(targetPath+":stress-policy", []byte("preserved-ads"), 0o600)
	dir, err := bindAtomicTransformDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for generation := 1; generation <= 100; generation++ {
		oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatalf("generation %d inspect Old: %v", generation, err)
		}
		stageName := fmt.Sprintf(".tmp-cas-v2-ready-stress-%03d", generation)
		stageState, err := atomicTransformBoundCreate(
			dir, stageName, []byte(fmt.Sprintf("generation-%03d", generation)), 0o600,
		)
		if err != nil {
			t.Fatalf("generation %d create Stage: %v", generation, err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(
			dir, stageName, atomicTransformMaxConfigBytes,
		)
		if err != nil {
			t.Fatalf("generation %d inspect Stage: %v", generation, err)
		}
		targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil {
			t.Fatalf("generation %d capture Old short name: %v", generation, err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			t.Fatalf("generation %d capture Stage short name: %v", generation, err)
		}
		receipt := atomicTransformV2Receipt{
			OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
			TargetShortName: targetShort, StageShortName: stageShort,
			TombstoneName:  fmt.Sprintf(".tmp-cas-v2-old-stress-%03d", generation),
			StageFinalName: stageName,
			Old:            atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage:          atomicTransformV2ArtifactFromState(stageName, stageState),
		}
		attempt, err := invokeAtomicTransformV2Replacement(dir, receipt, nil)
		if err != nil {
			t.Fatalf("generation %d invoke ReplaceFileW: %v", generation, err)
		}
		if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
			t.Fatalf("generation %d ReplaceFileW code/error/disposition=%d/%v/%d: %s",
				generation, attempt.Code, attempt.CallError, attempt.Disposition,
				atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed))
		}
		if err := flushAtomicTransformV2ReplacementForPublication(dir, receipt, attempt.Observed); err != nil {
			t.Fatalf("generation %d flush publication-ready replacement: %v", generation, err)
		}
		if err := repairAtomicTransformV2ReplacementShortName(
			dir, targetName, receipt.TombstoneName, targetShort, stageShort,
			attempt.Observed.Target, attempt.Observed.Backup,
		); err != nil {
			t.Fatalf("generation %d repair short name: %v", generation, err)
		}
		if err := os.Remove(filepath.Join(dir.path, receipt.TombstoneName)); err != nil {
			t.Fatalf("generation %d remove test backup: %v", generation, err)
		}
	}
}

func TestInvokeAtomicTransformV2ReplacementFreshDACLStress(t *testing.T) {
	root := t.TempDir()
	for iteration := 0; iteration < 100; iteration++ {
		directory := filepath.Join(root, fmt.Sprintf("fresh-%03d", iteration))
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		targetName := "Protected Configuration Settings.json"
		targetPath := filepath.Join(directory, targetName)
		if err := os.WriteFile(targetPath, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Alternate protected and naturally inherited Old DACLs. The subprocess
		// terminal matrix uses inherited DACLs, while production often receives a
		// file already hardened by safefile.
		if iteration%2 == 0 {
			if err := safefile.ProtectFile(targetPath); err != nil {
				t.Fatalf("iteration %d protect Old: %v", iteration, err)
			}
		}
		if iteration%4 >= 2 {
			if err := os.WriteFile(targetPath+":protected-stress", []byte("old-ads"), 0o600); err != nil {
				t.Fatalf("iteration %d add Old ADS: %v", iteration, err)
			}
		}
		dir, err := bindAtomicTransformDirectory(directory)
		if err != nil {
			t.Fatal(err)
		}
		oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageName := fmt.Sprintf(".tmp-cas-v2-fresh-stage-%03d", iteration)
		stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new"), 0o600)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		receipt := atomicTransformV2Receipt{
			OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
			TargetShortName: targetShort, StageShortName: stageShort,
			TombstoneName:  fmt.Sprintf(".tmp-cas-v2-fresh-old-%03d", iteration),
			StageFinalName: stageName,
			Old:            atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage:          atomicTransformV2ArtifactFromState(stageName, stageState),
		}
		attempt, invokeErr := invokeAtomicTransformV2Replacement(dir, receipt, nil)
		if invokeErr != nil {
			_ = dir.Close()
			t.Fatalf("iteration %d invoke: %v", iteration, invokeErr)
		}
		if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
			_ = dir.Close()
			t.Fatalf("iteration %d code/error/disposition=%d/%v/%d: %s", iteration,
				attempt.Code, attempt.CallError, attempt.Disposition,
				atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed))
		}
		if attempt.Observed.Target.preservedMetadataDigest != receipt.Old.PreservedMetadataSHA256 {
			_ = dir.Close()
			t.Fatalf("iteration %d published DACL/metadata did not converge to authenticated Old", iteration)
		}
		if err := dir.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRepairAtomicTransformV2ReplacementDACLAuthenticatesExactOneWayChange(t *testing.T) {
	type fixture struct {
		dir           *atomicTransformBoundDirectory
		receipt       atomicTransformV2Receipt
		observed      atomicTransformV2ReplaceObservation
		oldDACL       string
		inheritedDACL string
	}
	setDACL := func(t *testing.T, path, sddl string, protected bool) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatalf("construct DACL %q: %v", sddl, err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("extract DACL %q: %v", sddl, err)
		}
		information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
		if protected {
			information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		}
		if err := windows.SetNamedSecurityInfo(
			path, windows.SE_FILE_OBJECT, information, nil, nil, dacl, nil,
		); err != nil {
			t.Fatalf("set DACL %q on %s: %v", sddl, path, err)
		}
	}
	inheritedFromOld := func(t *testing.T, old string) string {
		t.Helper()
		prefix, aces, err := atomicTransformV2WindowsDACLParts(old)
		if err != nil || prefix != "D:P" {
			t.Fatalf("protected Old DACL parts = %q/%v, %v", prefix, aces, err)
		}
		var result strings.Builder
		result.WriteString("D:")
		for _, ace := range aces {
			first := strings.IndexByte(ace, ';')
			secondRelative := strings.IndexByte(ace[first+1:], ';')
			if first < 0 || secondRelative < 0 {
				t.Fatalf("invalid Old ACE %q", ace)
			}
			second := first + 1 + secondRelative
			if strings.Contains(ace[first+1:second], "ID") {
				t.Fatalf("Old ACE is already inherited: %q", ace)
			}
			result.WriteString(ace[:second])
			result.WriteString("ID")
			result.WriteString(ace[second:])
		}
		return result.String()
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		directory := t.TempDir()
		targetName := "settings.json"
		stageName := ".tmp-cas-v2-dacl-repair-stage"
		targetPath := filepath.Join(directory, targetName)
		currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || currentUser == nil || currentUser.User.Sid == nil {
			t.Fatalf("resolve current user: %v", err)
		}
		setDACL(t, directory, fmt.Sprintf(
			"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", currentUser.User.Sid,
		), true)
		dir, err := bindAtomicTransformDirectory(directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dir.Close() })
		oldState, err := atomicTransformBoundCreate(dir, targetName, []byte("old"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		oldState, err = atomicTransformBoundInspectFilePrivate(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil {
			t.Fatal(err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			t.Fatal(err)
		}
		receipt := atomicTransformV2Receipt{
			OldExists: true, TargetPath: targetPath,
			TargetShortName: targetShort, StageShortName: stageShort,
			TombstoneName: ".tmp-cas-v2-dacl-repair-old", StageFinalName: stageName,
			Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
		}
		if err := replaceAtomicTransformV2ExistingFile(
			targetPath, filepath.Join(directory, stageName), filepath.Join(directory, receipt.TombstoneName),
		); err != nil {
			t.Fatalf("native ReplaceFileW: %v", err)
		}
		observed, err := observeAtomicTransformV2Replacement(dir, receipt)
		if err != nil {
			t.Fatal(err)
		}
		backup, err := openAtomicTransformV2DACLRepairGuard(dir, receipt.TombstoneName, false)
		if err != nil {
			t.Fatal(err)
		}
		oldDACL, err := atomicTransformV2WindowsDACLCanonicalFromOpen(backup)
		_ = backup.Close()
		if err != nil {
			t.Fatal(err)
		}
		inheritedDACL := inheritedFromOld(t, oldDACL)
		setDACL(t, targetPath, inheritedDACL, false)
		observed, err = observeAtomicTransformV2Replacement(dir, receipt)
		if err != nil {
			t.Fatal(err)
		}
		target, err := openAtomicTransformV2DACLRepairGuard(dir, targetName, false)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := atomicTransformV2WindowsDACLCanonicalFromOpen(target)
		_ = target.Close()
		if err != nil {
			t.Fatal(err)
		}
		if normalized, normalizeErr := atomicTransformV2WindowsDACLIsReplaceNormalization(actual, oldDACL); normalizeErr != nil || !normalized {
			t.Fatalf("fixture DACL is not exact one-way normalization: %t, %v\nold=%q\nrequested=%q\nactual=%q", normalized, normalizeErr, oldDACL, inheritedDACL, actual)
		}
		return fixture{dir: dir, receipt: receipt, observed: observed, oldDACL: oldDACL, inheritedDACL: actual}
	}

	t.Run("repairs and is idempotent", func(t *testing.T) {
		fixture := setup(t)
		repaired, err := repairAtomicTransformV2ReplacementDACL(fixture.dir, fixture.receipt, fixture.observed)
		if err != nil || !repaired {
			t.Fatalf("repair = %t, %v; want true", repaired, err)
		}
		after, err := observeAtomicTransformV2Replacement(fixture.dir, fixture.receipt)
		if err != nil {
			t.Fatal(err)
		}
		if after.Target.preservedMetadataDigest != fixture.receipt.Old.PreservedMetadataSHA256 ||
			classifyAtomicTransformV2ReplaceObservation(fixture.receipt, atomicTransformV2ReplaceSuccess, after) != atomicTransformV2ReplaceReadyForPublication {
			t.Fatal("repaired target is not publication-ready")
		}
		if repaired, err := repairAtomicTransformV2ReplacementDACL(fixture.dir, fixture.receipt, after); err != nil || repaired {
			t.Fatalf("idempotent repair = %t, %v; want false, nil", repaired, err)
		}
	})

	for _, raceTarget := range []bool{false, true} {
		name := "backup descriptor change"
		if raceTarget {
			name = "target descriptor change"
		}
		t.Run(name, func(t *testing.T) {
			fixture := setup(t)
			targetBefore := fixture.inheritedDACL
			repaired, err := repairAtomicTransformV2ReplacementDACL(
				fixture.dir, fixture.receipt, fixture.observed,
				func(target, backup *os.File) error {
					path := filepath.Join(fixture.dir.path, fixture.receipt.TombstoneName)
					if raceTarget {
						path = fixture.receipt.TargetPath
					}
					setDACL(t, path, "D:P(A;;GR;;;SY)", true)
					_ = target
					_ = backup
					return nil
				},
			)
			if err == nil || repaired {
				t.Fatalf("raced repair = %t, %v; want false conflict", repaired, err)
			}
			if !raceTarget {
				target, openErr := openAtomicTransformV2DACLRepairGuard(fixture.dir, filepath.Base(fixture.receipt.TargetPath), false)
				if openErr != nil {
					t.Fatal(openErr)
				}
				got, readErr := atomicTransformV2WindowsDACLCanonicalFromOpen(target)
				_ = target.Close()
				if readErr != nil || got != targetBefore {
					t.Fatalf("backup race mutated target DACL = %q, %v; want %q", got, readErr, targetBefore)
				}
			}
		})
	}
}

func TestInvokeAtomicTransformV2ReplacementInjectedOutcomesNative(t *testing.T) {
	type fixture struct {
		dir        *atomicTransformBoundDirectory
		receipt    atomicTransformV2Receipt
		targetPath string
		stagePath  string
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		directory := t.TempDir()
		targetName, stageName := "settings.json", ".tmp-cas-v2-injected-stage"
		targetPath := filepath.Join(directory, targetName)
		if err := os.WriteFile(targetPath, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir, err := bindAtomicTransformDirectory(directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dir.Close() })
		oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new"), 0o600)
		if err != nil {
			t.Fatal(err)
		}
		stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
		if err != nil {
			t.Fatal(err)
		}
		targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
		if err != nil {
			t.Fatal(err)
		}
		stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
		if err != nil {
			t.Fatal(err)
		}
		receipt := atomicTransformV2Receipt{
			OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
			TargetShortName: targetShort, StageShortName: stageShort,
			TombstoneName: ".tmp-cas-v2-injected-old", StageFinalName: stageName,
			Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
			Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
		}
		return fixture{dir: dir, receipt: receipt, targetPath: targetPath,
			stagePath: filepath.Join(directory, stageName)}
	}
	assertStable := func(t *testing.T, fixture fixture, observed atomicTransformV2ReplaceObservation) {
		t.Helper()
		after, err := observeAtomicTransformV2Replacement(fixture.dir, fixture.receipt)
		if err != nil {
			t.Fatal(err)
		}
		if !atomicTransformArtifactStatesEqualExact(after.Target, observed.Target) ||
			!atomicTransformArtifactStatesEqualExact(after.Backup, observed.Backup) ||
			!atomicTransformArtifactStatesEqualExact(after.Stage, observed.Stage) {
			t.Fatalf("classified outcome changed in place: before=%s after=%s",
				atomicTransformV2ReplaceObservationSummary(fixture.receipt, observed),
				atomicTransformV2ReplaceObservationSummary(fixture.receipt, after))
		}
	}

	for _, code := range []uintptr{1175, 1176} {
		t.Run(fmt.Sprintf("error-%d-untouched", code), func(t *testing.T) {
			fixture := setup(t)
			before, err := observeAtomicTransformV2Replacement(fixture.dir, fixture.receipt)
			if err != nil {
				t.Fatal(err)
			}
			attempt, err := invokeAtomicTransformV2Replacement(
				fixture.dir, fixture.receipt,
				func(_, _, _ string) error { return windowsErrorForAtomicTransformV2Test(code) },
			)
			if err != nil {
				t.Fatal(err)
			}
			if attempt.Disposition != atomicTransformV2ReplaceRetryUntouched {
				t.Fatalf("error %d disposition = %d, want retry untouched", code, attempt.Disposition)
			}
			if !atomicTransformArtifactStatesEqualExact(before.Target, attempt.Observed.Target) ||
				!atomicTransformArtifactStatesEqualExact(before.Stage, attempt.Observed.Stage) ||
				attempt.Observed.Backup.exists {
				t.Fatalf("error %d changed the untouched namespace", code)
			}
			assertStable(t, fixture, attempt.Observed)
		})
	}

	t.Run("1177-known-stage-content-restores-only-old", func(t *testing.T) {
		fixture := setup(t)
		attempt, err := invokeAtomicTransformV2Replacement(
			fixture.dir, fixture.receipt,
			func(targetPath, stagePath, backupPath string) error {
				if err := os.Rename(targetPath, backupPath); err != nil {
					return err
				}
				pointer, pointerErr := windows.UTF16PtrFromString(stagePath)
				if pointerErr != nil {
					return pointerErr
				}
				attributes, attributeErr := windows.GetFileAttributes(pointer)
				if attributeErr != nil {
					return attributeErr
				}
				if attributeErr = windows.SetFileAttributes(pointer, attributes|windows.FILE_ATTRIBUTE_HIDDEN); attributeErr != nil {
					return attributeErr
				}
				return windowsErrorForAtomicTransformV2Test(1177)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.Disposition != atomicTransformV2ReplaceRestoreOldThenRetry {
			t.Fatalf("1177 disposition = %d, want exact Old restore: %s", attempt.Disposition,
				atomicTransformV2ReplaceObservationSummary(fixture.receipt, attempt.Observed))
		}
		stageBeforeRestore := attempt.Observed.Stage
		if err := restoreAtomicTransformV2Replace1177(
			fixture.dir, fixture.receipt, attempt.Observed,
		); err != nil {
			t.Fatal(err)
		}
		after, err := observeAtomicTransformV2Replacement(fixture.dir, fixture.receipt)
		if err != nil {
			t.Fatal(err)
		}
		if !after.Target.exists || after.Target.identity != fixture.receipt.Old.Identity ||
			after.Backup.exists || !atomicTransformArtifactStatesEqualExact(after.Stage, stageBeforeRestore) {
			t.Fatalf("1177 restore changed more than exact Old namespace: %s",
				atomicTransformV2ReplaceObservationSummary(fixture.receipt, after))
		}
	})

	t.Run("1177-foreign-stage-preserved-ambiguous", func(t *testing.T) {
		fixture := setup(t)
		originalStage := fixture.stagePath + ".original"
		attempt, err := invokeAtomicTransformV2Replacement(
			fixture.dir, fixture.receipt,
			func(targetPath, stagePath, backupPath string) error {
				if err := os.Rename(targetPath, backupPath); err != nil {
					return err
				}
				if err := os.Rename(stagePath, originalStage); err != nil {
					return err
				}
				if err := os.WriteFile(stagePath, []byte("foreign-stage"), 0o600); err != nil {
					return err
				}
				return windowsErrorForAtomicTransformV2Test(1177)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.Disposition != atomicTransformV2ReplaceAmbiguous {
			t.Fatalf("foreign-Stage 1177 disposition = %d, want preserved ambiguous", attempt.Disposition)
		}
		assertStable(t, fixture, attempt.Observed)
		if data, err := os.ReadFile(originalStage); err != nil || string(data) != "new" {
			t.Fatalf("recorded Stage side name = %q, %v; want new", data, err)
		}
	})

	t.Run("stage-name-swap-before-api-is-preserved-ambiguous", func(t *testing.T) {
		fixture := setup(t)
		originalStage := fixture.stagePath + ".original"
		attempt, err := invokeAtomicTransformV2Replacement(
			fixture.dir, fixture.receipt,
			func(targetPath, stagePath, backupPath string) error {
				if err := os.Rename(stagePath, originalStage); err != nil {
					return err
				}
				if err := os.WriteFile(stagePath, []byte("foreign-stage"), 0o600); err != nil {
					return err
				}
				return replaceAtomicTransformV2ExistingFile(targetPath, stagePath, backupPath)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceAmbiguous {
			t.Fatalf("Stage swap = code/error/disposition %d/%v/%d; want successful ambiguous",
				attempt.Code, attempt.CallError, attempt.Disposition)
		}
		assertStable(t, fixture, attempt.Observed)
		if string(attempt.Observed.Target.data) != "foreign-stage" {
			t.Fatalf("Stage-swap live data = %q, want foreign-stage", attempt.Observed.Target.data)
		}
	})

	t.Run("target-name-swap-before-api-is-preserved-ambiguous", func(t *testing.T) {
		fixture := setup(t)
		originalOld := fixture.targetPath + ".original"
		attempt, err := invokeAtomicTransformV2Replacement(
			fixture.dir, fixture.receipt,
			func(targetPath, stagePath, backupPath string) error {
				if err := os.Rename(targetPath, originalOld); err != nil {
					return err
				}
				if err := os.WriteFile(targetPath, []byte("foreign-live"), 0o600); err != nil {
					return err
				}
				return replaceAtomicTransformV2ExistingFile(targetPath, stagePath, backupPath)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceAmbiguous {
			t.Fatalf("target swap = code/error/disposition %d/%v/%d; want successful ambiguous",
				attempt.Code, attempt.CallError, attempt.Disposition)
		}
		assertStable(t, fixture, attempt.Observed)
		if string(attempt.Observed.Backup.data) != "foreign-live" {
			t.Fatalf("target-swap backup data = %q, want foreign-live", attempt.Observed.Backup.data)
		}
		if data, err := os.ReadFile(originalOld); err != nil || string(data) != "old" {
			t.Fatalf("original Old side name = %q, %v; want old", data, err)
		}
	})

	t.Run("stage-in-place-edit-before-api-is-preserved-ambiguous", func(t *testing.T) {
		fixture := setup(t)
		attempt, err := invokeAtomicTransformV2Replacement(
			fixture.dir, fixture.receipt,
			func(targetPath, stagePath, backupPath string) error {
				if err := os.WriteFile(stagePath, []byte("edited-stage"), 0o600); err != nil {
					return err
				}
				return replaceAtomicTransformV2ExistingFile(targetPath, stagePath, backupPath)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceAmbiguous {
			t.Fatalf("Stage edit = code/error/disposition %d/%v/%d; want successful ambiguous",
				attempt.Code, attempt.CallError, attempt.Disposition)
		}
		assertStable(t, fixture, attempt.Observed)
		if string(attempt.Observed.Target.data) != "edited-stage" {
			t.Fatalf("Stage-edit live data = %q, want edited-stage", attempt.Observed.Target.data)
		}
	})
}

func TestInvokeAtomicTransformV2ReplacementNativePreservesMetadata(t *testing.T) {
	directory := t.TempDir()
	targetName := "Long Configuration Settings.json"
	targetPath := filepath.Join(directory, targetName)
	if err := os.WriteFile(targetPath, []byte("old-main"), 0o600); err != nil {
		t.Fatal(err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		t.Fatalf("resolve current user for custom DACL: %v", err)
	}
	// Deliberately retain three ordered safe ACEs. The leading redundant user
	// read ACE makes this DACL observably different from the private Stage DACL,
	// while user and SYSTEM still retain full control.
	customDescriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;GR;;;%s)(A;;FA;;;SY)(A;;FA;;;%s)",
		currentUser.User.Sid, currentUser.User.Sid, currentUser.User.Sid,
	))
	if err != nil {
		t.Fatal(err)
	}
	customDACL, _, err := customDescriptor.DACL()
	if err != nil || customDACL == nil {
		t.Fatalf("construct custom DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		targetPath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, customDACL, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath+":defenseclaw-policy", []byte("old-ads"), 0o600); err != nil {
		t.Skipf("NTFS alternate streams unavailable: %v", err)
	}
	targetPointer, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	oldAttributes, err := windows.GetFileAttributes(targetPointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(
		targetPointer,
		(oldAttributes&^(windows.FILE_ATTRIBUTE_ARCHIVE|windows.FILE_ATTRIBUTE_NORMAL))|
			windows.FILE_ATTRIBUTE_HIDDEN,
	); err != nil {
		t.Fatal(err)
	}
	// Compression is part of the native preservation assertion when supported.
	oldFile, err := os.OpenFile(targetPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	compression := uint16(2)
	var returned uint32
	compressionEnabled := windows.DeviceIoControl(
		windows.Handle(oldFile.Fd()), windows.FSCTL_SET_COMPRESSION,
		(*byte)(unsafe.Pointer(&compression)), uint32(unsafe.Sizeof(compression)), nil, 0, &returned, nil,
	) == nil
	if err := oldFile.Close(); err != nil {
		t.Fatal(err)
	}

	dir, err := bindAtomicTransformDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	stageName := ".tmp-cas-v2-ready-native-replace-test"
	stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new-main"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join(directory, stageName)
	stagePointer, err := windows.UTF16PtrFromString(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	stageAttributes, err := windows.GetFileAttributes(stagePointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(stagePointer, stageAttributes|windows.FILE_ATTRIBUTE_SYSTEM); err != nil {
		t.Fatal(err)
	}
	stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	oldSecurity, err := atomicTransformV2ReadWindowsSecurityPartsForTest(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	stageSecurity, err := atomicTransformV2ReadWindowsSecurityPartsForTest(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	if oldSecurity.dacl == stageSecurity.dacl || strings.Count(oldSecurity.dacl, "(") != 3 {
		t.Fatalf("custom ordered Old DACL was not established: Old=%q Stage=%q",
			oldSecurity.dacl, stageSecurity.dacl)
	}
	targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
	if err != nil {
		t.Fatal(err)
	}
	stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
	if err != nil {
		t.Fatal(err)
	}
	receipt := atomicTransformV2Receipt{
		OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
		TargetShortName: targetShort, StageShortName: stageShort,
		TombstoneName: ".tmp-cas-v2-old-native-replace-test", StageFinalName: stageName,
		Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
		Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
	}
	attempt, err := invokeAtomicTransformV2Replacement(dir, receipt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.CallError != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
		t.Fatalf("native ReplaceFileW = code %d disposition %d error %v; target id/data/preserved/creation/stage/write/links=%s/%s/%s/%d/%s/%d/%d want=%s/%s/%d/%s/%d/%d backupOld=%v",
			attempt.Code, attempt.Disposition, attempt.CallError,
			attempt.Observed.Target.identity, attempt.Observed.Target.digest,
			attempt.Observed.Target.preservedMetadataDigest, attempt.Observed.Target.creationTime,
			attempt.Observed.Target.stageOwnedMetadataDigest, attempt.Observed.Target.lastWriteTime,
			attempt.Observed.Target.linkCount,
			receipt.Stage.Identity, receipt.Old.PreservedMetadataSHA256, receipt.Old.CreationTime,
			receipt.Stage.StageOwnedMetadataSHA256, receipt.Stage.LastWriteTime, receipt.Stage.LinkCount,
			atomicTransformV2OldExactMatches(receipt.Old, attempt.Observed.Backup))
	}
	if err := flushAtomicTransformV2ReplacementForPublication(dir, receipt, attempt.Observed); err != nil {
		t.Fatal(err)
	}
	if err := repairAtomicTransformV2ReplacementShortName(
		dir, targetName, receipt.TombstoneName, targetShort, stageShort,
		attempt.Observed.Target, attempt.Observed.Backup,
	); err != nil {
		t.Fatal(err)
	}
	after, err := observeAtomicTransformV2Replacement(dir, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if after.Target.identity != stageState.identity || string(after.Target.data) != "new-main" {
		t.Fatalf("published target identity/data = %q/%q; want %q/new-main",
			after.Target.identity, after.Target.data, stageState.identity)
	}
	if after.Backup.identity != oldState.identity || string(after.Backup.data) != "old-main" {
		t.Fatalf("backup identity/data = %q/%q; want %q/old-main",
			after.Backup.identity, after.Backup.data, oldState.identity)
	}
	targetSecurity, err := atomicTransformV2ReadWindowsSecurityPartsForTest(filepath.Join(dir.path, targetName))
	if err != nil {
		t.Fatal(err)
	}
	backupSecurity, err := atomicTransformV2ReadWindowsSecurityPartsForTest(
		filepath.Join(dir.path, receipt.TombstoneName),
	)
	if err != nil {
		t.Fatal(err)
	}
	if targetSecurity.dacl != oldSecurity.dacl {
		t.Fatalf("published custom DACL/order = %q, want Old %q", targetSecurity.dacl, oldSecurity.dacl)
	}
	if targetSecurity.owner != stageSecurity.owner || targetSecurity.group != stageSecurity.group {
		t.Fatalf("published owner/group = %s/%s, want Stage %s/%s",
			targetSecurity.owner, targetSecurity.group, stageSecurity.owner, stageSecurity.group)
	}
	if backupSecurity != oldSecurity {
		t.Fatalf("backup owner/group/DACL = %+v, want exact Old %+v", backupSecurity, oldSecurity)
	}
	if after.Target.creationTime != oldState.creationTime ||
		after.Target.preservedMetadataDigest != oldState.preservedMetadataDigest {
		t.Fatalf("ReplaceFileW metadata merge mismatch: target creation/preserved=%d/%s old=%d/%s",
			after.Target.creationTime, after.Target.preservedMetadataDigest,
			oldState.creationTime, oldState.preservedMetadataDigest)
	}
	ads, err := os.ReadFile(filepath.Join(dir.path, targetName) + ":defenseclaw-policy")
	if err != nil || string(ads) != "old-ads" {
		t.Fatalf("published ADS = %q, %v", ads, err)
	}
	if compressionEnabled {
		file, err := os.Open(filepath.Join(dir.path, targetName))
		if err != nil {
			t.Fatal(err)
		}
		witness, witnessErr := atomicTransformV2WindowsMetadataFromOpen(file)
		_ = file.Close()
		if witnessErr != nil || witness.Compression == 0 {
			t.Fatalf("published compression = %d, %v", witness.Compression, witnessErr)
		}
	}
	finalAttributes, err := windows.GetFileAttributes(targetPointer)
	if err != nil {
		t.Fatal(err)
	}
	if finalAttributes&windows.FILE_ATTRIBUTE_HIDDEN == 0 ||
		finalAttributes&windows.FILE_ATTRIBUTE_SYSTEM != 0 {
		t.Fatalf("published attributes = 0x%x; want Old Hidden and no Stage-only System", finalAttributes)
	}
}

func TestInvokeAtomicTransformV2ReplacementRejectsOwnerGroupRaceNative(t *testing.T) {
	directory := t.TempDir()
	targetName, stageName := "owner-race-old.json", ".tmp-cas-v2-owner-race-stage"
	targetPath := filepath.Join(directory, targetName)
	if err := os.WriteFile(targetPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := bindAtomicTransformDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	oldState, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	stageState, err := atomicTransformBoundCreate(dir, stageName, []byte("new"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	stageState, err = atomicTransformBoundInspectFilePrivate(dir, stageName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	targetShort, err := atomicTransformV2CaptureWindowsShortName(dir, targetName, oldState)
	if err != nil {
		t.Fatal(err)
	}
	stageShort, err := atomicTransformV2CaptureWindowsShortName(dir, stageName, stageState)
	if err != nil {
		t.Fatal(err)
	}
	receipt := atomicTransformV2Receipt{
		OldExists: true, TargetPath: filepath.Join(dir.path, targetName),
		TargetShortName: targetShort, StageShortName: stageShort,
		TombstoneName: ".tmp-cas-v2-owner-race-old", StageFinalName: stageName,
		Old:   atomicTransformV2ArtifactFromState(targetName, oldState),
		Stage: atomicTransformV2ArtifactFromState(stageName, stageState),
	}
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Skipf("owner/group race capability unavailable: enumerate token groups: %v", err)
	}
	stageSecurity, err := atomicTransformV2ReadWindowsSecurityPartsForTest(filepath.Join(dir.path, stageName))
	if err != nil {
		t.Fatal(err)
	}
	type securityMutation struct {
		sid   *windows.SID
		owner bool
	}
	var candidates []securityMutation
	for _, group := range groups.AllGroups() {
		if group.Sid == nil || group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		if group.Attributes&windows.SE_GROUP_OWNER != 0 && group.Sid.String() != stageSecurity.owner {
			candidates = append(candidates, securityMutation{sid: group.Sid, owner: true})
		}
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Sid.String() != stageSecurity.group {
			candidates = append(candidates, securityMutation{sid: group.Sid})
		}
	}
	if len(candidates) == 0 {
		t.Skip("owner/group race capability unavailable: token has no alternate assignable SID")
	}
	mutation := ""
	attempt, err := invokeAtomicTransformV2Replacement(
		dir, receipt,
		func(targetPath, stagePath, backupPath string) error {
			for _, candidate := range candidates {
				securityInformation := windows.SECURITY_INFORMATION(windows.GROUP_SECURITY_INFORMATION)
				var owner, group *windows.SID
				if candidate.owner {
					securityInformation = windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION)
					owner = candidate.sid
				} else {
					group = candidate.sid
				}
				if setErr := windows.SetNamedSecurityInfo(
					stagePath, windows.SE_FILE_OBJECT, securityInformation,
					owner, group, nil, nil,
				); setErr == nil {
					kind := "group"
					if candidate.owner {
						kind = "owner"
					}
					mutation = kind + "=" + candidate.sid.String()
					break
				}
			}
			if mutation == "" {
				return windows.ERROR_PRIVILEGE_NOT_HELD
			}
			return replaceAtomicTransformV2ExistingFile(targetPath, stagePath, backupPath)
		},
	)
	if mutation == "" {
		t.Skipf("owner/group race capability unavailable: alternate owner/group assignment failed (%v)", attempt.CallError)
	}
	if err != nil {
		t.Fatal(err)
	}
	if attempt.CallError != nil || attempt.Code != atomicTransformV2ReplaceSuccess {
		t.Fatalf("owner-race ReplaceFileW = code %d error %v", attempt.Code, attempt.CallError)
	}
	if attempt.Observed.Target.ownerGroupDigest == receipt.Stage.OwnerGroupSHA256 {
		t.Fatalf("security mutation %s did not change the target owner/group witness", mutation)
	}
	if attempt.Disposition != atomicTransformV2ReplaceAmbiguous {
		t.Fatalf("owner/group race disposition = %d, want preserved ambiguous: %s",
			attempt.Disposition, atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed))
	}
	after, err := observeAtomicTransformV2Replacement(dir, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !atomicTransformArtifactStatesEqualExact(after.Target, attempt.Observed.Target) ||
		!atomicTransformArtifactStatesEqualExact(after.Backup, attempt.Observed.Backup) ||
		after.Stage.exists != attempt.Observed.Stage.exists {
		t.Fatal("ambiguous owner/group race was mutated after classification")
	}
}

func TestNativeReplaceFileWLastWriteCompositionMatrix(t *testing.T) {
	variants := []struct {
		name        string
		ads         bool
		hidden      bool
		compression bool
	}{
		{"plain", false, false, false},
		{"ads", true, false, false},
		{"hidden", false, true, false},
		{"ads-hidden", true, true, false},
		{"compression", false, false, true},
		{"ads-compression", true, false, true},
		{"hidden-compression", false, true, true},
		{"ads-hidden-compression", true, true, true},
	}
	filetimeValue := func(filetime windows.Filetime) uint64 {
		return uint64(filetime.HighDateTime)<<32 | uint64(filetime.LowDateTime)
	}
	setTimes := func(t *testing.T, path string, creation, lastWrite windows.Filetime) {
		t.Helper()
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetFileTime(
			windows.Handle(file.Fd()), &creation, nil, &lastWrite,
		); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	oldCreation := windows.NsecToFiletime(time.Date(2018, 1, 2, 3, 4, 5, 0, time.UTC).UnixNano())
	oldLastWrite := windows.NsecToFiletime(time.Date(2019, 2, 3, 4, 5, 6, 0, time.UTC).UnixNano())
	stageCreation := windows.NsecToFiletime(time.Date(2023, 3, 4, 5, 6, 7, 0, time.UTC).UnixNano())
	stageLastWrite := windows.NsecToFiletime(time.Date(2024, 4, 5, 6, 7, 8, 0, time.UTC).UnixNano())
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "old.json")
			stage := filepath.Join(dir, "stage.json")
			backup := filepath.Join(dir, "backup.json")
			if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stage, []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
			if variant.ads {
				if err := os.WriteFile(target+":metadata", []byte("ads"), 0o600); err != nil {
					t.Skip(err)
				}
			}
			if variant.hidden {
				ptr, _ := windows.UTF16PtrFromString(target)
				attrs, _ := windows.GetFileAttributes(ptr)
				if err := windows.SetFileAttributes(ptr, attrs|windows.FILE_ATTRIBUTE_HIDDEN); err != nil {
					t.Fatal(err)
				}
			}
			if variant.compression {
				file, err := os.OpenFile(target, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				format := uint16(2)
				var returned uint32
				err = windows.DeviceIoControl(
					windows.Handle(file.Fd()), windows.FSCTL_SET_COMPRESSION,
					(*byte)(unsafe.Pointer(&format)), 2, nil, 0, &returned, nil,
				)
				_ = file.Close()
				if err != nil {
					t.Skip(err)
				}
			}
			// Metadata setup itself can advance LastWriteTime. Pin deliberately
			// distinct values afterwards so the composition contract is observable.
			setTimes(t, target, oldCreation, oldLastWrite)
			setTimes(t, stage, stageCreation, stageLastWrite)
			witness := func(path string) atomicTransformV2WindowsMetadataWitness {
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				got, err := atomicTransformV2WindowsMetadataFromOpen(file)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			oldBefore, stageBefore := witness(target), witness(stage)
			if oldBefore.LastWriteTime != filetimeValue(oldLastWrite) ||
				stageBefore.LastWriteTime != filetimeValue(stageLastWrite) {
				t.Fatalf("fixed timestamps were not applied: Old=%d Stage=%d", oldBefore.LastWriteTime, stageBefore.LastWriteTime)
			}
			// NTFS records an ADS-bearing ReplaceFileW publication at call time.
			// Allow a small wall-clock envelope for timestamp granularity and load.
			callLower := filetimeValue(windows.NsecToFiletime(time.Now().Add(-2 * time.Second).UnixNano()))
			if err := replaceAtomicTransformV2ExistingFile(target, stage, backup); err != nil {
				t.Fatal(err)
			}
			callUpper := filetimeValue(windows.NsecToFiletime(time.Now().Add(2 * time.Second).UnixNano()))
			targetAfter, backupAfter := witness(target), witness(backup)
			if targetAfter.Identity != stageBefore.Identity {
				t.Fatalf("target identity = %s, want Stage %s", targetAfter.Identity, stageBefore.Identity)
			}
			if targetAfter.CreationTime != oldBefore.CreationTime ||
				targetAfter.PreservedDigest != oldBefore.PreservedDigest ||
				targetAfter.ProtectionSHA256 != oldBefore.ProtectionSHA256 {
				t.Fatalf("Old-preserved target composition mismatch")
			}
			if backupAfter.Identity != oldBefore.Identity ||
				backupAfter.CreationTime != oldBefore.CreationTime ||
				backupAfter.LastWriteTime != oldBefore.LastWriteTime ||
				backupAfter.PreservedDigest != oldBefore.PreservedDigest ||
				backupAfter.ProtectionSHA256 != oldBefore.ProtectionSHA256 {
				t.Fatalf("backup is not the exact Old witness")
			}
			if !variant.ads {
				if targetAfter.LastWriteTime != stageBefore.LastWriteTime {
					t.Fatalf("no-ADS target LastWriteTime = %d, want Stage %d",
						targetAfter.LastWriteTime, stageBefore.LastWriteTime)
				}
			} else {
				if targetAfter.LastWriteTime == stageBefore.LastWriteTime {
					t.Fatalf("ADS target unexpectedly retained Stage LastWriteTime %d", stageBefore.LastWriteTime)
				}
				if targetAfter.LastWriteTime < callLower || targetAfter.LastWriteTime > callUpper {
					t.Fatalf("ADS target LastWriteTime %d is outside ReplaceFileW interval [%d,%d]",
						targetAfter.LastWriteTime, callLower, callUpper)
				}
			}
		})
	}
}

func TestNativeReplaceFileWHardLinkTopologyMatrix(t *testing.T) {
	for _, variant := range []struct {
		name       string
		oldLinks   uint32
		stageLinks uint32
	}{
		{"old-1-stage-1", 1, 1},
		{"old-1-stage-2", 1, 2},
		{"old-2-stage-1", 2, 1},
		{"old-2-stage-2", 2, 2},
	} {
		t.Run(variant.name, func(t *testing.T) {
			directory := t.TempDir()
			targetName, stageName, backupName := "old.json", "stage.json", "backup.json"
			target := filepath.Join(directory, targetName)
			stage := filepath.Join(directory, stageName)
			backup := filepath.Join(directory, backupName)
			if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(stage, []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
			oldPeer, stagePeer := filepath.Join(directory, "old-peer.json"), filepath.Join(directory, "stage-peer.json")
			if variant.oldLinks == 2 {
				if err := os.Link(target, oldPeer); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			}
			if variant.stageLinks == 2 {
				if err := os.Link(stage, stagePeer); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			}

			dir, err := bindAtomicTransformDirectory(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			oldBefore, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
			if err != nil {
				t.Fatal(err)
			}
			stageBefore, err := atomicTransformBoundInspect(dir, stageName, atomicTransformMaxConfigBytes)
			if err != nil {
				t.Fatal(err)
			}
			if oldBefore.linkCount != variant.oldLinks || stageBefore.linkCount != variant.stageLinks {
				t.Fatalf("pre-Replace link topology Old/Stage = %d/%d, want %d/%d",
					oldBefore.linkCount, stageBefore.linkCount, variant.oldLinks, variant.stageLinks)
			}
			receipt := atomicTransformV2Receipt{
				OldExists: true, TargetPath: target,
				TombstoneName: backupName, StageFinalName: stageName,
				Old:   atomicTransformV2ArtifactFromState(targetName, oldBefore),
				Stage: atomicTransformV2ArtifactFromState(stageName, stageBefore),
			}
			if err := replaceAtomicTransformV2ExistingFile(target, stage, backup); err != nil {
				t.Fatal(err)
			}
			targetAfter, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
			if err != nil {
				t.Fatal(err)
			}
			backupAfter, err := atomicTransformBoundInspect(dir, backupName, atomicTransformMaxConfigBytes)
			if err != nil {
				t.Fatal(err)
			}
			if targetAfter.identity != stageBefore.identity || targetAfter.linkCount != variant.stageLinks {
				t.Fatalf("published target identity/links = %s/%d, want Stage %s/%d",
					targetAfter.identity, targetAfter.linkCount, stageBefore.identity, variant.stageLinks)
			}
			if backupAfter.identity != oldBefore.identity || backupAfter.linkCount != variant.oldLinks {
				t.Fatalf("backup identity/links = %s/%d, want Old %s/%d",
					backupAfter.identity, backupAfter.linkCount, oldBefore.identity, variant.oldLinks)
			}
			if variant.oldLinks == 2 {
				peer, err := atomicTransformBoundInspect(dir, filepath.Base(oldPeer), atomicTransformMaxConfigBytes)
				if err != nil || peer.identity != backupAfter.identity {
					t.Fatalf("Old hard-link peer identity = %s, %v; want %s", peer.identity, err, backupAfter.identity)
				}
			}
			if variant.stageLinks == 2 {
				peer, err := atomicTransformBoundInspect(dir, filepath.Base(stagePeer), atomicTransformMaxConfigBytes)
				if err != nil || peer.identity != targetAfter.identity {
					t.Fatalf("Stage hard-link peer identity = %s, %v; want %s", peer.identity, err, targetAfter.identity)
				}
			}
			observed := atomicTransformV2ReplaceObservation{Target: targetAfter, Backup: backupAfter}
			got := classifyAtomicTransformV2ReplaceObservation(receipt, atomicTransformV2ReplaceSuccess, observed)
			if variant.oldLinks == 1 && variant.stageLinks == 1 {
				if got != atomicTransformV2ReplaceReadyForPublication {
					t.Fatalf("1/1 Replace composition disposition = %d, want ready for publication", got)
				}
			} else if got == atomicTransformV2ReplaceReadyForPublication {
				t.Fatalf("%d/%d linked Replace composition incorrectly became publication-ready",
					variant.oldLinks, variant.stageLinks)
			}
		})
	}
}
