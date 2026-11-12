// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// What a failing TestWindowsManagedPolicyWriterNeverLeavesTheFileMissing adds
// to its message. A missing name cannot happen with an atomic rename on plain
// NTFS, so when it does (GAP-2644, PR #1427 pk3: 2667 missing reads in 69765
// on one CI runner, green on the rerun) the cause is the runner: which rename
// ran, which file system and which filter drivers it has. The writer does not
// record the rename it ran, so the path is derived here: from the subtest
// parameter when the seam forces the fallback, otherwise by trying the same
// POSIX-semantics request in the same folder. Nothing here runs unless the
// test is already failing, and none of it changes what the test requires.

const (
	renameReplaceIfExists = 0x1 // FILE_RENAME_FLAG_REPLACE_IF_EXISTS
	renamePOSIXSemantics  = 0x2 // FILE_RENAME_FLAG_POSIX_SEMANTICS
)

var volumeFlagNames = []struct {
	flag uint32
	name string
}{
	{windows.FILE_CASE_SENSITIVE_SEARCH, "CASE_SENSITIVE_SEARCH"},
	{windows.FILE_CASE_PRESERVED_NAMES, "CASE_PRESERVED_NAMES"},
	{windows.FILE_UNICODE_ON_DISK, "UNICODE_ON_DISK"},
	{windows.FILE_PERSISTENT_ACLS, "PERSISTENT_ACLS"},
	{windows.FILE_FILE_COMPRESSION, "FILE_COMPRESSION"},
	{windows.FILE_VOLUME_QUOTAS, "VOLUME_QUOTAS"},
	{windows.FILE_SUPPORTS_SPARSE_FILES, "SPARSE_FILES"},
	{windows.FILE_SUPPORTS_REPARSE_POINTS, "REPARSE_POINTS"},
	{0x00000400, "POSIX_UNLINK_RENAME"}, // FILE_SUPPORTS_POSIX_UNLINK_RENAME
	{windows.FILE_VOLUME_IS_COMPRESSED, "VOLUME_IS_COMPRESSED"},
	{windows.FILE_SUPPORTS_OBJECT_IDS, "OBJECT_IDS"},
	{windows.FILE_SUPPORTS_ENCRYPTION, "ENCRYPTION"},
	{windows.FILE_NAMED_STREAMS, "NAMED_STREAMS"},
	{windows.FILE_READ_ONLY_VOLUME, "READ_ONLY_VOLUME"},
	{windows.FILE_SEQUENTIAL_WRITE_ONCE, "SEQUENTIAL_WRITE_ONCE"},
	{windows.FILE_SUPPORTS_TRANSACTIONS, "TRANSACTIONS"},
	{windows.FILE_SUPPORTS_HARD_LINKS, "HARD_LINKS"},
	{windows.FILE_SUPPORTS_EXTENDED_ATTRIBUTES, "EXTENDED_ATTRIBUTES"},
	{windows.FILE_SUPPORTS_OPEN_BY_FILE_ID, "OPEN_BY_FILE_ID"},
	{windows.FILE_SUPPORTS_USN_JOURNAL, "USN_JOURNAL"},
	{0x04000000, "INTEGRITY_STREAMS"}, // FILE_SUPPORTS_INTEGRITY_STREAMS
	{0x08000000, "BLOCK_REFCOUNTING"}, // FILE_SUPPORTS_BLOCK_REFCOUNTING
	{0x10000000, "SPARSE_VDL"},        // FILE_SUPPORTS_SPARSE_VDL
	{windows.FILE_DAX_VOLUME, "DAX_VOLUME"},
	{0x40000000, "GHOSTING"}, // FILE_SUPPORTS_GHOSTING
}

// managedPolicyWriterRunnerHints describes the runner for a failure message.
// dir is the folder the writer replaced the file in; refused is the subtest
// parameter (the POSIX-semantics rename forced to refuse). run starts a
// system tool (fsutil, fltmc); it is a parameter so the passing-run test can
// stub it.
func managedPolicyWriterRunnerHints(dir string, refused bool, run func(tool string, args ...string) (string, error)) string {
	var b strings.Builder
	b.WriteString("runner hints (gathered after the failure):\n")
	fmt.Fprintf(&b, "  rename path: %s\n", managedPolicyRenamePath(dir, refused))
	fmt.Fprintf(&b, "  volume: %s\n", managedPolicyVolumeHints(dir, run))
	fmt.Fprintf(&b, "  OS: %s\n", managedPolicyOSBuild())
	out, err := run("fltmc", "filters")
	if err != nil {
		fmt.Fprintf(&b, "  fltmc filters: could not run (%v)", err)
		if strings.TrimSpace(out) != "" {
			fmt.Fprintf(&b, ", output: %s", strings.TrimSpace(out))
		}
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, "  fltmc filters:\n%s\n", indentLines(strings.TrimSpace(out), "    "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func indentLines(text, prefix string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

// managedPolicyRenamePath names the rename safefile.ReplaceFileAtomically ran:
// the FileRenameInfoEx POSIX-semantics request, or the FileRenameInfo
// replacement it falls back to where that request is refused.
func managedPolicyRenamePath(dir string, refused bool) string {
	if refused {
		return "FileRenameInfo replace (the fallback): the subtest forces the POSIX-semantics rename to refuse (safefile.RefusePOSIXRenameForTest)"
	}
	err := probePOSIXSemanticsRename(dir)
	switch {
	case err == nil:
		return "FileRenameInfoEx with POSIX semantics (a probe of the same request in the same folder was accepted)"
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER),
		errors.Is(err, windows.ERROR_NOT_SUPPORTED),
		errors.Is(err, windows.ERROR_INVALID_FUNCTION):
		return fmt.Sprintf("FileRenameInfo replace (the fallback): a probe of the POSIX-semantics rename in the same folder was refused: %v", err)
	default:
		return fmt.Sprintf("unknown: a probe of the POSIX-semantics rename in the same folder failed with %v, which the writer does not fall back on", err)
	}
}

// probePOSIXSemanticsRename renames one scratch file over another in dir with
// the request safefile.ReplaceFileAtomically tries first.
func probePOSIXSemanticsRename(dir string) error {
	var paths [2]string
	for i := range paths {
		file, err := os.CreateTemp(dir, ".rename-probe-*.tmp")
		if err != nil {
			return fmt.Errorf("create probe file: %w", err)
		}
		paths[i] = file.Name()
		defer os.Remove(paths[i])
		if err := file.Close(); err != nil {
			return fmt.Errorf("close probe file: %w", err)
		}
	}
	from, err := winpath.UTF16Ptr(paths[0])
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(from, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open probe file: %w", err)
	}
	defer windows.CloseHandle(handle)
	name, err := windows.UTF16FromString(paths[1])
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = renameReplaceIfExists | renamePOSIXSemantics
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx,
		(*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}

// managedPolicyVolumeHints reports the volume dir is on: file system name and
// flags (GetVolumeInformation), and whether it is ReFS or a Dev Drive.
func managedPolicyVolumeHints(dir string, run func(tool string, args ...string) (string, error)) string {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	root := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(path, &root[0], uint32(len(root))); err != nil {
		return fmt.Sprintf("unknown (GetVolumePathName %s: %v)", dir, err)
	}
	var serial, maxComponent, flags uint32
	fsName := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeInformation(&root[0], nil, 0, &serial, &maxComponent, &flags,
		&fsName[0], uint32(len(fsName))); err != nil {
		return fmt.Sprintf("%s: unknown (GetVolumeInformation: %v)", windows.UTF16ToString(root), err)
	}
	fs := windows.UTF16ToString(fsName)
	var names []string
	for _, known := range volumeFlagNames {
		if flags&known.flag != 0 {
			names = append(names, known.name)
		}
	}
	return fmt.Sprintf("%s file system %s, flags 0x%08x [%s], ReFS: %t, Dev Drive: %s",
		windows.UTF16ToString(root), fs, flags, strings.Join(names, " "), strings.EqualFold(fs, "ReFS"),
		managedPolicyDevDriveHint(windows.UTF16ToString(root), run))
}

// managedPolicyDevDriveHint asks fsutil whether the volume is a Dev Drive.
func managedPolicyDevDriveHint(root string, run func(tool string, args ...string) (string, error)) string {
	out, err := run("fsutil", "devdrv", "query", root)
	text := strings.TrimSpace(out)
	switch {
	case strings.Contains(text, "not a developer volume"):
		return "false"
	case strings.Contains(text, "developer volume"):
		return "true"
	case err != nil:
		return fmt.Sprintf("unknown (fsutil devdrv query could not run: %v: %s)", err, text)
	default:
		return fmt.Sprintf("unknown (fsutil devdrv query said: %s)", text)
	}
}

func managedPolicyOSBuild() string {
	version := windows.RtlGetVersion()
	build := fmt.Sprintf("Windows %d.%d build %d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return build
	}
	defer key.Close()
	if revision, _, err := key.GetIntegerValue("UBR"); err == nil {
		build += fmt.Sprintf(".%d", revision)
	}
	if product, _, err := key.GetStringValue("ProductName"); err == nil {
		build += " (" + product + ")"
	}
	return build
}

// runSystemTool runs a tool from the System32 folder and returns its output.
// fltmc needs an administrator; where a tool cannot run, the caller says so.
func runSystemTool(tool string, args ...string) (string, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(system, tool+".exe"), args...).CombinedOutput()
	return string(out), err
}

// The hints are only built when the writer test fails, so a passing run never
// exercises them. This keeps them from rotting without making a passing run
// depend on the runner: the stubbed tool runner must be the one used, the
// rename path and the volume must each be reported under their own label, and
// the probe must leave the folder empty. A path or volume the probe could not
// describe ("unknown", for example when an antivirus or filter driver holds the
// scratch file) is logged, not failed: the writer test is what decides.
func TestManagedPolicyWriterRunnerHintsNameTheRunner(t *testing.T) {
	dir := t.TempDir()
	stubbed := 0
	hints := managedPolicyWriterRunnerHints(dir, false, func(string, ...string) (string, error) {
		stubbed++
		return "", errors.New("stub: not run")
	})
	for _, want := range []string{"rename path: ", "volume: ", "OS: Windows ", "fltmc filters: could not run (stub: not run)"} {
		if !strings.Contains(hints, want) {
			t.Errorf("hints lack %q:\n%s", want, hints)
		}
	}
	if stubbed == 0 {
		t.Errorf("the stubbed tool runner was not used:\n%s", hints)
	}
	for _, line := range strings.Split(hints, "\n") {
		field := strings.TrimSpace(line)
		for _, label := range []string{"rename path: ", "volume: "} {
			if value, ok := strings.CutPrefix(field, label); ok && (strings.HasPrefix(value, "unknown") || strings.Contains(value, ": unknown (")) {
				t.Logf("the runner could not describe its %s%s", label, value)
			}
		}
	}
	if got := managedPolicyRenamePath(dir, true); !strings.Contains(got, "FileRenameInfo replace (the fallback)") {
		t.Errorf("refused rename path = %q", got)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the probe left files in %s: %v, %v", dir, entries, err)
	}
}
