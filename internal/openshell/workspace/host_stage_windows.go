// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	hostStageVolumeGUID = 1 // GetFinalPathNameByHandle VOLUME_NAME_GUID
)

type windowsHostStagePin struct {
	files      []*os.File
	path       string
	volumePath string
}

func (p *windowsHostStagePin) leaf() *os.File { return p.files[len(p.files)-1] }
func (p *windowsHostStagePin) close() {
	for i := len(p.files) - 1; i >= 0; i-- {
		_ = p.files[i].Close()
	}
}

func prepareHostStagePlatform(ctx context.Context, opts StageOptions) (_ *HostStage, retErr error) {
	ctx, cancel := context.WithTimeout(ctx, hostStageDeadline)
	defer cancel()
	source, err := openWindowsHostStagePin(opts.Project)
	if err != nil {
		return nil, fmt.Errorf("workspace: pin original Windows project: %w", err)
	}
	defer source.close()
	if err := validateWindowsHostStageSource(source.path, opts); err != nil {
		return nil, err
	}
	identity, err := windowsHostStageIdentity(source.leaf())
	if err != nil {
		return nil, err
	}
	// Policy paths refer to the original source, never the temporary capture.
	scan := stageSecretOptions(opts, source.path)
	output, err := openWindowsHostStagePin(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("workspace: pin Windows staging parent: %w", err)
	}
	keepOutput := false
	defer func() {
		if !keepOutput {
			output.close()
		}
	}()
	if err := safefile.ValidatePrivateHandle(windows.Handle(output.leaf().Fd())); err != nil {
		return nil, fmt.Errorf("workspace: staging parent must already be current-user private (its ACL was not changed): %w", err)
	}
	overlap, err := windowsHostStagePinsOverlap(source, output)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, errors.New("workspace: the project overlaps the private staging parent")
	}
	name := "host-stage-" + opts.Name + "-" + randomSuffix()
	artifactPin, err := createWindowsHostStageDirectory(output.leaf(), name)
	if err != nil {
		return nil, fmt.Errorf("workspace: atomically create held-parent private host stage: %w", err)
	}
	artifactID, err := windowsHostStageCreatedIdentity(artifactPin, filepath.Join(output.path, name))
	if err != nil {
		// No bytes have been captured and cleanup cannot yet bind a file ID.
		// Report the exact empty residue instead of reopening an unchecked name.
		return nil, errors.Join(err, artifactPin.Close())
	}
	var root *os.Root
	var capture, sanitized, scratch *os.Root
	var lock *os.File
	var treeParent, treePin *os.File
	cleanup := func() error {
		// A consumer lease blocks entry to cleanup altogether. Once consumers
		// release, uncertain producer-pin close must still stop before any
		// recursive deletion. Successfully closed pins are never closed twice.
		for _, pin := range []**os.File{&treePin, &treeParent} {
			if *pin != nil {
				if err := (*pin).Close(); err != nil {
					return fmt.Errorf("workspace: retain host stage after uncertain root pin close: %w", err)
				}
				*pin = nil
			}
		}
		for _, held := range []*os.Root{capture, sanitized, scratch} {
			if held != nil {
				_ = held.Close()
			}
		}
		capture, sanitized, scratch = nil, nil, nil
		if lock != nil {
			_ = windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, new(windows.Overlapped))
			_ = lock.Close()
			lock = nil
		}
		if root != nil {
			_ = root.Close()
			root = nil
		}
		if artifactPin != nil {
			_ = artifactPin.Close()
			artifactPin = nil
		}
		cleanupCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		budget := 4*hostStageMaxEntries + 10_000
		err := removeWindowsHostStageChild(cleanupCtx, output.leaf(), name, artifactID, 0, &budget)
		output.close()
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			retErr = errors.Join(retErr, cleanup())
		}
	}()
	if _, err := windowsHostStageInfo(artifactPin, true); err != nil {
		return nil, err
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(artifactPin.Fd())); err != nil {
		return nil, err
	}
	// Reopen exactly once using the held directory's volume spelling and
	// verify its full identity before mutation. All later I/O is root-relative.
	artifactPath, err := windowsHostStageFinalPath(artifactPin, hostStageVolumeGUID)
	if err != nil {
		return nil, err
	}
	root, err = os.OpenRoot(artifactPath)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsHostStagePrivateRoot(root, artifactID); err != nil {
		return nil, err
	}
	lock, err = root.OpenFile("owner.lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(lock.Fd())); err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped)); err != nil {
		return nil, fmt.Errorf("workspace: lock private host artifact: %w", err)
	}
	for _, dir := range []string{"capture", "sanitized", "scratch"} {
		if err := root.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultCopyMaxBytes
	}
	maxEntries := opts.MaxWalkEntries
	if maxEntries <= 0 || maxEntries > hostStageMaxEntries {
		maxEntries = hostStageMaxEntries
	}
	capture, err = root.OpenRoot("capture")
	if err != nil {
		return nil, err
	}
	budget := windowsHostCaptureBudget{maxBytes: maxBytes, remaining: maxEntries}
	captureFile, err := capture.Open(".")
	if err != nil {
		return nil, err
	}
	captureID, err := windowsHostStageIdentity(captureFile)
	_ = captureFile.Close()
	if err != nil {
		return nil, err
	}
	err = captureWindowsHostTree(ctx, source.leaf(), capture, "", 0, &budget)
	if err != nil {
		return nil, err
	}
	settings := capturedGitSettings{frozen: true}
	if _, statErr := capture.Lstat(".git"); statErr == nil {
		settings, err = freezeWindowsHostStageSettings(ctx, opts)
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nil, statErr
	}
	sanitized, err = root.OpenRoot("sanitized")
	if err != nil {
		return nil, err
	}
	scratch, err = root.OpenRoot("scratch")
	if err != nil {
		return nil, err
	}
	scratchFile, err := scratch.Open(".")
	if err != nil {
		return nil, err
	}
	scratchID, err := windowsHostStageIdentity(scratchFile)
	_ = scratchFile.Close()
	if err != nil {
		return nil, err
	}
	engineOpts := opts
	engineOpts.Project = source.path
	rec, err := stageCapturedSHA1(ctx, capture, sanitized, scratch, engineOpts, scan, settings)
	if err != nil {
		return nil, err
	}
	for _, held := range []*os.Root{capture, scratch} {
		if err := held.Close(); err != nil {
			return nil, err
		}
	}
	capture, scratch = nil, nil
	// Raw source and decoding scratch are never part of the retained tree.
	for _, temporary := range []struct{ name, id string }{{"capture", captureID}, {"scratch", scratchID}} {
		cleanupBudget := 2*hostStageMaxEntries + 1
		if err := removeWindowsHostStageChild(ctx, artifactPin, temporary.name, temporary.id, 0, &cleanupBudget); err != nil {
			return nil, fmt.Errorf("workspace: discard private temporary %s: %w", temporary.name, err)
		}
	}
	rec.Stage = filepath.Join(artifactPath, "sanitized", rec.RepoName)
	// Preserve original source custody and policy identity in the summary.
	rec.Project = source.path
	// Retain a native object chain for handoff. Display paths never select the
	// sanitized root, including when a caller later changes drive aliases.
	treeParent, err = openWindowsHostStageChild(artifactPin, "sanitized", windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsHostStageLeaseDirectory(treeParent); err != nil {
		return nil, err
	}
	treePin, err = openWindowsHostStageChild(treeParent, rec.RepoName, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsHostStageLeaseDirectory(treePin); err != nil {
		return nil, err
	}
	treeID, err := windowsHostStageIdentity(treePin)
	if err != nil {
		return nil, err
	}
	stage := &HostStage{record: rec, identity: identity, close: cleanup, duplicateRoot: func() (*os.File, error) {
		return duplicateWindowsHostStageRoot(treePin, treeID)
	}}
	keepOutput, succeeded = true, true
	return stage, nil
}

func validateWindowsHostStageLeaseDirectory(file *os.File) error {
	if _, err := windowsHostStageInfo(file, true); err != nil {
		return err
	}
	if err := windowsHostStageNoStreams(file); err != nil {
		return err
	}
	return safefile.ValidatePrivateHandle(windows.Handle(file.Fd()))
}

var hostStageGetHandleInformation = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func windowsHostStageLeaseHandleFlags(file *os.File) (uint32, error) {
	if err := hostStageGetHandleInformation.Find(); err != nil {
		return 0, err
	}
	var flags uint32
	ok, _, _ := hostStageGetHandleInformation.Call(file.Fd(), uintptr(unsafe.Pointer(&flags)))
	runtime.KeepAlive(file)
	if ok == 0 {
		return 0, errors.New("workspace: query Windows root lease handle flags refused")
	}
	return flags, nil
}

// The source was opened with read/query access, without delete sharing. Handle
// access is not a guest policy: relative child access still uses caller tokens.
// A nonnil duplicate transfers cleanup to the tracked lease even on validation
// failure, so a failed close cannot erase custody of an allocated handle.
func duplicateWindowsHostStageRoot(source *os.File, expectedID string) (*os.File, error) {
	if err := validateWindowsHostStageLeaseDirectory(source); err != nil {
		return nil, err
	}
	id, err := windowsHostStageIdentity(source)
	if err != nil || id != expectedID {
		return nil, errors.New("workspace: held Windows sanitized root identity changed")
	}
	var handle windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(source.Fd()),
		windows.CurrentProcess(), &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), "host-stage-root-lease")
	if err := validateWindowsHostStageLeaseDirectory(file); err != nil {
		return file, err
	}
	id, err = windowsHostStageIdentity(file)
	if err != nil || id != expectedID {
		return file, errors.New("workspace: Windows sanitized root duplicate identity differs")
	}
	flags, err := windowsHostStageLeaseHandleFlags(file)
	if err != nil {
		return file, err
	}
	if flags&windows.HANDLE_FLAG_INHERIT != 0 {
		return file, errors.New("workspace: Windows root lease unexpectedly inheritable")
	}
	return file, nil
}

func validateWindowsHostStagePrivateRoot(root *os.Root, expectedID string) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	identity, err := windowsHostStageIdentity(file)
	if err != nil || identity != expectedID {
		return errors.New("workspace: reopened Windows root differs from held artifact identity")
	}
	return safefile.ValidatePrivateHandle(windows.Handle(file.Fd()))
}

func createWindowsHostStageDirectory(parent *os.File, name string) (*os.File, error) {
	if err := validateWindowsHostStageName(name); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("workspace: resolve effective Windows staging owner: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("workspace: effective Windows staging owner has no SID")
	}
	grants := fmt.Sprintf("(A;OICI;FA;;;%s)", user.User.Sid)
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		grants += "(A;OICI;FA;;;SY)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P%s", user.User.Sid, grants))
	if err != nil {
		return nil, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()), ObjectName: objectName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: descriptor}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	// A DELETE-access file object conflicts with os.OpenRoot's share mode even
	// when another handle has reduced rights. Keep this pin read-only and deny
	// delete sharing; ID-known cleanup opens its own DELETE handle after close.
	err = windows.NtCreateFile(&handle, windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		&attributes, &status, nil, windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

// Only for a newly created, still-empty private artifact, before source bytes.
// An identity-query refusal must retain and name that residue explicitly.
func windowsHostStageCreatedIdentity(file *os.File, path string) (string, error) {
	identity, err := windowsHostStageIdentity(file)
	if err != nil {
		return "", fmt.Errorf("workspace: cannot bind initial file identity; retained empty private directory %q: %w", path, err)
	}
	return identity, nil
}

// Each pathname component is opened from a held parent. Delete sharing is
// withheld while a path is pinned; leaf reads additionally withhold writes.
func openWindowsHostStagePin(path string) (_ *windowsHostStagePin, retErr error) {
	return openWindowsHostStagePinMode(path, false)
}

func openWindowsHostStageOptionalPin(path string) (*windowsHostStagePin, error) {
	return openWindowsHostStagePinMode(path, true)
}

func openWindowsHostStagePinMode(path string, missingOK bool) (_ *windowsHostStagePin, retErr error) {
	if path == "" || !utf8.ValidString(path) {
		return nil, errors.New("empty or invalid Windows host path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	mount, err := winpath.ValidateFixedNTFSMountedPath(abs)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(mount.DriveRoot)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	pin := &windowsHostStagePin{files: []*os.File{os.NewFile(uintptr(handle), mount.DriveRoot)}}
	completed := false
	defer func() {
		if !completed {
			pin.close()
		}
	}()
	if _, err := windowsHostStageInfo(pin.leaf(), true); err != nil {
		return nil, err
	}
	volumeRoot, err := windowsHostStageFinalPath(pin.leaf(), hostStageVolumeGUID)
	if err != nil || !strings.EqualFold(strings.TrimRight(volumeRoot, `\`), strings.TrimRight(mount.VolumeName, `\`)) {
		return nil, errors.New("workspace: opened drive root differs from validated mount-manager identity")
	}
	for _, component := range strings.Split(strings.TrimPrefix(abs[2:], `\`), `\`) {
		if component == "" {
			continue
		}
		if err := validateWindowsHostStageName(component); err != nil {
			return nil, err
		}
		child, err := openWindowsHostStageChild(pin.leaf(), component, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
		if missingOK && windowsHostStageMissing(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		pin.files = append(pin.files, child)
		if _, err := windowsHostStageInfo(child, true); err != nil {
			return nil, err
		}
	}
	name, err := windowsHostStageFinalPath(pin.leaf(), 0) // VOLUME_NAME_DOS, display/policy only
	if err != nil {
		return nil, err
	}
	pin.path = strings.TrimPrefix(name, `\\?\`)
	pin.volumePath, err = windowsHostStageFinalPath(pin.leaf(), hostStageVolumeGUID)
	if err != nil {
		return nil, err
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(pin.path); err != nil {
		return nil, err
	}
	completed = true
	return pin, nil
}

func windowsHostStagePinsOverlap(a, b *windowsHostStagePin) (bool, error) {
	aID, err := windowsHostStageIdentity(a.leaf())
	if err != nil {
		return false, err
	}
	bID, err := windowsHostStageIdentity(b.leaf())
	if err != nil {
		return false, err
	}
	for _, candidate := range []struct {
		leaf      string
		ancestors *windowsHostStagePin
	}{{aID, b}, {bID, a}} {
		for _, file := range candidate.ancestors.files {
			id, err := windowsHostStageIdentity(file)
			if err != nil {
				return false, err
			}
			if id == candidate.leaf {
				return true, nil
			}
		}
	}
	return false, nil
}

func windowsHostStageFinalPath(file *os.File, flags uint32) (string, error) {
	name := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &name[0], uint32(len(name)), flags)
	if err != nil || n >= uint32(len(name)) {
		return "", fmt.Errorf("workspace: resolve pinned Windows path: %w", errors.Join(err, fs.ErrInvalid))
	}
	return windows.UTF16ToString(name[:n]), nil
}

func openWindowsHostStageChild(parent *os.File, name string, share uint32) (*os.File, error) {
	return openWindowsHostStageChildAccess(parent, name, share, windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE)
}

func openWindowsHostStageChildAccess(parent *os.File, name string, share, access uint32) (*os.File, error) {
	if err := validateWindowsHostStageName(name); err != nil {
		return nil, err
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()), ObjectName: objectName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access,
		&attributes, &status, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("workspace: open held Windows entry (reparse points and concurrent writers are refused): %w", err)
	}
	return os.NewFile(uintptr(handle), name), nil
}

func windowsHostStageInfo(file *os.File, wantDirectory bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return info, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != wantDirectory {
		return info, errors.New("workspace: Windows entry is a reparse point or changed file type")
	}
	if !wantDirectory && info.NumberOfLinks != 1 {
		return info, errors.New("workspace: Windows host staging refuses hardlinked regular files")
	}
	if wantDirectory {
		var flags uint32
		if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileCaseSensitiveInfo,
			(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags))); err != nil {
			return info, fmt.Errorf("workspace: query Windows directory case semantics: %w", err)
		}
		if flags&windows.FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
			return info, errors.New("workspace: case-sensitive Windows directories are unsupported for host staging")
		}
	}
	return info, nil
}

type windowsHostStageFileID struct {
	Volume uint64
	ID     [16]byte
}

func windowsHostStageIdentity(file *os.File) (string, error) {
	var id windowsHostStageFileID
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return "", fmt.Errorf("workspace: query pinned Windows file identity: %w", err)
	}
	return fmt.Sprintf("windows:%016x:%x", id.Volume, id.ID), nil
}

func windowsHostStageNoStreams(file *os.File) error {
	// FILE_STREAM_INFO entries require eight-byte alignment. []byte alone
	// does not express that requirement (notably under race instrumentation).
	storage := make([]uint64, (64<<10)/8)
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&storage[0])), len(storage)*8)
	err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileStreamInfo, &buffer[0], uint32(len(buffer)))
	if errors.Is(err, windows.ERROR_HANDLE_EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workspace: enumerate bounded Windows named streams: %w", err)
	}
	for offset, count := 0, 0; ; count++ {
		if count >= 128 || offset < 0 || offset+24 > len(buffer) {
			return errors.New("workspace: invalid or excessive Windows stream list")
		}
		next, length := binary.LittleEndian.Uint32(buffer[offset:]), binary.LittleEndian.Uint32(buffer[offset+4:])
		if length == 0 && next == 0 {
			return nil // a directory with no streams
		}
		if length == 0 || length%2 != 0 || uint64(offset)+24+uint64(length) > uint64(len(buffer)) {
			return errors.New("workspace: invalid Windows stream name")
		}
		units := make([]uint16, int(length)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(buffer[offset+24+i*2:])
		}
		if !strings.EqualFold(windows.UTF16ToString(units), "::$DATA") {
			return errors.New("workspace: Windows host staging refuses named data streams")
		}
		if next == 0 {
			return nil
		}
		if next < 24+length || uint64(offset)+uint64(next) >= uint64(len(buffer)) {
			return errors.New("workspace: invalid Windows stream continuation")
		}
		offset += int(next)
	}
}

func validateWindowsHostStageSource(project string, opts StageOptions) error {
	home, err := resolveHome(opts.Home)
	if err != nil {
		return err
	}
	volumeRoot := filepath.VolumeName(project) + `\`
	if samePath(project, volumeRoot) || samePath(project, filepath.Dir(home)) ||
		samePath(project, home) || within(home, project) {
		return &SourceError{Path: project, Reason: "it is a volume, user-profile root, home, or contains home"}
	}
	windowsDir, err := windows.GetWindowsDirectory()
	if err != nil {
		return err
	}
	systemTrees := []string{windowsDir, filepath.Join(home, "AppData")}
	for _, folder := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramData} {
		path, err := windows.KnownFolderPath(folder, 0)
		if err != nil {
			return fmt.Errorf("workspace: resolve protected Windows system folder: %w", err)
		}
		systemTrees = append(systemTrees, path)
	}
	for _, path := range systemTrees {
		if within(project, path) || within(path, project) {
			return &SourceError{Path: project, Reason: "it overlaps Windows system or application state"}
		}
	}
	protected := append([]string(nil), opts.Protected...)
	protected = append(protected, opts.DataDir)
	for _, tree := range credentialTrees(home) {
		protected = append(protected, tree.path)
	}
	for _, path := range protected {
		if path != "" && Overlaps(project, path) {
			return &SourceError{Path: project, Reason: "it overlaps a protected credential, harness or state directory"}
		}
	}
	return nil
}

type windowsHostCaptureBudget struct {
	bytes, maxBytes int64
	remaining       int
}

func captureWindowsHostTree(ctx context.Context, source *os.File, destination *os.Root, rel string, depth int, budget *windowsHostCaptureBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > hostStageMaxDepth {
		return errors.New("workspace: Windows capture exceeds its depth limit")
	}
	if _, err := windowsHostStageInfo(source, true); err != nil {
		return err
	}
	if err := windowsHostStageNoStreams(source); err != nil {
		return err
	}
	seen := map[string]bool{}
	for {
		entries, readErr := source.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			budget.remaining--
			if budget.remaining < 0 {
				return errors.New("workspace: Windows capture exceeds its entry limit")
			}
			name := entry.Name()
			if err := validateWindowsHostStageName(name); err != nil {
				return err
			}
			key := strings.ToUpper(name)
			if seen[key] {
				return errors.New("workspace: Windows capture contains colliding entry names")
			}
			seen[key] = true
			file, err := openWindowsHostStageChild(source, name, windows.FILE_SHARE_READ)
			if err != nil {
				return err
			}
			err = captureWindowsHostEntry(ctx, file, destination, filepath.Join(rel, name), depth, budget)
			_ = file.Close()
			if err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func captureWindowsHostEntry(ctx context.Context, source *os.File, destination *os.Root, rel string, depth int, budget *windowsHostCaptureBudget) error {
	stat, err := source.Stat()
	if err != nil {
		return err
	}
	if _, err := windowsHostStageInfo(source, stat.IsDir()); err != nil {
		return err
	}
	if _, err := windowsHostStageIdentity(source); err != nil {
		return err
	}
	if stat.IsDir() {
		if err := destination.Mkdir(rel, 0o700); err != nil {
			return err
		}
		return captureWindowsHostTree(ctx, source, destination, rel, depth+1, budget)
	}
	if !stat.Mode().IsRegular() || stat.Size() < 0 {
		return errors.New("workspace: Windows capture requires regular files")
	}
	if err := windowsHostStageNoStreams(source); err != nil {
		return err
	}
	if stat.Size() > budget.maxBytes-budget.bytes {
		return &TooLargeError{What: "the complete Windows source capture (including git metadata)", Size: budget.bytes + stat.Size(), Limit: budget.maxBytes}
	}
	out, err := destination.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := safefile.ValidatePrivateHandle(windows.Handle(out.Fd())); err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(source, stat.Size()+1))
	if err != nil {
		return err
	}
	if n != stat.Size() {
		return errors.New("workspace: Windows source size changed during capture")
	}
	budget.bytes += n
	return out.Sync()
}

// Cleanup uses held-parent NT-relative opens and deletes the opened object by
// handle. Its expected top identity is checked before descent or mutation.
// Reparse/name replacement refuses and leaves residue; no absolute rm occurs.
func removeWindowsHostStageChild(ctx context.Context, parent *os.File, name, expectedID string, depth int, budget *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	*budget = *budget - 1
	if *budget < 0 || depth > hostStageMaxDepth+8 {
		return errors.New("workspace: bounded owned host-stage cleanup refused excessive entries/depth")
	}
	file, err := openWindowsHostStageChildAccess(parent, name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		if expectedID != "" {
			return errors.New("workspace: owned Windows cleanup identity is no longer at its expected name")
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if expectedID != "" {
		identity, err := windowsHostStageIdentity(file)
		if err != nil || identity != expectedID {
			return errors.New("workspace: cleanup target differs from its owned Windows file identity")
		}
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("workspace: refuse nonprivate cleanup target: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("workspace: cleanup refuses Windows reparse points")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		for {
			entries, readErr := file.ReadDir(128)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				err = readErr
				break
			}
			for _, entry := range entries {
				if err = removeWindowsHostStageChild(ctx, file, entry.Name(), "", depth+1, budget); err != nil {
					break
				}
			}
			if err != nil || errors.Is(readErr, io.EOF) {
				break
			}
		}
		if err != nil {
			return err
		}
	}
	return discardWindowsHostStageHandle(file)
}

func discardWindowsHostStageHandle(file *os.File) error {
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if err := windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags))); err != nil {
		return fmt.Errorf("workspace: delete exact owned Windows handle: %w", err)
	}
	return nil
}
