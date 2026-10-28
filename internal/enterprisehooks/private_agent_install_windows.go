// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func privateInstallContractReason(name, version string) string {
	if minimum := windowsEnterpriseStandaloneAgentMinimum(name); minimum != "" &&
		compareWindowsEnterpriseVersion(connector.NormalizeAgentVersion(name, version), minimum) < 0 {
		return "version " + version + " is below the lowest supported hook contract " + minimum
	}
	if result := connector.ResolveHookContract(name, version); result.Status != connector.HookCompatibilityKnown {
		return "version " + version + " is not verified against a known hook contract"
	}
	return ""
}

// windowsPrivateInstallMachineRoots are machine npm prefixes every account
// can run a copy from: Node's own folder, where npm puts global packages
// when the prefix is the Node installation. Tests replace it.
var windowsPrivateInstallMachineRoots = func() []string {
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if programFiles == "" || !filepath.IsAbs(programFiles) {
		programFiles = `C:\Program Files`
	}
	return []string{filepath.Join(programFiles, "nodejs")}
}

// DiscoverWindowsPrivateAgentInstalls checks the fixed npm roots, every
// installed Node of the version managers (not only the newest few), the
// Volta package images, the vendor's local install, the native installer's
// versions, the machine npm prefix and every npm prefix at any depth below
// a profile, where npm --prefix or a project leaves a runnable local copy
// (GAP-0988). It performs bounded
// static reads and refuses reparse chains while the enumerator runs as
// LocalSystem; a part it cannot read or that exceeds its bound is reported
// incomplete with the reason.
func DiscoverWindowsPrivateAgentInstalls(ctx context.Context, home string, names []string) []PrivateAgentInstall {
	if ctx == nil {
		ctx = context.Background()
	}
	wanted := privateInstallConnectors(names, func(name string) bool { return name == "claudecode" || name == "codex" || name == "copilot" })
	if len(wanted) == 0 {
		return nil
	}
	home = filepath.Clean(home)
	scan := newPrivateInstallScan()
	if winpath.RejectReparseChain(home) != nil {
		scan.skipAll(wanted, PrivateInstallSkippedLocation)
		return scan.result()
	}
	roots := []string{home, filepath.Join(home, ".claude", "local"), filepath.Join(home, "AppData", "Roaming", "npm"),
		filepath.Join(home, ".bun", "install", "global"),
		filepath.Join(home, "AppData", "Local", "Yarn", "Data", "global")}
	modulesRoots, truncated := windowsStandaloneNodeModulesRootsBounded(home, privateAgentInstallMaxVersionDirs)
	if truncated {
		scan.skipAll(wanted, PrivateInstallSkippedVersionManagers)
	}
	for _, modules := range modulesRoots {
		roots = append(roots, filepath.Dir(modules))
	}
	// The walk never descends through a reparse point: the profile's
	// compatibility junctions name folders it reads through their own
	// paths, and LocalSystem must not follow a user's link anywhere else.
	nested, complete := windowsPrivateHomeWalk(ctx, home)
	if !complete {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
	}
	roots = append(roots, nested...)
	if ctx.Err() != nil {
		return scan.result()
	}
	for _, machine := range windowsPrivateInstallMachineRoots() {
		info, err := os.Lstat(machine)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || winpath.RejectReparseChain(machine) != nil {
			// Absent, or nvm-windows' link to the active version under one
			// profile's nvm root, which that profile's scan reads.
			continue
		}
		roots = append(roots, machine)
	}
	for _, name := range wanted {
		if ctx.Err() != nil {
			scan.skipAll(wanted, PrivateInstallSkippedHome)
			return scan.result()
		}
		packages := windowsStandaloneNPMPackages[name]
		packageRoots := append([]string(nil), roots...)
		for _, packageName := range packages {
			// Volta gives each package an image below AppData\Local, outside
			// the profile's immediate children and the npm prefix roots.
			packageRoots = append(packageRoots, filepath.Join(home, "AppData", "Local", "Volta", "tools", "image", "packages", packageName))
		}
		for _, root := range packageRoots {
			if ctx.Err() != nil {
				scan.skipAll(wanted, PrivateInstallSkippedHome)
				return scan.result()
			}
			for _, packageName := range packages {
				if ctx.Err() != nil {
					scan.skipAll(wanted, PrivateInstallSkippedHome)
					return scan.result()
				}
				for _, modules := range []string{"node_modules", filepath.Join("lib", "node_modules")} {
					scanWindowsNPMPackage(scan, name, filepath.Join(root, modules, packageName))
				}
			}
		}
	}
	if ctx.Err() != nil {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
		return scan.result()
	}
	if containsPrivateConnector(wanted, "claudecode") {
		local := filepath.Join(home, ".claude", "local")
		packageDir := filepath.Join(local, "node_modules", "@anthropic-ai", "claude-code")
		if runnable, known := windowsNPMPackageRunnable("claudecode", packageDir); !known {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
		} else if !runnable {
			for _, base := range []string{"claude", "claude.cmd", "claude.exe"} {
				if ctx.Err() != nil {
					scan.skipAll(wanted, PrivateInstallSkippedHome)
					return scan.result()
				}
				wrapper := filepath.Join(local, base)
				info, err := os.Lstat(wrapper)
				switch {
				case err == nil && winpath.RejectReparseChain(wrapper) != nil:
					scan.skip("claudecode", PrivateInstallSkippedLocation)
				case err == nil && info.Mode().IsRegular():
					if scan.judge(windowsCopyIdentity(wrapper)) {
						scan.add(PrivateAgentInstall{Connector: "claudecode", Path: wrapper})
					}
				case err != nil && !os.IsNotExist(err):
					scan.skip("claudecode", PrivateInstallSkippedLocation)
				}
			}
		}
		if ctx.Err() != nil {
			scan.skipAll(wanted, PrivateInstallSkippedHome)
			return scan.result()
		}
		scanWindowsClaudeVersions(scan, filepath.Join(home, ".local", "share", "claude", "versions"))
	}
	if ctx.Err() != nil {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
	}
	return scan.result()
}

// windowsPrivateWalkRun is one bounded walk of a home for npm prefixes.
// Tests replace it.
var windowsPrivateWalkRun = func(ctx context.Context, home string) ([]string, bool) {
	return walkPrivateNPMPrefixes(ctx, home, privateInstallWalk{open: openWindowsPrivateWalkDir, openChild: openWindowsPrivateWalkChild,
		enter:       enterWindowsPrivateWalkBackup,
		unreachable: func(_ string, err error) bool { return errors.Is(err, fs.ErrNotExist) }})
}

// A home walk is not bound to the profile's scan deadline: under hook load
// it can need longer than a cycle's share (20 s at most), and every cycle
// then cut it off, so coverage_complete stayed false after an upgrade until
// the host went idle (GAP-2002). The walk runs on to
// windowsPrivateWalkBackgroundBound; the scan waits for it until shortly
// before its own deadline, keeping time for the fixed install roots it reads
// every cycle. When the walk is still running then, the scan uses the last
// complete walk of that home if it is at most windowsPrivateWalkReuse old,
// and the account is reported incomplete otherwise. A walk that ends
// incomplete (its entry bound, an unlistable folder) is reported as it ends,
// never replaced by an older result.
var (
	windowsPrivateWalkBackgroundBound = 2 * time.Minute
	windowsPrivateWalkReuse           = 10 * time.Minute
	windowsPrivateWalkNow             = time.Now
)

type windowsPrivateWalkRunState struct {
	done     chan struct{}
	prefixes []string
	complete bool
	// reported marks a walk a scan stopped waiting for with no fresh
	// complete walk to use, so that account was reported incomplete.
	reported bool
}

type windowsPrivateWalkHome struct {
	running *windowsPrivateWalkRunState
	last    []string
	lastAt  time.Time
}

var windowsPrivateWalks = struct {
	sync.Mutex
	homes map[string]*windowsPrivateWalkHome
}{homes: map[string]*windowsPrivateWalkHome{}}

// windowsPrivateWalkLate is signalled when a walk finishes complete after a
// scan reported its account incomplete for want of it. The enumerator runs
// one extra cycle on it, so the coverage record does not stay incomplete
// until the next interval tick (5 minutes) after a slow first cycle, such as
// the one right after an upgrade (GAP-2002). The extra cycle uses that fresh
// walk, so it does not signal again.
var windowsPrivateWalkLate = make(chan struct{}, 1)

// WindowsPrivateWalkCompletedLate returns the channel the enumerator's
// interval loop waits on for that extra cycle.
func WindowsPrivateWalkCompletedLate() <-chan struct{} { return windowsPrivateWalkLate }

// windowsPrivateWalkWait is the part of ctx the scan waits for its walk:
// a quarter of what is left, at least 2 s, stays for the rest of the scan.
func windowsPrivateWalkWait(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return context.WithCancel(ctx)
	}
	reserve := time.Until(deadline) / 4
	if reserve < 2*time.Second {
		reserve = 2 * time.Second
	}
	return context.WithDeadline(ctx, deadline.Add(-reserve))
}

func windowsPrivateHomeWalk(ctx context.Context, home string) ([]string, bool) {
	if ctx.Err() != nil {
		return nil, false
	}
	key := strings.ToLower(filepath.Clean(home))
	windowsPrivateWalks.Lock()
	state := windowsPrivateWalks.homes[key]
	if state == nil {
		state = &windowsPrivateWalkHome{}
		windowsPrivateWalks.homes[key] = state
	}
	run := state.running
	if run == nil {
		run = &windowsPrivateWalkRunState{done: make(chan struct{})}
		state.running = run
		go func() {
			walkCtx, cancel := context.WithTimeout(context.Background(), windowsPrivateWalkBackgroundBound)
			prefixes, complete := windowsPrivateWalkRun(walkCtx, home)
			cancel()
			windowsPrivateWalks.Lock()
			run.prefixes, run.complete = prefixes, complete
			if complete {
				state.last, state.lastAt = prefixes, windowsPrivateWalkNow()
			}
			state.running = nil
			late := complete && run.reported
			windowsPrivateWalks.Unlock()
			close(run.done)
			if late {
				select {
				case windowsPrivateWalkLate <- struct{}{}:
				default: // an extra cycle is already due
				}
			}
		}()
	}
	windowsPrivateWalks.Unlock()
	wait, cancel := windowsPrivateWalkWait(ctx)
	defer cancel()
	select {
	case <-run.done:
		return append([]string(nil), run.prefixes...), run.complete
	case <-wait.Done():
	}
	windowsPrivateWalks.Lock()
	defer windowsPrivateWalks.Unlock()
	if age := windowsPrivateWalkNow().Sub(state.lastAt); !state.lastAt.IsZero() && age >= 0 && age <= windowsPrivateWalkReuse {
		return append([]string(nil), state.last...), true
	}
	if state.running == run {
		run.reported = true
	}
	return nil, false
}

// errPrivateWalkReparse refuses a directory path that cannot be opened as
// ordinary local directories from the drive root.
var errPrivateWalkReparse = errors.New("the folder is a reparse point")

// The SYSTEM service can hold SeBackupPrivilege without enabling it for the
// whole process. Give each bounded walk branch its own thread token so a
// private application directory can be listed without changing the access
// of concurrent service work. If the privilege is unavailable, ordinary
// opens still work and a denied subtree remains honestly incomplete.
func enterWindowsPrivateWalkBackup() func() {
	runtime.LockOSThread()
	var existing windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &existing)
	if err == nil {
		_ = existing.Close()
		runtime.UnlockOSThread()
		return func() {} // never replace a caller's impersonation token
	}
	if !errors.Is(err, windows.ERROR_NO_TOKEN) {
		runtime.UnlockOSThread()
		return func() {}
	}
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return func() {}
	}
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &token); err != nil {
		_ = windows.RevertToSelf()
		runtime.UnlockOSThread()
		return func() {}
	}
	name, err := windows.UTF16PtrFromString("SeBackupPrivilege")
	var privilege windows.LUID
	if err == nil {
		err = windows.LookupPrivilegeValue(nil, name, &privilege)
	}
	if err == nil {
		state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: privilege, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
		err = windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil)
	}
	if err != nil {
		_ = token.Close()
		_ = windows.RevertToSelf()
		runtime.UnlockOSThread()
		return func() {}
	}
	return func() {
		_ = token.Close()
		_ = windows.RevertToSelf()
		runtime.UnlockOSThread()
	}
}

// openWindowsPrivateWalkDir opens a profile root, checking the drive root's
// final path once. Children of this handle use openWindowsPrivateWalkChild.
// A pathname check followed by os.Open can follow a junction planted between
// those calls; the handle returned here is the one ReadDir uses.
func openWindowsPrivateWalkDir(dir string) (*os.File, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// The scan runs as LocalSystem. A UNC or device path is never a profile
	// directory to enumerate, even if it is selected by a user-controlled
	// reparse point.
	if len(absolute) < 3 || absolute[1] != ':' || absolute[2] != '\\' ||
		((absolute[0] < 'A' || absolute[0] > 'Z') && (absolute[0] < 'a' || absolute[0] > 'z')) ||
		len(filepath.VolumeName(absolute)) != 2 || strings.Contains(absolute[2:], ":") {
		return nil, errPrivateWalkReparse
	}
	root := absolute[:3]
	ptr, err := winpath.UTF16Ptr(root)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, err := windows.CreateFile(ptr, access, share, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsPrivateWalkHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	// A substituted or remapped drive has no reparse attribute. The drive
	// root must name the local volume requested before we descend from it.
	rootPath, err := windowsPrivateWalkHandlePath(handle)
	if err != nil || !strings.EqualFold(filepath.Clean(rootPath), filepath.Clean(`\\?\`+root)) {
		_ = windows.CloseHandle(handle)
		return nil, errPrivateWalkReparse
	}
	for _, part := range strings.Split(strings.Trim(absolute[3:], `\`), `\`) {
		if part == "" {
			break // volume root
		}
		child, err := openWindowsPrivateWalkChildHandle(handle, part)
		_ = windows.CloseHandle(handle)
		if err != nil {
			return nil, err
		}
		handle = child
	}
	return os.NewFile(uintptr(handle), absolute), nil
}

func openWindowsPrivateWalkChild(parent *os.File, name string) (*os.File, error) {
	handle, err := openWindowsPrivateWalkChildHandle(windows.Handle(parent.Fd()), name)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func openWindowsPrivateWalkChildHandle(parent windows.Handle, name string) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return 0, errPrivateWalkReparse
	}
	unicodeName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent,
		ObjectName: unicodeName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	var child windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&child, access, &attributes, &status, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
			return 0, fs.ErrNotExist
		}
		return 0, err
	}
	if err := validateWindowsPrivateWalkHandle(child); err != nil {
		_ = windows.CloseHandle(child)
		return 0, err
	}
	return child, nil
}

func validateWindowsPrivateWalkHandle(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errPrivateWalkReparse
	}
	return nil
}

func windowsPrivateWalkHandlePath(handle windows.Handle) (string, error) {
	var small [512]uint16
	n, err := windows.GetFinalPathNameByHandle(handle, &small[0], uint32(len(small)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", errPrivateWalkReparse
	}
	if n < uint32(len(small)) {
		return windows.UTF16ToString(small[:n]), nil
	}
	if n >= 32768 {
		return "", errPrivateWalkReparse
	}
	large := make([]uint16, n+1)
	n, err = windows.GetFinalPathNameByHandle(handle, &large[0], uint32(len(large)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(large)) {
		return "", errPrivateWalkReparse
	}
	return windows.UTF16ToString(large[:n]), nil
}

// windowsCopyIdentity names one copy: the scan refuses reparse points, so
// the cleaned path, case-folded as NTFS compares names, is the copy.
func windowsCopyIdentity(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

// windowsNPMPackageRunnable reports whether an agent's npm package holds an
// entry point (privateNPMEntries): a package record without one is a
// leftover, not a copy. known is false when a reparse point or a read error
// leaves the answer unknown.
func windowsNPMPackageRunnable(connector, dir string) (runnable, known bool) {
	known = true
	manifest, err := readBoundedWindowsAgentPackageJSON(filepath.Join(dir, "package.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		known = false
	}
	for _, entry := range privateNPMEntries(connector, manifest) {
		path := filepath.Join(dir, filepath.FromSlash(entry))
		if winpath.RejectReparseChain(path) != nil {
			known = false
			continue
		}
		info, err := os.Lstat(path)
		switch {
		case err == nil && info.Mode().IsRegular():
			return true, true
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			known = false
		}
	}
	return false, known
}

func scanWindowsNPMPackage(scan *privateInstallScan, name, packageDir string) {
	identity := windowsCopyIdentity(packageDir)
	if scan.seen[identity] {
		return
	}
	if winpath.RejectReparseChain(packageDir) != nil {
		scan.skip(name, PrivateInstallSkippedLocation)
		return
	}
	if info, err := os.Lstat(packageDir); err != nil || !info.IsDir() {
		return
	}
	scan.judge(identity)
	runnable, known := windowsNPMPackageRunnable(name, packageDir)
	if !known {
		scan.skip(name, PrivateInstallSkippedLocation)
		return
	}
	if !runnable {
		return // a leftover package record without an entry point
	}
	version, ok := readWindowsAgentVersionCandidate(filepath.Join(packageDir, "package.json"))
	if ok && privateInstallReason(name, version) == "" {
		return
	}
	scan.add(PrivateAgentInstall{Connector: name, Version: version, Path: packageDir})
}

func scanWindowsClaudeVersions(scan *privateInstallScan, versionsDir string) {
	if winpath.RejectReparseChain(versionsDir) != nil {
		scan.skip("claudecode", PrivateInstallSkippedLocation)
		return
	}
	f, err := os.Open(versionsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
		}
		return
	}
	versions, listErr := f.Readdirnames(privateAgentInstallMaxVersionDirs + 1)
	_ = f.Close()
	if listErr != nil && listErr != io.EOF {
		scan.skip("claudecode", PrivateInstallSkippedLocation)
		return
	}
	if len(versions) > privateAgentInstallMaxVersionDirs {
		scan.skip("claudecode", PrivateInstallSkippedNativeVersions)
	}
	for _, version := range versions {
		path := filepath.Join(versionsDir, version)
		if winpath.RejectReparseChain(path) != nil {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !scan.judge(windowsCopyIdentity(path)) {
			continue
		}
		if !windowsNativeClaudeVersionName(version) {
			version = ""
		}
		if privateInstallReason("claudecode", version) == "" {
			continue
		}
		scan.add(PrivateAgentInstall{Connector: "claudecode", Version: version, Path: path})
	}
}

func containsPrivateConnector(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
