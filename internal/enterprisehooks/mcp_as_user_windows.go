// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"golang.org/x/sys/windows"
)

// mcpAsUserActiveProcessLimit bounds the processes one server may run
// (npx starts node, uvx a Python).
const mcpAsUserActiveProcessLimit = 64

// WindowsMCPAsUserStarter starts, as the enrolled user, a local MCP server
// that the hook enumerator published for that user, for the gateway's
// admission scan (#1164). It runs in the enumerator service (LocalSystem).
//
// It starts only the definition in its own published record (the request
// names it, its digest pins it), only an npx or uvx launcher with a package
// argument, only with the user's own signed-in session token, only in the
// folder the agent uses (its cwd, else its project, else the profile, never
// a stand-in for a refused one) after it checked that folder while
// impersonating the user: inside the project or the user's profile, in no
// other profile, with no link or reparse point on the way. The launcher is
// the one the agent would run with the server's env, and only one installed
// for all users under Program Files that only administrators can change. The
// server runs in the services session on a private desktop (see
// startWindowsMCPAsUserProcess), and it and everything it starts run in a job
// that ends with the scan. Any failure refuses the start, and the gateway
// blocks the server.
type WindowsMCPAsUserStarter struct {
	// Manifest returns the enrolled targets.
	Manifest func() (Manifest, error)
	// AuthorizationDir returns the hook guardian authorization folder that
	// holds the published records.
	AuthorizationDir func() (string, error)
}

// Seams for tests.
var (
	windowsMCPAsUserReadSpool = func(dir, sid, connector string) ([]config.MCPServerEntry, *ClaudeStateUnreadable, error) {
		return readMCPSpool(dir, sid, connector, managed.ValidateTrustedFilePath)
	}
	windowsMCPAsUserSessionToken = windowsEnterpriseSignedInTargetTokenResolver
	windowsMCPAsUserStartProcess = startWindowsMCPAsUserProcess
)

// Start implements mcpasuser.Starter.
func (s WindowsMCPAsUserStarter) Start(_ context.Context, request mcpasuser.Request) (mcpasuser.Session, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if s.Manifest == nil || s.AuthorizationDir == nil {
		return nil, errors.New("the hook enumerator has no enrollment to check the request against")
	}
	manifest, err := s.Manifest()
	if err != nil {
		return nil, fmt.Errorf("read the enrollment manifest: %w", err)
	}
	target, homes, ok := mcpAsUserTarget(manifest, request)
	if !ok {
		return nil, fmt.Errorf("account %s is not enrolled for %s", request.SID, request.Connector)
	}
	home := filepath.Clean(strings.TrimSpace(target.UserHome))
	account := strings.TrimSpace(target.User)
	if account == "" {
		account = request.SID
	}
	authorizationDir, err := s.AuthorizationDir()
	if err != nil {
		return nil, err
	}
	dir := ClaudeMCPSpoolDir(authorizationDir)
	if request.Connector == "kiro" {
		dir = KiroMCPSpoolDir(authorizationDir)
	}
	servers, unreadable, err := windowsMCPAsUserReadSpool(dir, request.SID, request.Connector)
	if err != nil {
		return nil, fmt.Errorf("read the MCP servers published for %s: %w", account, err)
	}
	if unreadable != nil && unreadable.SignedOut {
		// The enumerator could not read the servers as the user: the user
		// signed out after the gateway saw the server (GAP-0643).
		return nil, mcpAsUserSignedOut(account, request.Name)
	}
	if unreadable != nil {
		return nil, fmt.Errorf("the MCP servers of %s are unknown: %s (%s)", account, unreadable.Path, unreadable.Reason)
	}
	entry, err := findMCPAsUserServer(servers, request)
	if err != nil {
		return nil, err
	}
	entry.Home = home
	launcher, err := checkMCPAsUserDefinition(entry)
	if err != nil {
		return nil, fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
	}

	sid, err := validateWindowsEnterpriseTargetSID(request.SID)
	if err != nil {
		return nil, err
	}
	impersonation, err := windowsMCPAsUserSessionToken(sid)
	if err != nil {
		if IsWindowsTargetSessionUnavailable(err) {
			return nil, mcpAsUserSignedOut(account, entry.Name)
		}
		return nil, fmt.Errorf("get the session token of %s: %w", account, err)
	}
	defer impersonation.Close()
	if err := validateWindowsEnterpriseTargetToken(impersonation, sid); err != nil {
		return nil, err
	}
	if err := validateWindowsEnterpriseTokenProfile(impersonation, home); err != nil {
		return nil, err
	}
	var primary windows.Token
	if err := windows.DuplicateTokenEx(impersonation,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, fmt.Errorf("make a process token for %s: %w", account, err)
	}
	defer primary.Close()
	userEnv, err := primary.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("read the environment of %s: %w", account, err)
	}
	env := mergeMCPAsUserEnv(userEnv, entry.Env)

	programFiles, err := windowsProgramFilesRoots()
	if err != nil {
		return nil, err
	}
	// The folder and the launcher are resolved as the user: the user's
	// access decides, so a junction into another profile fails.
	var workDir, launcherPath string
	if err := runWindowsEnterpriseImpersonatedCallback(impersonation, sid, func() error {
		var err error
		workDir, launcherPath, err = planMCPAsUserLaunch(entry, home, otherWindowsHomes(homes, home), launcher, env,
			windowsClaudeMCPWorkDirChecks, windowsMCPAsUserLauncherFS(programFiles))
		return err
	}); err != nil {
		return nil, err
	}
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	argv, err := mcpAsUserArgv(launcher, launcherPath, filepath.Join(systemDir, "cmd.exe"), entry.Args)
	if err != nil {
		return nil, fmt.Errorf("MCP server %q is not started: %w", entry.Name, err)
	}
	return windowsMCPAsUserStartProcess(primary, argv, env, workDir)
}

// mcpAsUserSignedOut is the refusal for an account that is not signed in.
func mcpAsUserSignedOut(account, server string) error {
	return fmt.Errorf("%s is not signed in, so their MCP server %q cannot be started as them; "+
		"it is scanned again once they sign in", account, server)
}

// mcpAsUserTarget is the enabled manifest row of the request's account and
// connector, and every enrolled profile.
func mcpAsUserTarget(manifest Manifest, request mcpasuser.Request) (ManifestTarget, []string, bool) {
	var homes []string
	var found ManifestTarget
	ok := false
	for _, target := range manifest.Targets {
		home := strings.TrimSpace(target.UserHome)
		if filepath.IsAbs(home) {
			homes = append(homes, filepath.Clean(home))
		}
		if ok || !strings.EqualFold(strings.TrimSpace(target.SID), request.SID) ||
			!strings.EqualFold(strings.TrimSpace(target.Connector), request.Connector) ||
			(target.Enabled != nil && !*target.Enabled) || !filepath.IsAbs(home) {
			continue
		}
		found, ok = target, true
	}
	return found, homes, ok
}

// windowsProgramFilesRoots are the Program Files folders, from the Known
// Folder API, not the environment.
func windowsProgramFilesRoots() ([]string, error) {
	var roots []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		root, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT)
		if err != nil {
			continue
		}
		if root = filepath.Clean(strings.TrimSpace(root)); filepath.IsAbs(root) && !containsFold(roots, root) {
			roots = append(roots, root)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("the Program Files folder is unknown, so no MCP launcher can be trusted")
	}
	return roots, nil
}

// windowsMCPAsUserLauncherFS is the launcher policy of a managed scan, as the
// scanner applies it to a server the gateway starts itself: the launcher is
// under Program Files and only administrators can change it or any folder
// above it (owner, DACL, no link or reparse point on the way).
func windowsMCPAsUserLauncherFS(programFiles []string) mcpAsUserLauncherFS {
	return mcpAsUserLauncherFS{
		exists: func(path string) bool {
			info, err := os.Lstat(path)
			return err == nil && !info.IsDir()
		},
		trusted: func(path string) error {
			inside := false
			for _, root := range programFiles {
				if claudeMCPPathWithin(path, root) {
					inside = true
					break
				}
			}
			if !inside {
				return errors.New("it is not under Program Files")
			}
			return managed.ValidateTrustedFilePath(path, "MCP launcher")
		},
	}
}

// windowsMCPAsUserSession is a server started by startWindowsMCPAsUserProcess.
type windowsMCPAsUserSession struct {
	process, job          windows.Handle
	desktop               *windowsMCPAsUserDesktop
	stdin, stdout, stderr *os.File
	killOnce, releaseOnce sync.Once
}

func (s *windowsMCPAsUserSession) Stdin() io.WriteCloser { return s.stdin }
func (s *windowsMCPAsUserSession) Stdout() io.Reader     { return s.stdout }
func (s *windowsMCPAsUserSession) Stderr() io.Reader     { return s.stderr }

func (s *windowsMCPAsUserSession) Wait() (int, error) {
	if _, err := windows.WaitForSingleObject(s.process, windows.INFINITE); err != nil {
		return 1, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(s.process, &code); err != nil {
		return 1, err
	}
	return int(int32(code)), nil
}

func (s *windowsMCPAsUserSession) Kill() {
	s.killOnce.Do(func() { _ = windows.TerminateJobObject(s.job, 1) })
}

func (s *windowsMCPAsUserSession) Close() {
	s.Kill()
	s.releaseOnce.Do(func() {
		_ = s.stdin.Close()
		_ = s.stdout.Close()
		_ = s.stderr.Close()
		_ = windows.CloseHandle(s.process)
		_ = windows.CloseHandle(s.job)
		s.desktop.close()
	})
}

// windowsMCPAsUserMaxCommandLine is the longest command line
// CreateProcessWithTokenW accepts, in UTF-16 units.
const windowsMCPAsUserMaxCommandLine = 1024

// startWindowsMCPAsUserProcess starts argv with the user's primary token in
// workDir, hidden on a private desktop, in a job that kills every process of
// the server when the job handle closes. The child gets only its three stdio
// pipe ends.
//
// Session: CreateProcessWithTokenW starts the process in the caller's
// session, whatever session the token names. The enumerator runs in the
// services session (0), so the server runs there with the user's identity,
// environment, profile hive and files, but not on the user's own desktop.
// That is the supported contract of the scan: it speaks MCP over stdio and
// needs no desktop; a server that needs the user's interactive desktop,
// clipboard or session-local objects fails its scan and stays blocked. The
// desktop is a window station and desktop made for this one server that only
// LocalSystem and the user can open, never the services desktop, which the
// function would otherwise open to the user.
func startWindowsMCPAsUserProcess(token windows.Token, argv, env []string, workDir string) (_ mcpasuser.Session, err error) {
	if len(argv) == 0 {
		return nil, errors.New("no command to start")
	}
	commandLine := make([]string, len(argv))
	for i, arg := range argv {
		commandLine[i] = windows.EscapeArg(arg)
	}
	joined := strings.Join(commandLine, " ")
	if n := len(utf16.Encode([]rune(joined))); n > windowsMCPAsUserMaxCommandLine {
		return nil, fmt.Errorf("the server command line has %d characters; Windows starts at most %d as another user",
			n, windowsMCPAsUserMaxCommandLine)
	}
	appName, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		return nil, err
	}
	cmdLine, err := windows.UTF16PtrFromString(joined)
	if err != nil {
		return nil, err
	}
	dirPtr, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return nil, err
	}
	block, err := windowsEnvironmentBlock(env)
	if err != nil {
		return nil, err
	}
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("read the user of the server token: %v", err)
	}
	desktop, err := newWindowsMCPAsUserDesktop(user.User.Sid)
	if err != nil {
		return nil, err
	}
	desktopName, err := windows.UTF16PtrFromString(desktop.name)
	if err != nil {
		desktop.close()
		return nil, err
	}

	var closers []windows.Handle
	closeAll := func() {
		for _, handle := range closers {
			_ = windows.CloseHandle(handle)
		}
		desktop.close()
	}
	inherit := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	pipe := func(childReads bool) (parent, child windows.Handle, err error) {
		var readEnd, writeEnd windows.Handle
		if err := windows.CreatePipe(&readEnd, &writeEnd, &inherit, 0); err != nil {
			return 0, 0, err
		}
		closers = append(closers, readEnd, writeEnd)
		parent, child = writeEnd, readEnd
		if !childReads {
			parent, child = readEnd, writeEnd
		}
		if err := windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
			return 0, 0, err
		}
		return parent, child, nil
	}
	stdinParent, stdinChild, err := pipe(true)
	if err == nil {
		var stdoutParent, stdoutChild, stderrParent, stderrChild windows.Handle
		if stdoutParent, stdoutChild, err = pipe(false); err == nil {
			if stderrParent, stderrChild, err = pipe(false); err == nil {
				session, err := startWindowsMCPAsUserChild(token, appName, cmdLine, block, dirPtr, desktopName,
					[3]windows.Handle{stdinChild, stdoutChild, stderrChild},
					[3]windows.Handle{stdinParent, stdoutParent, stderrParent}, &closers, closeAll)
				if err != nil {
					return nil, err
				}
				session.desktop = desktop
				return session, nil
			}
		}
	}
	closeAll()
	return nil, fmt.Errorf("create the server stdio pipes: %w", err)
}

// windowsMCPAsUserDesktop is the private window station and desktop of one
// as-user server.
type windowsMCPAsUserDesktop struct {
	station, desktop uintptr
	// name is "station\desktop", as STARTUPINFO.lpDesktop names it.
	name      string
	closeOnce sync.Once
}

func (d *windowsMCPAsUserDesktop) close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		if d.desktop != 0 {
			_, _, _ = procCloseDesktop.Call(d.desktop)
		}
		if d.station != 0 {
			_, _, _ = procCloseWindowStation.Call(d.station)
		}
	})
}

var (
	modWindowsMCPAsUserUser32   = windows.NewLazySystemDLL("user32.dll")
	procCreateWindowStationW    = modWindowsMCPAsUserUser32.NewProc("CreateWindowStationW")
	procCreateDesktopW          = modWindowsMCPAsUserUser32.NewProc("CreateDesktopW")
	procGetProcessWindowStation = modWindowsMCPAsUserUser32.NewProc("GetProcessWindowStation")
	procSetProcessWindowStation = modWindowsMCPAsUserUser32.NewProc("SetProcessWindowStation")
	procCloseWindowStation      = modWindowsMCPAsUserUser32.NewProc("CloseWindowStation")
	procCloseDesktop            = modWindowsMCPAsUserUser32.NewProc("CloseDesktop")

	// CreateDesktop makes the desktop in the process window station, so
	// the enumerator switches to the new station for that one call.
	windowsMCPAsUserStationMu sync.Mutex
)

const (
	windowsCWFCreateOnly          = 0x00000001
	windowsStandardRightsRequired = 0x000F0000
	windowsWinstaAllAccess        = 0x0000037F | windowsStandardRightsRequired
	windowsDesktopAllAccess       = 0x000001FF | windowsStandardRightsRequired
)

// newWindowsMCPAsUserDesktop makes a window station with one desktop that
// only LocalSystem and user can open.
func newWindowsMCPAsUserDesktop(user *windows.SID) (*windowsMCPAsUserDesktop, error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + user.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("make the server desktop access list: %w", err)
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	stationName := "DefenseClaw-MCP-" + hex.EncodeToString(nonce[:])
	stationPtr, err := windows.UTF16PtrFromString(stationName)
	if err != nil {
		return nil, err
	}
	desktopPtr, err := windows.UTF16PtrFromString("Default")
	if err != nil {
		return nil, err
	}
	windowsMCPAsUserStationMu.Lock()
	defer windowsMCPAsUserStationMu.Unlock()
	station, _, callErr := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(stationPtr)), windowsCWFCreateOnly,
		windowsWinstaAllAccess, uintptr(unsafe.Pointer(&attributes)))
	if station == 0 {
		return nil, fmt.Errorf("create the server window station: %w", windowsCallError(callErr))
	}
	d := &windowsMCPAsUserDesktop{station: station, name: stationName + `\Default`}
	previous, _, callErr := procGetProcessWindowStation.Call()
	if previous == 0 {
		d.close()
		return nil, fmt.Errorf("read the enumerator window station: %w", windowsCallError(callErr))
	}
	if ok, _, callErr := procSetProcessWindowStation.Call(station); ok == 0 {
		d.close()
		return nil, fmt.Errorf("switch to the server window station: %w", windowsCallError(callErr))
	}
	desktop, _, desktopErr := procCreateDesktopW.Call(uintptr(unsafe.Pointer(desktopPtr)), 0, 0, 0,
		windowsDesktopAllAccess, uintptr(unsafe.Pointer(&attributes)))
	if ok, _, callErr := procSetProcessWindowStation.Call(previous); ok == 0 {
		// The enumerator keeps the new station as its own; it is closed
		// with the process. Nothing starts on it.
		if desktop != 0 {
			_, _, _ = procCloseDesktop.Call(desktop)
		}
		return nil, fmt.Errorf("switch back from the server window station: %w", windowsCallError(callErr))
	}
	runtime.KeepAlive(sd)
	if desktop == 0 {
		d.close()
		return nil, fmt.Errorf("create the server desktop: %w", windowsCallError(desktopErr))
	}
	d.desktop = desktop
	return d, nil
}

func windowsCallError(err error) error {
	if err == nil || err == windows.ERROR_SUCCESS {
		return errors.New("the call failed")
	}
	return err
}

func startWindowsMCPAsUserChild(
	token windows.Token,
	appName, cmdLine, block, dirPtr, desktop *uint16,
	child, parent [3]windows.Handle,
	closers *[]windows.Handle,
	closeAll func(),
) (*windowsMCPAsUserSession, error) {
	startup := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    desktop,
		Flags:      windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
		StdInput:   child[0],
		StdOutput:  child[1],
		StdErr:     child[2],
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("create the server job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
				windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
			ActiveProcessLimit: mcpAsUserActiveProcessLimit,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("limit the server job: %w", err)
	}
	var info windows.ProcessInformation
	err = withWindowsImpersonatePrivilege(func() error {
		return createWindowsProcessWithToken(token, windowsLogonWithProfile, appName, cmdLine,
			windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NEW_CONSOLE,
			block, dirPtr, &startup, &info)
	})
	if err != nil {
		_ = windows.CloseHandle(job)
		closeAll()
		if errors.Is(err, windows.ERROR_SERVICE_DISABLED) {
			return nil, errors.New("start the server as the user: the Secondary Logon (seclogon) service is disabled; " +
				"DefenseClaw needs it to start an MCP server in a user profile as that user for its scan")
		}
		return nil, fmt.Errorf("start the server as the user: %w", err)
	}
	defer windows.CloseHandle(info.Thread)
	if err := windows.AssignProcessToJobObject(job, info.Process); err != nil {
		_ = windows.TerminateProcess(info.Process, 1)
		_ = windows.CloseHandle(info.Process)
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("put the server in its job: %w", err)
	}
	if _, err := windows.ResumeThread(info.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(info.Process)
		_ = windows.CloseHandle(job)
		closeAll()
		return nil, fmt.Errorf("resume the server: %w", err)
	}
	// The child holds its ends now; the parent keeps only its own.
	for _, handle := range child {
		_ = windows.CloseHandle(handle)
	}
	*closers = nil
	return &windowsMCPAsUserSession{
		process: info.Process, job: job,
		stdin:  os.NewFile(uintptr(parent[0]), "mcp-server-stdin"),
		stdout: os.NewFile(uintptr(parent[1]), "mcp-server-stdout"),
		stderr: os.NewFile(uintptr(parent[2]), "mcp-server-stderr"),
	}, nil
}

// CreateProcessWithTokenW starts a process with another user's token
// through the Secondary Logon service. It needs only SeImpersonatePrivilege,
// which the enumerator service already holds, so no service privilege
// changes and an upgrade or a rollback keeps the service configuration.
var (
	modWindowsMCPAsUserAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessWithTokenW = modWindowsMCPAsUserAdvapi32.NewProc("CreateProcessWithTokenW")
)

// windowsLogonWithProfile is LOGON_WITH_PROFILE: the user's registry hive is
// loaded for the process, as it is for the user's own programs.
const windowsLogonWithProfile = 0x00000001

func createWindowsProcessWithToken(
	token windows.Token, logonFlags uint32, appName, cmdLine *uint16, creationFlags uint32,
	env, currentDir *uint16, startup *windows.StartupInfo, info *windows.ProcessInformation,
) error {
	if err := procCreateProcessWithTokenW.Find(); err != nil {
		return err
	}
	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(token), uintptr(logonFlags), uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(cmdLine)),
		uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startup)), uintptr(unsafe.Pointer(info)))
	runtime.KeepAlive(startup)
	if ret == 0 {
		if callErr == nil || callErr == windows.ERROR_SUCCESS {
			return errors.New("CreateProcessWithTokenW failed")
		}
		return callErr
	}
	return nil
}

// withWindowsImpersonatePrivilege runs fn on a locked thread with
// SeImpersonatePrivilege enabled, which CreateProcessWithTokenW requires.
func withWindowsImpersonatePrivilege(fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create a process creation token: %w", err)
			return
		}
		var token windows.Token
		err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token)
		if err == nil {
			err = enableWindowsThreadPrivilege(token, "SeImpersonatePrivilege")
			token.Close()
		}
		if err == nil {
			err = fn()
		}
		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Never return a still-impersonating thread to the pool.
			result <- errors.Join(err, fmt.Errorf("revert the process creation token: %w", revertErr))
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}

// windowsEnvironmentBlock is env as a CreateProcess environment block.
func windowsEnvironmentBlock(env []string) (*uint16, error) {
	var block []uint16
	for _, kv := range env {
		if strings.ContainsRune(kv, 0) {
			return nil, errors.New("an environment entry contains NUL")
		}
		block = append(block, utf16.Encode([]rune(kv))...)
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	block = append(block, 0)
	return &block[0], nil
}
