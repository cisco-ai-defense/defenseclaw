// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
	"golang.org/x/sys/windows"
)

// #1164: the enumerator refuses, before it takes any token, a request for an
// account or connector it does not enroll, a record it cannot read, and a
// server whose definition is not the one the gateway scanned; a signed-out
// user is refused with a message that says when the scan runs again. It
// never starts a process for any of them.
func TestWindowsMCPAsUserStarterRefusesBeforeStarting(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	home := `C:\Users\dcw-std1`
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."}, Connector: "claudecode", Project: home + `\proj`}
	request, err := mcpasuser.NewRequest("DefenseClawGateway", sid, server)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	manifest := Manifest{Targets: []ManifestTarget{
		{User: "dcw-std1", UserHome: home, SID: sid, Connector: "claudecode", Enabled: &enabled},
		{User: "dcw-std2", UserHome: `C:\Users\dcw-std2`, SID: "S-1-5-21-1-2-3-1002", Connector: "claudecode", Enabled: &enabled},
	}}
	starter := WindowsMCPAsUserStarter{
		Manifest:         func() (Manifest, error) { return manifest, nil },
		AuthorizationDir: func() (string, error) { return `C:\ProgramData\x`, nil },
	}
	oldSpool, oldToken, oldStart := windowsMCPAsUserReadSpool, windowsMCPAsUserSessionToken, windowsMCPAsUserStartProcess
	t.Cleanup(func() {
		windowsMCPAsUserReadSpool, windowsMCPAsUserSessionToken, windowsMCPAsUserStartProcess = oldSpool, oldToken, oldStart
	})
	published := []config.MCPServerEntry{server}
	var spoolErr error
	var unreadable *ClaudeStateUnreadable
	windowsMCPAsUserReadSpool = func(_, gotSID, connector string) ([]config.MCPServerEntry, *ClaudeStateUnreadable, error) {
		if gotSID != sid || connector != "claudecode" {
			t.Errorf("read the record of %s %s", gotSID, connector)
		}
		return published, unreadable, spoolErr
	}
	tokens := 0
	windowsMCPAsUserSessionToken = func(*windows.SID) (windows.Token, error) {
		tokens++
		return 0, &WindowsTargetSessionUnavailableError{SID: sid}
	}
	windowsMCPAsUserStartProcess = func(windows.Token, []string, []string, string) (mcpasuser.Session, error) {
		t.Fatal("a process was started")
		return nil, nil
	}

	other := request
	other.SID = "S-1-5-21-1-2-3-1003"
	kiro := request
	kiro.Connector = "kiro"
	for name, req := range map[string]mcpasuser.Request{"not enrolled": other, "other connector": kiro} {
		if _, err := starter.Start(context.Background(), req); err == nil || !strings.Contains(err.Error(), "not enrolled") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	spoolErr = errors.New("record missing")
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "record missing") {
		t.Fatalf("unreadable spool: %v", err)
	}
	spoolErr, unreadable = nil, &ClaudeStateUnreadable{Path: home + `\.claude.json`, Reason: "parse"}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unreadable state: %v", err)
	}
	// GAP-0643: once the enumerator republished the record of a user who
	// signed out, the repeat scan still says the user is not signed in.
	unreadable = &ClaudeStateUnreadable{Path: home + `\.claude.json`, Reason: "no session", SignedOut: true}
	if _, err := starter.Start(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), `dcw-std1 is not signed in, so their MCP server "notes" cannot be started`) {
		t.Fatalf("state of a signed-out user: %v", err)
	}
	unreadable = nil
	changed := server
	changed.Args = []string{"-y", "evil"}
	published = []config.MCPServerEntry{changed}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed definition: %v", err)
	}
	shell := server
	shell.Command, shell.Args = "cmd.exe", []string{"/c", "calc"}
	shellRequest, err := mcpasuser.NewRequest("DefenseClawGateway", sid, shell)
	if err != nil {
		t.Fatal(err)
	}
	published = []config.MCPServerEntry{shell}
	if _, err := starter.Start(context.Background(), shellRequest); err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("shell server: %v", err)
	}
	if tokens != 0 {
		t.Fatalf("a token was taken for a refused request (%d)", tokens)
	}
	published = []config.MCPServerEntry{server}
	if _, err := starter.Start(context.Background(), request); err == nil || !strings.Contains(err.Error(), "not signed in") {
		t.Fatalf("signed-out user: %v", err)
	}
}

// #1164: the managed launcher policy trusts only a launcher installed for
// all users under Program Files that only administrators can change; a
// same-name launcher in a folder the user can write is refused.
func TestWindowsMCPAsUserLauncherFSTrustsOnlyProgramFiles(t *testing.T) {
	roots, err := windowsProgramFilesRoots()
	if err != nil {
		t.Fatal(err)
	}
	fs := windowsMCPAsUserLauncherFS(roots)
	writable := filepath.Join(t.TempDir(), "npx.cmd")
	if err := os.WriteFile(writable, []byte("@echo off\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fs.exists(writable) || fs.exists(filepath.Dir(writable)) {
		t.Fatal("exists does not tell a file from a folder")
	}
	if err := fs.trusted(writable); err == nil || !strings.Contains(err.Error(), "Program Files") {
		t.Fatalf("a launcher in a user folder: %v", err)
	}
	if _, err := resolveMCPAsUserLauncher(mcpAsUserLauncher{name: "npx", file: "npx.cmd"}, filepath.Dir(writable),
		os.Getenv("PATH"), "", fs); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("an npx.cmd in the working folder: %v", err)
	}
	installed := filepath.Join(roots[0], "nodejs", "npx.cmd")
	if _, err := os.Stat(installed); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("the CI runner has no Node.js under Program Files: %v", err)
		}
		t.Skipf("no Node.js installed for all users: %v", err)
	}
	if err := fs.trusted(installed); err != nil {
		t.Fatalf("the all-users npx.cmd is not trusted: %v", err)
	}
}

// windowsMCPAsUserHelperEnv makes the test binary act as an as-user server.
const windowsMCPAsUserHelperEnv = "MCP_AS_USER_TEST_CHILD"

// TestWindowsMCPAsUserHelperChild is the child process of
// TestStartWindowsMCPAsUserProcessRunsOnItsOwnDesktop. It reports its
// folder, session and window station, echoes one stdin line and exits 7.
func TestWindowsMCPAsUserHelperChild(t *testing.T) {
	if os.Getenv(windowsMCPAsUserHelperEnv) != "1" {
		t.Skip("helper process")
	}
	cwd, _ := os.Getwd()
	var session uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	station := ""
	if handle, _, _ := procGetProcessWindowStation.Call(); handle != 0 {
		buf := make([]uint16, 256)
		var needed uint32
		getName := modWindowsMCPAsUserUser32.NewProc("GetUserObjectInformationW")
		const uoiName = 2
		if ok, _, _ := getName.Call(handle, uoiName, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&needed))); ok != 0 {
			station = windows.UTF16ToString(buf)
		}
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Printf("cwd=%s\nsession=%d\nstation=%s\nline=%s\n", cwd, session, station, strings.TrimSpace(line))
	fmt.Fprintln(os.Stderr, "helper stderr")
	os.Exit(7)
}

// #1164: the as-user start really creates the process: in the folder it was
// given, with the environment it was given, on its own window station (not
// the caller's), carrying stdio both ways and the exit code. It runs in the
// caller's session, whatever session the token names: that is the
// CreateProcessWithTokenW contract the enumerator relies on (the services
// session for the enumerator, this session here).
func TestStartWindowsMCPAsUserProcessRunsOnItsOwnDesktop(t *testing.T) {
	if os.Getenv(windowsMCPAsUserHelperEnv) == "1" {
		t.Skip("helper process")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(process,
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID,
		nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), windowsMCPAsUserHelperEnv+"=1")
	session, err := startWindowsMCPAsUserProcess(primary, []string{exe, "-test.run=^TestWindowsMCPAsUserHelperChild$"}, env, work)
	if err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || strings.Contains(err.Error(), "does not hold") {
			enabled, privilegeErr := windowsTestProcessImpersonatePrivilegeEnabled(process)
			if privilegeErr != nil {
				t.Fatalf("check the runner's process token after %v: %v", err, privilegeErr)
			}
			if !enabled {
				t.Skipf("the runner's process token has SeImpersonatePrivilege disabled: %v", err)
			}
		}
		if strings.Contains(err.Error(), "Secondary Logon") && os.Getenv("GITHUB_ACTIONS") != "true" {
			t.Skipf("this runner cannot start a process with a token: %v", err)
		}
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := io.WriteString(session.Stdin(), "ping\n"); err != nil {
		t.Fatal(err)
	}
	_ = session.Stdin().Close()
	type read struct {
		out, errOut []byte
	}
	done := make(chan read, 1)
	go func() {
		errOut := make(chan []byte, 1)
		go func() { data, _ := io.ReadAll(session.Stderr()); errOut <- data }()
		out, _ := io.ReadAll(session.Stdout())
		done <- read{out, <-errOut}
	}()
	var got read
	select {
	case got = <-done:
	case <-time.After(2 * time.Minute):
		session.Kill()
		t.Fatal("the child did not finish")
	}
	code, err := session.Wait()
	if err != nil || code != 7 {
		t.Fatalf("exit code %d (%v), want 7; stdout %q stderr %q", code, err, got.out, got.errOut)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(got.out), "\r", ""), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fields[key] = value
		}
	}
	var own uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(fields["cwd"], work) || fields["session"] != strconv.FormatUint(uint64(own), 10) ||
		!strings.HasPrefix(fields["station"], "DefenseClaw-MCP-") || fields["line"] != "ping" ||
		!strings.Contains(string(got.errOut), "helper stderr") {
		t.Fatalf("child reported %q (stderr %q); want cwd %s, session %d, a private station and the stdin line",
			got.out, got.errOut, work, own)
	}
}

// The preflight job carries GITHUB_ACTIONS=true but disables its process
// token's privileges to match a hosted runner. CreateProcessWithTokenW can
// return ERROR_PRIVILEGE_NOT_HELD in that token even when the helper enabled
// SeImpersonatePrivilege on its impersonated thread. Inspect the capability
// that the failed process actually inherited instead of guessing from CI env.
func windowsTestProcessImpersonatePrivilegeEnabled(token windows.Token) (bool, error) {
	name, err := windows.UTF16PtrFromString("SeImpersonatePrivilege")
	if err != nil {
		return false, err
	}
	var want windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &want); err != nil {
		return false, err
	}
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size == 0 || size > 64<<10 {
		return false, fmt.Errorf("size process token privileges: %w", err)
	}
	data := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &data[0], size, &size); err != nil {
		return false, err
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&data[0]))
	needed := unsafe.Offsetof(windows.Tokenprivileges{}.Privileges) + uintptr(privileges.PrivilegeCount)*unsafe.Sizeof(windows.LUIDAndAttributes{})
	if needed > uintptr(len(data)) {
		return false, errors.New("process token privileges exceed their returned buffer")
	}
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid == want {
			return privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0, nil
		}
	}
	return false, nil
}
