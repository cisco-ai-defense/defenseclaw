// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = true

// hookWrapperHops is how many launching processes processStartTime looks
// through: the system PowerShell bridge of a registration and the per-user
// stable launcher.
const hookWrapperHops = 2

// maxHookWrapperLead bounds the time a verified one-call wrapper can add to
// the hook's start. A script that starts several hooks is never a wrapper.
const maxHookWrapperLead = 10 * time.Second

// hookWrapperProcess is one launching process of the hook: its image, start
// and command line. Only a recognized one-call PowerShell bridge contributes
// its start to the hook budget.
type hookWrapperProcess struct {
	image   string
	created time.Time
	argv    []string
}

func processStartTime(time.Time) (time.Time, bool) {
	created, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		return time.Time{}, false
	}
	powerShell := ""
	if system, err := windows.GetSystemDirectory(); err == nil {
		powerShell = filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	return callStartBehindWrappers(created, hookWrapperChain(), powerShell), true
}

// callStartBehindWrappers is when the call began: created, or the creation
// of the wrappers that launched this process for it (nearest first). Codex,
// Antigravity, Cursor and the other agents whose registration is a system
// PowerShell -EncodedCommand line start PowerShell first, and the per-user
// stable launcher starts the full hook: their start counts against the
// budgets as the hook's own does, since the agent waits for all of it (a
// Codex call blocked at 6.4 s with 3 s of hook time behind a 1.9 s
// PowerShell start, GAP-0167). Only an earlier start is taken, so the
// budgets can only get shorter: the call fails closed sooner, never later.
// A parent created after its child is a reused process id, not the wrapper.
func callStartBehindWrappers(created time.Time, chain []hookWrapperProcess, powerShell string) time.Time {
	start := created
	for _, parent := range chain {
		if !hookWrapperImage(parent.image, powerShell) || !parent.created.Before(start) ||
			start.Sub(parent.created) > maxHookWrapperLead {
			break
		}
		if powerShell != "" && strings.EqualFold(filepath.Clean(parent.image), filepath.Clean(powerShell)) &&
			!oneCallPowerShellBridge(parent.argv) {
			break
		}
		start = parent.created
	}
	return start
}

// oneCallPowerShellBridge recognizes the PowerShell command emitted for one
// registered hook call. A PowerShell -File driver may launch many hooks from
// the same process; charging every call for that process's age made new calls
// fail immediately after the first few and recover at maxHookWrapperLead.
// An unreadable or unfamiliar command line does not shorten this call's
// budget. The hook's own process creation still bounds it.
func oneCallPowerShellBridge(argv []string) bool {
	if len(argv) != 6 || !strings.EqualFold(argv[1], "-NoLogo") ||
		!strings.EqualFold(argv[2], "-NoProfile") || !strings.EqualFold(argv[3], "-NonInteractive") ||
		!strings.EqualFold(argv[4], "-EncodedCommand") || len(argv[5]) > 64<<10 {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(argv[5])
	if err != nil || len(data) == 0 || len(data)&1 != 0 {
		return false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	script := string(utf16.Decode(units))
	const nativePrefix = "$ErrorActionPreference='Stop'; $env:NoDefaultCurrentDirectoryInExePath='1'; "
	if strings.HasPrefix(script, nativePrefix) {
		if strings.HasSuffix(script, "; exit $hookProcess.ExitCode") {
			return strings.Contains(script, "$hookProcess=[System.Diagnostics.Process]::Start($hookStart)") &&
				strings.Contains(script, "$hookProcess.WaitForExit()") ||
				strings.Contains(script, "Start-Process -FilePath") && strings.Contains(script, " -Wait -PassThru")
		}
		return strings.HasSuffix(script, "; exit $LASTEXITCODE") && strings.Contains(script, "defenseclaw-hook")
	}
	// Cursor's registered adapter reads stdin itself and invokes one adapter
	// script. It has no explicit exit line but PowerShell exits after the call.
	return strings.HasPrefix(script, "$reader=[IO.StreamReader]::new([Console]::OpenStandardInput(),") &&
		strings.Contains(script, "$payload | & ") && strings.Contains(strings.ToLower(script), "cursor-hook.ps1")
}

// hookWrapperImage reports a wrapper the registrations launch the hook
// through: the system PowerShell, or a DefenseClaw hook binary (the per-user
// stable launcher).
func hookWrapperImage(image, powerShell string) bool {
	image = filepath.Clean(strings.TrimSpace(image))
	if strings.EqualFold(filepath.Base(image), "defenseclaw-hook.exe") {
		return true
	}
	return powerShell != "" && strings.EqualFold(image, filepath.Clean(powerShell))
}

// hookWrapperChain reads the launching processes of this one, nearest first,
// up to hookWrapperHops. It stops at the first it cannot read.
func hookWrapperChain() []hookWrapperProcess {
	var chain []hookWrapperProcess
	child := windows.CurrentProcess()
	var opened []windows.Handle
	defer func() {
		for _, handle := range opened {
			_ = windows.CloseHandle(handle)
		}
	}()
	for hop := 0; hop < hookWrapperHops; hop++ {
		var info windows.PROCESS_BASIC_INFORMATION
		var returned uint32
		if err := windows.NtQueryInformationProcess(child, windows.ProcessBasicInformation,
			unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &returned); err != nil {
			break
		}
		parentID := uint32(info.InheritedFromUniqueProcessId)
		if parentID == 0 {
			break
		}
		parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parentID)
		if err != nil {
			break
		}
		opened = append(opened, parent)
		image, err := processImagePath(parent)
		if err != nil {
			break
		}
		created, err := processCreationTime(parent)
		if err != nil {
			break
		}
		var argv []string
		if strings.EqualFold(filepath.Base(image), "powershell.exe") {
			argv, _ = agentprocess.CommandLineForPID(int(parentID))
		}
		chain = append(chain, hookWrapperProcess{image: image, created: created, argv: argv})
		child = parent
	}
	return chain
}

func processCreationTime(process windows.Handle) (time.Time, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, creation.Nanoseconds()), nil
}

func processImagePath(process windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}
