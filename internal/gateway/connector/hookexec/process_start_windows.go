// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = true

// hookWrapperHops is how many launching processes processStartTime looks
// through: the system PowerShell bridge or system cmd.exe of a registration
// and the per-user stable launcher.
const hookWrapperHops = 2

// maxHookWrapperLead is how much earlier than the process it launched a
// wrapper may have started and still count as part of the same call; an
// older one is a long-running shell, not a per-call wrapper.
const maxHookWrapperLead = 10 * time.Second

// hookWrapperProcess is one launching process of the hook: its image and
// when the system created it.
type hookWrapperProcess struct {
	image   string
	created time.Time
}

func processStartTime(time.Time) (time.Time, bool) {
	created, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		return time.Time{}, false
	}
	var wrappers []string
	if system, err := windows.GetSystemDirectory(); err == nil {
		wrappers = append(wrappers,
			filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
			filepath.Join(system, "cmd.exe"))
	}
	return callStartBehindWrappers(created, hookWrapperChain(), wrappers...), true
}

// callStartBehindWrappers is when the call began: created, or the creation
// of the wrappers that launched this process for it (nearest first). Codex,
// Antigravity, Cursor and the other agents whose registration is a system
// PowerShell -EncodedCommand line start PowerShell first, Codex's direct
// registration starts the system cmd.exe first (GAP-1908), and the per-user
// stable launcher starts the full hook: their start counts against the
// budgets as the hook's own does, since the agent waits for all of it (a
// Codex call blocked at 6.4 s with 3 s of hook time behind a 1.9 s
// PowerShell start, GAP-0167). Only an earlier start is taken, so the
// budgets can only get shorter: the call fails closed sooner, never later.
// A parent created after its child is a reused process id, not the wrapper.
func callStartBehindWrappers(created time.Time, chain []hookWrapperProcess, wrappers ...string) time.Time {
	start := created
	for _, parent := range chain {
		if !hookWrapperImage(parent.image, wrappers) || !parent.created.Before(start) ||
			start.Sub(parent.created) > maxHookWrapperLead {
			break
		}
		start = parent.created
	}
	return start
}

// hookWrapperImage reports a wrapper the registrations launch the hook
// through: one of wrappers (the system PowerShell and the system cmd.exe),
// or a DefenseClaw hook binary (the per-user stable launcher).
func hookWrapperImage(image string, wrappers []string) bool {
	image = filepath.Clean(strings.TrimSpace(image))
	if strings.EqualFold(filepath.Base(image), "defenseclaw-hook.exe") {
		return true
	}
	for _, wrapper := range wrappers {
		if wrapper != "" && strings.EqualFold(image, filepath.Clean(wrapper)) {
			return true
		}
	}
	return false
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
		chain = append(chain, hookWrapperProcess{image: image, created: created})
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
