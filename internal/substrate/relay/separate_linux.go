// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// separate decides how the relay keeps the agent away from itself
// (substrate-1 GAP-0116). In an actor the relay is PID 1, but gVisor delivers
// SIGKILL and SIGSTOP from inside the actor to its PID 1, so a relay and an
// agent of the same user are not separated. A kit image of 1.0.10 or later
// runs the relay as root and names the agent's user (relay.agent_user): every
// process the relay starts runs as that user with no capabilities, so the
// agent cannot signal, trace or replace the relay.
//
// The outcomes:
//   - agent_user unset, or the relay is not root: not separated (nil, a
//     warning). Images built before 1.0.10 run like this.
//   - the relay is root and may change user: separated, and the relay keeps
//     only the capabilities it needs (confine, GAP-0376).
//   - the relay is root but may not change user or stop the agent (no
//     CAP_SETUID, CAP_SETGID or CAP_KILL), or cannot drop the rest: an
//     error. The agent is never run as root.
func separate(rc kit.RelayConfig) (*separation, string, error) {
	uid, gid, ok, err := rc.AgentIDs()
	if err != nil {
		return nil, "", err
	}
	euid := os.Geteuid()
	switch {
	case !ok:
		return nil, "the agent runs as the relay's own user, so it can stop the relay (under gVisor even as PID 1); rebuild the template with DefenseClaw 1.0.10 or later to separate them", nil
	case euid != 0:
		return nil, fmt.Sprintf("relay.agent_user is %s but the relay runs as UID %d, not root, so the agent and the relay are not separated; the template's image must keep USER 0 (template build sets it)", rc.AgentUser, euid), nil
	}
	if !hasCaps(unix.CAP_SETUID, unix.CAP_SETGID) {
		return nil, "", fmt.Errorf("the relay runs as root but may not change user (CAP_SETUID or CAP_SETGID is dropped), so it cannot start the agent as %s; it never runs the agent as root. Keep the default capabilities in the template", rc.AgentUser)
	}
	if !hasCaps(unix.CAP_KILL) {
		return nil, "", fmt.Errorf("the relay runs as root but may not signal the agent's processes (CAP_KILL is dropped), so it could not stop the agent when DefenseClaw's hooks are tampered with. Keep the default capabilities in the template")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, "", fmt.Errorf("the relay cannot find its own binary to copy files as the agent's user: %w", err)
	}
	// No process the relay starts may gain privileges through a set-user-ID
	// program (sudo, su) and come back for the relay as root. The flag is
	// per thread, so every thread gets it.
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		return nil, "", fmt.Errorf("the relay could not set no_new_privs on every thread (%v; a build with cgo cannot), so a set-user-ID program in the image could give the agent root back; build the relay with CGO_ENABLED=0", errno)
	}
	warn, err := confine()
	if err != nil {
		return nil, "", err
	}
	return &separation{cred: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}, exe: exe}, warn, nil
}

// relayCaps are the only capabilities a separated relay keeps (GAP-0376),
// each for code that needs it:
//   - CAP_SETUID, CAP_SETGID: every process it starts (agent PTY, headless
//     task, exec, the files-put, files-get and state-dir children) is
//     switched to relay.agent_user (asAgent: setgroups, setgid, setuid).
//   - CAP_KILL: it signals the agent's processes, another user's: the
//     agent's process group (killProcessGroup), the task tree on a stall
//     (procTree.signal) and every process of the actor on a guard trip
//     (stopActorProcesses).
//   - CAP_CHOWN: it gives the agent the terminal it runs on (ownTTY); the
//     PTY is made by root.
//   - CAP_DAC_READ_SEARCH: as root but no longer exempt from file modes, it
//     still reads inside the agent's own folders, whose modes the base image
//     picks (a 0700 or 0750 HOME is common): the guard's lstat and inotify
//     watch of HOME and ~/.gemini (watchGuarded) and the project folder
//     check (projectDir). It reads only; it writes nothing as root.
//
// Everything else goes from the effective, permitted, inheritable, ambient
// and bounding sets of every thread: no DAC_OVERRIDE, FOWNER, NET_RAW,
// SYS_CHROOT, MKNOD, SETPCAP, SETFCAP, NET_BIND_SERVICE (the port is bound
// by then) or AUDIT_WRITE. CAP_CHOWN and CAP_DAC_READ_SEARCH are kept only
// when the relay has them; the first three are required (separate).
var relayCaps = []int{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL, unix.CAP_CHOWN, unix.CAP_DAC_READ_SEARCH}

// capMask is the 64-bit mask of caps.
func capMask(caps []int) uint64 {
	var m uint64
	for _, c := range caps {
		m |= 1 << uint(c)
	}
	return m
}

// confine drops every capability but relayCaps on every thread
// (GAP-0376). The bounding set needs CAP_SETPCAP: without it the bounding
// set stays (a warning; no_new_privs and the user switch keep the agent from
// it). Any other failure is an error.
func confine() (string, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return "", fmt.Errorf("the relay cannot read its capabilities: %w", err)
	}
	have := uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32
	keep := capMask(relayCaps) & have
	warn := ""
	if have&(1<<unix.CAP_SETPCAP) != 0 {
		for c := 0; c <= lastCap(); c++ {
			if keep&(1<<uint(c)) != 0 {
				continue
			}
			if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(c), 0); errno != 0 && errno != syscall.EINVAL {
				return "", fmt.Errorf("the relay could not drop capability %d from its bounding set: %v", c, errno)
			}
		}
	} else {
		warn = "the relay may not drop capabilities from its bounding set (CAP_SETPCAP is dropped); its own capabilities are dropped"
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); errno != 0 && errno != syscall.EINVAL {
		return "", fmt.Errorf("the relay could not clear its ambient capabilities: %v", errno)
	}
	set := [2]unix.CapUserData{
		{Effective: uint32(keep), Permitted: uint32(keep)},
		{Effective: uint32(keep >> 32), Permitted: uint32(keep >> 32)},
	}
	hdr = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&set[0])), 0); errno != 0 {
		return "", fmt.Errorf("the relay could not drop its capabilities on every thread: %v", errno)
	}
	return warn, nil
}

// lastCap is the highest capability the kernel knows.
func lastCap() int {
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < 64 {
			return n
		}
	}
	return unix.CAP_LAST_CAP
}

// hasCaps reports whether every capability is in the effective set.
func hasCaps(caps ...int) bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	for _, c := range caps {
		if data[c/32].Effective&(1<<(uint(c)%32)) == 0 {
			return false
		}
	}
	return true
}

// ownTTY gives the agent's user the terminal it runs on, as login does; a
// failure leaves the open descriptors working.
func ownTTY(f *os.File, cred *syscall.Credential) {
	if cred != nil {
		_ = f.Chown(int(cred.Uid), int(cred.Gid))
	}
}
