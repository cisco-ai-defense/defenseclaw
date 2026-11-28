// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"errors"
	"fmt"
	"os"
	"runtime"
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
	if !hasCaps(unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL) {
		return nil, "", fmt.Errorf("the relay runs as root but lacks CAP_SETUID, CAP_SETGID or CAP_KILL, so it can neither start the agent as %s nor stop it; it never runs the agent as root. The template's container must add SETUID and SETGID (security_context.capabilities; defenseclaw substrate template publish sets it)", rc.AgentUser)
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

// relayCaps are the only capabilities a separated relay keeps (GAP-0376,
// GAP-0458), each for code that needs it; kit.RelayCapabilities, the set
// its template asks Substrate for:
//   - CAP_SETUID, CAP_SETGID: every process it starts (agent PTY, headless
//     task, exec, the files-put, files-get and state-dir children) is
//     switched to relay.agent_user (asAgent: setgroups, setgid, setuid), and
//     the relay takes the agent's file-system identity to open the agent's
//     terminal (devpts gives it to the opener) and to read the agent's
//     /proc/<pid>/io (withFSCred).
//   - CAP_KILL: it signals the agent's processes, another user's: the
//     agent's process group (killProcessGroup), the task tree on a stall
//     (procTree.signal) and every process of the actor on a guard trip
//     (stopActorProcesses).
//
// Everything else goes from the effective, permitted, inheritable and
// ambient sets of every thread, and from the bounding set when the relay may
// change it: CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, NET_RAW,
// NET_BIND_SERVICE (the port is bound by then), AUDIT_WRITE and the rest. A
// kit actor on Substrate has only these three (kit.RelayCapabilitiesAdd and
// Drop).
var relayCaps = []int{unix.CAP_SETUID, unix.CAP_SETGID, unix.CAP_KILL}

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
	} else if bnd, err := boundingSet(); err == nil && bnd&^keep != 0 {
		warn = fmt.Sprintf("the relay may not drop capabilities from its bounding set (CAP_SETPCAP is dropped; bounding set %#x); its own capabilities are dropped", bnd)
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

// boundingSet reads the process's bounding set (CapBnd).
func boundingSet() (uint64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapBnd:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		}
	}
	return 0, fmt.Errorf("no CapBnd line")
}

// withAgentFS runs fn with the agent's file-system identity (the relay's own
// when it is not separated); false when it could not be taken.
func (sp *separation) withAgentFS(fn func()) bool {
	if sp == nil {
		fn()
		return true
	}
	return withFSCred(sp.cred, fn)
}

// withFSCred runs fn on a locked thread whose file-system uid and gid are
// cred's (setfsuid needs CAP_SETUID), and puts them back. If they cannot be
// put back the thread stays locked and ends with the goroutine, so no other
// goroutine runs with them. ok is false when the identity could not be
// taken (fn did not run).
func withFSCred(cred *syscall.Credential, fn func()) (ok bool) {
	if cred == nil {
		fn()
		return true
	}
	runtime.LockOSThread()
	pg, _ := unix.SetfsgidRetGid(int(cred.Gid))
	pu, _ := unix.SetfsuidRetUid(int(cred.Uid))
	cu, _ := unix.SetfsuidRetUid(-1)
	cg, _ := unix.SetfsgidRetGid(-1)
	if cu == int(cred.Uid) && cg == int(cred.Gid) {
		fn()
		ok = true
	}
	_, _ = unix.SetfsuidRetUid(pu)
	_, _ = unix.SetfsgidRetGid(pg)
	if u, _ := unix.SetfsuidRetUid(-1); u != pu {
		return ok
	}
	if g, _ := unix.SetfsgidRetGid(-1); g != pg {
		return ok
	}
	runtime.UnlockOSThread()
	return ok
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

// openPTY opens a new pseudo-terminal and returns its master and slave
// sides, both unlocked and open. For a separated relay both are opened with
// the agent's file-system identity (GAP-0458): devpts makes the new
// terminal the opener's, so the agent owns the terminal it runs on, as
// after a login, without CAP_CHOWN; and the relay, which keeps no
// DAC_OVERRIDE, could not open the agent's 0620 terminal as itself.
func openPTY(cred *syscall.Credential) (master, slave *os.File, err error) {
	open := func() {
		master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
		if err != nil {
			err = fmt.Errorf("open pty: %w", err)
			return
		}
		fd := int(master.Fd())
		if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			master.Close()
			err = fmt.Errorf("unlock pty: %w", err)
			return
		}
		n, gerr := unix.IoctlGetInt(fd, unix.TIOCGPTN)
		if gerr != nil {
			master.Close()
			err = fmt.Errorf("pty number: %w", gerr)
			return
		}
		slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			master.Close()
			err = fmt.Errorf("open pty slave: %w", err)
		}
	}
	if !withFSCred(cred, open) {
		return nil, nil, errors.New("open pty: cannot take the agent's file-system identity")
	}
	return master, slave, err
}
