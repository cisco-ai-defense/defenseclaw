// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"fmt"
	"os"
	"syscall"

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
//   - the relay is root and may change user: separated.
//   - the relay is root but may not change user (no CAP_SETUID or
//     CAP_SETGID): an error. The agent is never run as root.
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
	exe, err := os.Executable()
	if err != nil {
		return nil, "", fmt.Errorf("the relay cannot find its own binary to copy files as the agent's user: %w", err)
	}
	// No process the relay starts may gain privileges through a set-user-ID
	// program (sudo, su) and come back for the relay as root. The flag is
	// per thread, so every thread gets it; a build with cgo cannot set it
	// on all threads, which leaves only that path open (a warning).
	warn := ""
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno != 0 {
		warn = fmt.Sprintf("the relay could not set no_new_privs (%v): a set-user-ID program in the image could give the agent root back", errno)
	}
	return &separation{cred: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}, exe: exe}, warn, nil
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
