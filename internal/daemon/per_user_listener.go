// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// PerUserListenerClass describes a listener for display. It never authorizes
// a token-bearing request or process control.
type PerUserListenerClass uint8

const (
	PerUserListenerUnknown PerUserListenerClass = iota
	PerUserListenerOwnGateway
	PerUserListenerOwnGatewayRunAsRoot
	PerUserListenerForeign
	// This home's PID record names a live process of this account, but listener
	// ownership is unavailable. The connected-peer check decides before use.
	PerUserListenerUnlistedOwnProcess
)

const RootGatewayListenerReason = "Your DefenseClaw gateway is running as root."

// RootGatewayListenerRemedy is the next step for a root-run gateway on this
// account's home, in the words of the running OS (GAP-0706). It names the
// PID-record home and executable before sudo resets the caller's environment.
// It carries no final period: callers end the sentence themselves.
func RootGatewayListenerRemedy(dataDir string) string {
	return rootGatewayRemedyFor(runtime.GOOS, dataDir)
}

// rootGatewayRemedyFor is the one table of root-gateway remedies. A root run
// leaves root-owned files in the home, so an account start fails until they
// are returned: the Unix remedy is one sequence that stops the root gateway,
// returns the home and starts it as the account (GAP-0711, GAP-0713).
// DefenseClawMac exists only on macOS.
func rootGatewayRemedyFor(goos, dataDir string) string {
	switch goos {
	case "windows":
		return windowsRootGatewayRemedy(rootGatewayWindowsExecutable())
	case "darwin":
		return "Open DefenseClawMac and choose Start Gateway: it stops the root gateway with administrator approval, " +
			"returns its files to you and starts the gateway as you. Without the app, run: " + rootGatewayRecoveryCommand(dataDir)
	}
	return "Stop it, return its files to your account and start it as yourself with: " + rootGatewayRecoveryCommand(dataDir)
}

// windowsRootGatewayRemedy names the elevated stop and the account start of
// the gateway at executable. Both commands are rendered by
// managed.WindowsCommandLine, the one place a PowerShell command line is
// built (TestManagedWindowsCommandsComeFromTheRenderer). The call-operator
// form runs only in PowerShell, so the text names PowerShell for both steps
// (a Command Prompt cannot run it); a bare command would not run as typed and a
// path with a space or an apostrophe would break it.
func windowsRootGatewayRemedy(executable string) string {
	return "Stop it from an elevated PowerShell prompt (" + managed.WindowsCommandLine(executable, "stop") +
		"), then start it as yourself from a normal PowerShell prompt (" + managed.WindowsCommandLine(executable, "start") + ")"
}

// rootGatewayWindowsExecutable is the gateway of this account: the running
// binary when it is the gateway, else the one on PATH. With neither it is the
// bare file name, which a per-user install has on PATH.
func rootGatewayWindowsExecutable() string {
	const name = "defenseclaw-gateway.exe"
	if self, err := os.Executable(); err == nil && strings.EqualFold(filepath.Base(self), name) {
		return self
	}
	if found, err := exec.LookPath(name); err == nil && filepath.IsAbs(found) {
		return found
	}
	return name
}

// rootGatewayRecoveryCommand stops the root gateway, returns the home to the
// calling account and starts the gateway as that account.
func rootGatewayRecoveryCommand(dataDir string) string {
	return rootGatewayStopCommand(dataDir) + " && sudo chown -R \"$(id -un)\" " + shellQuote(absoluteDataDir(dataDir)) +
		" && defenseclaw-gateway start"
}

func rootGatewayStopCommand(dataDir string) string {
	executable := "\"$(command -v defenseclaw-gateway)\""
	if path := rootGatewayExecutablePath(); path != "" {
		executable = shellQuote(path)
	}
	return "sudo env DEFENSECLAW_HOME=" + shellQuote(absoluteDataDir(dataDir)) + " " + executable + " stop"
}

func absoluteDataDir(dataDir string) string {
	if absolute, err := filepath.Abs(dataDir); err == nil {
		return absolute
	}
	return dataDir
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func rootGatewayExecutablePath() string {
	// A gateway handling its own stop error can use the binary it is running.
	// Other callers resolve the account's executable before sudo changes PATH.
	if self, err := os.Executable(); err == nil && filepath.Base(self) == "defenseclaw-gateway" && runnableGatewayFile(self) {
		return self
	}
	if found, err := exec.LookPath("defenseclaw-gateway"); err == nil && runnableGatewayFile(found) {
		return found
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".local", "bin", "defenseclaw-gateway")
		if runnableGatewayFile(candidate) {
			return candidate
		}
	}
	return ""
}

func runnableGatewayFile(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0
}

// ClassifyPerUserListener combines the observed endpoint owner with the PID
// record for this home. The result is diagnostic only:
// every per-user transport still verifies the connected peer separately.
func ClassifyPerUserListener(host string, port int, dataDir string, holder PortHolder, holderErr error, answers bool) PerUserListenerClass {
	if runtime.GOOS == "windows" {
		return PerUserListenerUnknown
	}
	wanted := net.ParseIP(strings.Trim(host, "[]"))
	if port < 1 || port > 65535 || wanted == nil || !wanted.IsLoopback() {
		return PerUserListenerUnknown
	}
	if holderErr != nil && !answers {
		return PerUserListenerUnknown
	}
	ownUID := os.Getuid()
	d := New(dataDir)
	if holderErr == nil && holder.UID == ownUID {
		if holder.PID > 0 && d.HasManagedProcessIdentity(holder.PID) {
			return PerUserListenerOwnGateway
		}
		return PerUserListenerUnknown
	}
	if holderErr != nil || (ownUID != 0 && holder.UID == 0) {
		info, err := d.readPIDInfo()
		if err == nil && info.PID > 0 && d.recordBindsThisHome(info) &&
			d.HasManagedProcessIdentity(info.PID) {
			uid, uidErr := gatewayProcessUID(info.PID)
			if uidErr == nil && (holder.PID == 0 || holder.PID == info.PID) {
				if ownUID != 0 && uid == 0 {
					return PerUserListenerOwnGatewayRunAsRoot
				}
				if holderErr != nil && uid == ownUID {
					return PerUserListenerUnlistedOwnProcess
				}
			}
		}
	}
	if holderErr != nil {
		// A gateway left running during an upgrade can have an older PID record.
		// It can reach the connected-peer verifier when it still runs as this
		// account; the record alone never authorizes the answering socket.
		if running, pid := d.IsRunning(); running && pid > 0 {
			if uid, err := gatewayProcessUID(pid); err == nil && uid == ownUID {
				return PerUserListenerUnlistedOwnProcess
			}
		}
	}
	return PerUserListenerForeign
}
