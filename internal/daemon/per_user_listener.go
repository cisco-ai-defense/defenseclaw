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

// RootGatewayListenerRemedy names the PID-record home and executable before
// sudo resets the caller's environment.
func RootGatewayListenerRemedy(dataDir string) string {
	return "Stop it with " + rootGatewayStopCommand(dataDir) + ", then start it as yourself (defenseclaw-gateway start). On macOS, use DefenseClawMac to repair root-owned gateway files."
}

func rootGatewayStopCommand(dataDir string) string {
	if absolute, err := filepath.Abs(dataDir); err == nil {
		dataDir = absolute
	}
	quotedHome := "'" + strings.ReplaceAll(dataDir, "'", "'\\''") + "'"
	executable := "\"$(command -v defenseclaw-gateway)\""
	if path := rootGatewayExecutablePath(); path != "" {
		executable = "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
	}
	return "sudo env DEFENSECLAW_HOME=" + quotedHome + " " + executable + " stop"
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
