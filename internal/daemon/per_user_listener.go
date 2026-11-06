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

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
		return "Stop it from an administrator prompt (defenseclaw-gateway stop), then start it as yourself (defenseclaw-gateway start)"
	case "darwin":
		return "Open DefenseClawMac and choose Start Gateway: it stops the root gateway with administrator approval, " +
			"returns its files to you and starts the gateway as you. Without the app, run: " + rootGatewayRecoveryCommand(dataDir)
	}
	return "Stop it, return its files to your account and start it as yourself with: " + rootGatewayRecoveryCommand(dataDir)
}

// rootGatewayRecoveryCommand stops the root gateway, returns the install home
// and the moved store to the calling account and starts the gateway as that
// account. The root run leaves root-owned files in both (GAP-0711, GAP-0713).
func rootGatewayRecoveryCommand(dataDir string) string {
	dirs := rootGatewayRecoveryDirs(dataDir)
	for i, dir := range dirs {
		dirs[i] = shellQuote(dir)
	}
	return rootGatewayStopCommand(dataDir) + " && sudo chown -R \"$(id -un)\" " + strings.Join(dirs, " ") +
		" && defenseclaw-gateway start"
}

// rootGatewayRecoveryDirs are the directories a root-run gateway for the
// install home writes to: the home that holds the PID record, and the store
// that home's config moved the data to (defenseclaw config set data_dir). A
// chown of the home alone leaves the store's connector state root-owned, so
// the account start fails on it.
func rootGatewayRecoveryDirs(installHome string) []string {
	home := absoluteDataDir(installHome)
	dirs := []string{home}
	if store := movedStoreOfHome(home); store != "" && store != home {
		dirs = append(dirs, store)
	}
	return dirs
}

// movedStoreOfHome reads data_dir from the config the gateway reads for the
// install home: DEFENSECLAW_CONFIG when set, else home/config.yaml. It
// returns "" when there is none, it cannot be read or it names no directory.
// A relative data_dir is taken relative to the config file, as the gateway does.
func movedStoreOfHome(home string) string {
	configFile := os.Getenv(managed.ConfigPathEnv)
	if configFile == "" {
		configFile = filepath.Join(home, "config.yaml")
	}
	if !filepath.IsAbs(configFile) {
		return ""
	}
	raw, err := safefile.ReadRegularFileBounded(configFile, maxRemedyConfigBytes)
	if err != nil {
		return ""
	}
	var source struct {
		DataDir string `yaml:"data_dir"`
	}
	if yaml.Unmarshal(raw, &source) != nil {
		return ""
	}
	store := strings.TrimSpace(source.DataDir)
	if store == "" {
		return ""
	}
	if !filepath.IsAbs(store) {
		store = filepath.Join(filepath.Dir(configFile), store)
	}
	return filepath.Clean(store)
}

// maxRemedyConfigBytes bounds the config read for a remedy. A larger file
// names no store here; the remedy then covers the install home only.
const maxRemedyConfigBytes = 4 << 20

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
