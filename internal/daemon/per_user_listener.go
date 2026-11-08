// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

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
// DefenseClawMac exists only on macOS. The shell command is always the last
// thing in the text and holds nothing but the command, so it can be copied
// whole; a note about it comes before it.
func rootGatewayRemedyFor(goos, dataDir string) string {
	if goos == "windows" {
		return windowsRootGatewayRemedy(rootGatewayWindowsExecutable())
	}
	command, note := rootGatewayRecoverySteps(dataDir)
	if goos == "darwin" {
		return note + "Open DefenseClawMac and choose Start Gateway: it stops the root gateway with administrator approval, " +
			"returns its files to you and starts the gateway as you. Without the app, run: " + command
	}
	return note + "Stop it, return its files to your account and start it as yourself with: " + command
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

// rootGatewayRecoverySteps returns the shell command that stops the root
// gateway, returns the install home and the moved store to the calling account
// and starts the gateway as that account (the root run leaves root-owned files
// in both, GAP-0711, GAP-0713), and the sentence to read before it. When the
// home's configuration exists but cannot say where the store is, the command
// names the install home only and the note says so, so the sequence is never
// presented as complete. The note is empty otherwise.
func rootGatewayRecoverySteps(dataDir string) (command, note string) {
	return rootGatewayRecoveryStepsLoosening(dataDir, nil)
}

// rootGatewayRecoveryStepsLoosening is rootGatewayRecoverySteps with a chmod
// between the return and the start for the root-owned files that also grant
// group or others access (GAP-0788): the gateway refuses such a file after the
// owner is returned. The owner change alone does not make a file usable: a
// root-owned file whose owner bits lack read or write (mode 000, 044) or a
// folder without owner access stays unusable to its new owner, so the chain
// restores the owner bits on the returned folders (chmod -R u+rwX, group and
// other bits untouched) before the loosening step and the start.
func rootGatewayRecoveryStepsLoosening(dataDir string, loosen []string) (command, note string) {
	dirs, configFile, storeErr := rootGatewayRecoveryDirs(dataDir)
	agentConfigs := rootOwnedAgentConfigPaths(dirs[len(dirs)-1])
	for i, dir := range dirs {
		dirs[i] = shellQuote(dir)
	}
	owned := strings.Join(dirs, " ")
	command = rootGatewayStopCommand(dataDir) + " && sudo chown -R \"$(id -un)\" " + owned +
		" && chmod -R u+rwX " + owned
	if len(agentConfigs) > 0 {
		// The agent config files and folders in the account home that a root run
		// wrote (GAP-0848): the owner return above does not reach them.
		command += " && " + rootOwnedAgentConfigStep(agentConfigs)
	}
	if step := rootGatewayLoosenStep(loosen); step != "" {
		command += " && " + step
	}
	command += " && defenseclaw-gateway start"
	if storeErr != nil {
		note = "The configuration " + configFile + " could not be read here, so a data_dir it sets is " +
			"not in the chown command below: return that folder to your account too. "
	}
	return command, note
}

// rootOwnedAgentConfigsOf lists the agent config files and folders in the
// account home that root owns. The connector package imports this one, so it
// registers the scan (RegisterRootOwnedAgentConfigPaths) instead of being
// imported here.
var rootOwnedAgentConfigsOf func(dataDir string) []string

// RegisterRootOwnedAgentConfigPaths sets the scan the recovery chain uses to
// name the root-owned agent config paths (connector.RootOwnedAgentConfigPaths).
func RegisterRootOwnedAgentConfigPaths(scan func(dataDir string) []string) {
	rootOwnedAgentConfigsOf = scan
}

func rootOwnedAgentConfigPaths(dataDir string) []string {
	if rootOwnedAgentConfigsOf == nil {
		return nil
	}
	return rootOwnedAgentConfigsOf(dataDir)
}

// rootOwnedAgentConfigReturnScript is the body of the sh -c step that returns
// those paths to the account, one argument each. The scan above ran earlier and
// the account can change its own folders at any moment, so each path is bound
// to the folder that holds it before sudo runs: the step enters that folder
// (cd -P), proves with the external pwd -P (a getcwd of the folder it is in,
// not a lookup of the name) that the folder is the physical in-home one, and
// runs sudo find on the bare name inside it. sudo keeps the working directory,
// so replacing the folder or its parent with a link after the check changes
// nothing about the folder the find walks. Only a root-owned folder, or a
// root-owned file with a single hard link, is changed: find does not follow a
// link at the path itself, -execdir runs the change inside the folder find is
// walking, chown -h changes a link rather than its target, and -xdev keeps the
// walk of a returned folder on its own volume. A path that fails the check is
// skipped with a message; a failed sudo ends the chain.
const rootOwnedAgentConfigReturnScript = `for p; do d=${p%/*}; b=${p##*/}; ` +
	`(cd -P "$d" 2>/dev/null && [ "$(/bin/pwd -P)" = "$d" ] || { echo "skipped $p: its folder is a link or moved" >&2; exit 0; }; ` +
	`[ -e "$b" ] || exit 0; ` +
	`sudo find -P "./$b" -xdev -user root \( -type d -o -type f -links 1 \) ` +
	`-execdir chown -h "$(id -un)" {} \; -execdir chmod u+rwX {} \;) || exit 1; done`

// rootOwnedAgentConfigStep is the chain step that returns the paths.
func rootOwnedAgentConfigStep(paths []string) string {
	quoted := make([]string, len(paths))
	for i, path := range paths {
		quoted[i] = shellQuote(path)
	}
	return "sh -c \x27" + rootOwnedAgentConfigReturnScript + "\x27 sh " + strings.Join(quoted, " ")
}

// rootGatewayLoosenStep takes group and other access away from the root-owned
// files the owner return leaves loose. A path that ends in a separator is a
// folder whose files could not be seen: a find over it takes the access away
// from the runtime files it holds, so a hidden store is repaired too.
func rootGatewayLoosenStep(loosen []string) string {
	var files, folders []string
	for _, path := range loosen {
		if strings.HasSuffix(path, string(filepath.Separator)) {
			folders = append(folders, shellQuote(path))
		} else {
			files = append(files, shellQuote(path))
		}
	}
	var steps []string
	if len(files) > 0 {
		steps = append(steps, "chmod go-rwx "+strings.Join(files, " "))
	}
	if len(folders) > 0 {
		var tests []string
		for _, name := range rootRuntimeLeftoverNames {
			tests = append(tests, "-name "+name)
		}
		tests = append(tests, "-path '*/hooks/.hook-*.token'")
		steps = append(steps, "find "+strings.Join(folders, " ")+" -maxdepth 2 -type f \\( "+
			strings.Join(tests, " -o ")+" \\) -exec chmod go-rwx {} +")
	}
	return strings.Join(steps, " && ")
}

// rootGatewayRecoveryDirs are the directories a root-run gateway for the
// install home writes to: the home that holds the PID record, and the store
// that home's config moved the data to (defenseclaw config set data_dir). A
// chown of the home alone leaves the store's connector state root-owned, so
// the account start fails on it. configFile and a non-nil err report a
// configuration that exists but names no readable store.
func rootGatewayRecoveryDirs(installHome string) (dirs []string, configFile string, err error) {
	home := absoluteDataDir(installHome)
	dirs = []string{home}
	store, configFile, err := movedStoreOfHome(home)
	if store != "" && store != home {
		dirs = append(dirs, store)
	}
	return dirs, configFile, err
}

// movedStoreOfHome resolves the store the way the gateway does. The gateway
// is started with the install home as its working directory, so a relative
// DEFENSECLAW_CONFIG and a relative data_dir are both taken from there (the
// loader makes a config path absolute and the compiler a data_dir, each from
// the working directory). The config is opened as the loader opens it, so a
// link to it is followed. It returns "" and no error when there is no config
// or it sets no data_dir, and an error when the config exists but cannot be
// read or parsed, so the caller can say the recovery is incomplete.
func movedStoreOfHome(home string) (store, configFile string, err error) {
	configFile = os.Getenv(managed.ConfigPathEnv)
	if configFile == "" {
		configFile = filepath.Join(home, "config.yaml")
	}
	if !filepath.IsAbs(configFile) {
		configFile = filepath.Join(home, configFile)
	}
	configFile = filepath.Clean(configFile)
	raw, err := readRemedyConfig(configFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", configFile, nil
	}
	if err != nil {
		return "", configFile, err
	}
	var source struct {
		DataDir string `yaml:"data_dir"`
	}
	if err := yaml.Unmarshal(raw, &source); err != nil {
		return "", configFile, err
	}
	store = strings.TrimSpace(source.DataDir)
	if store == "" {
		return "", configFile, nil
	}
	if !filepath.IsAbs(store) {
		store = filepath.Join(home, store)
	}
	return filepath.Clean(store), configFile, nil
}

// readRemedyConfig reads at most maxRemedyConfigBytes of the file the way the
// gateway's config loader opens it (a link is followed) and requires a
// regular file.
func readRemedyConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxRemedyConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRemedyConfigBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxRemedyConfigBytes)
	}
	return raw, nil
}

// maxRemedyConfigBytes bounds the config read for a remedy.
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
