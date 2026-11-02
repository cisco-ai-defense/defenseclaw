//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// DarwinManagedInstallRoot is the managed macOS install root.
	DarwinManagedInstallRoot = "/opt/cisco/secureclient/defenseclaw"
	// DarwinManagedLogDir is the managed macOS log folder.
	DarwinManagedLogDir = "/Library/Logs/Cisco/SecureClient/DefenseClaw"

	darwinPrereqProbeTimeout = 10 * time.Second
	darwinLoopbackDialBound  = 2 * time.Second
)

// HostPrereqInput selects what the host prerequisite checks look at.
type HostPrereqInput struct {
	// InstallRoot is the managed install root; empty means the default.
	InstallRoot string
	// Ports are the gateway's loopback ports (API and guardrail). Zero or
	// negative entries are ignored.
	Ports []int
	// ExecProbe runs the gateway binary with --version. The installer sets it
	// before bootstrap; the guardian only checks the binary is still present.
	ExecProbe bool
}

// HostPrereqProbes is every host interaction the checks make, so tests can
// replace them.
type HostPrereqProbes struct {
	Lstat       func(string) (fs.FileInfo, error)
	Stat        func(string) (fs.FileInfo, error)
	Flags       func(string) (uint32, bool)
	Securelevel func() (int, bool)
	ReadDir     func(string) ([]fs.DirEntry, error)
	// RunVersion runs path with --version and returns its combined output.
	RunVersion func(ctx context.Context, path string) ([]byte, error)
	// PortHolder reports the process listening on 127.0.0.1:port, if any.
	PortHolder func(ctx context.Context, port int) (pid int, command string, held bool, err error)
	// DialLoopback opens and closes a TCP connection to 127.0.0.1:port.
	DialLoopback func(port int) error
	// RunCurl runs /usr/bin/curl --version.
	RunCurl func(ctx context.Context) error
	// CommandLineToolsPresent reports whether xcode-select finds the Command
	// Line Tools, which /usr/bin/python3 needs to be more than a stub.
	CommandLineToolsPresent func(ctx context.Context) bool
}

// DefaultHostPrereqProbes returns the probes that act on the real host.
func DefaultHostPrereqProbes() HostPrereqProbes {
	return HostPrereqProbes{
		Lstat: os.Lstat,
		Stat:  os.Stat,
		Flags: func(path string) (uint32, bool) {
			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return 0, false
			}
			return st.Flags, true
		},
		Securelevel: func() (int, bool) {
			level, err := unix.SysctlUint32("kern.securelevel")
			if err != nil {
				return 0, false
			}
			return int(int32(level)), true
		},
		ReadDir: os.ReadDir,
		RunVersion: func(ctx context.Context, path string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, path, "--version")
			cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
			cmd.Dir = "/"
			return cmd.CombinedOutput()
		},
		PortHolder:   darwinLoopbackPortHolder,
		DialLoopback: darwinDialLoopback,
		RunCurl: func(ctx context.Context) error {
			cmd := exec.CommandContext(ctx, "/usr/bin/curl", "--version")
			cmd.Env = []string{"LANG=C", "LC_ALL=C"}
			return cmd.Run()
		},
		CommandLineToolsPresent: func(ctx context.Context) bool {
			cmd := exec.CommandContext(ctx, "/usr/bin/xcode-select", "-p")
			cmd.Env = []string{"LANG=C", "LC_ALL=C"}
			output, err := cmd.Output()
			if err != nil {
				return false
			}
			dir := strings.TrimSpace(string(output))
			info, err := os.Stat(dir)
			return dir != "" && err == nil && info.IsDir()
		},
	}
}

// CheckHostPrerequisites runs the host prerequisite checks and returns every
// missing prerequisite. It never fails: a probe that cannot run is skipped.
func CheckHostPrerequisites(in HostPrereqInput, probes HostPrereqProbes) []PrereqFinding {
	root := strings.TrimSpace(in.InstallRoot)
	if root == "" {
		root = DarwinManagedInstallRoot
	}
	root = filepath.Clean(root)
	var findings []PrereqFinding
	findings = append(findings, checkBinaryExecAllowed(root, in.ExecProbe, probes)...)
	findings = append(findings, checkSystemImmutableFlags(root, probes)...)
	findings = append(findings, checkGatewayLoopbackPorts(in.Ports, probes)...)
	findings = append(findings, checkHookTransportTools(probes)...)
	return sortedFindings(findings)
}

func binaryExecFinding(path, detail string) PrereqFinding {
	return PrereqFinding{
		Check:  PrereqBinaryExecAllowed,
		Path:   path,
		Detail: detail,
		Remedy: fmt.Sprintf("Application control or EDR blocked execution of %s. Allow Cisco Team ID DE8Y96K9QP (signed builds) or this binary's CDHash in Santa, Jamf Protect or the EDR, then reinstall.", path),
	}
}

func checkBinaryExecAllowed(root string, execProbe bool, probes HostPrereqProbes) []PrereqFinding {
	path := filepath.Join(root, "bin", "defenseclaw-gateway")
	info, err := probes.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// launchd keeps failing to spawn a quarantined or deleted binary and
		// nothing running can restore it; only a reinstall can.
		return []PrereqFinding{binaryExecFinding(path, "binary missing (quarantined or deleted)")}
	case err != nil:
		return nil
	case !info.Mode().IsRegular():
		return []PrereqFinding{binaryExecFinding(path, "not a regular file")}
	case info.Mode().Perm()&0o111 == 0:
		return []PrereqFinding{binaryExecFinding(path, "not executable")}
	}
	if !execProbe || probes.RunVersion == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), darwinPrereqProbeTimeout)
	defer cancel()
	output, err := probes.RunVersion(ctx, path)
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return []PrereqFinding{binaryExecFinding(path, "did not finish --version within "+darwinPrereqProbeTimeout.String())}
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES):
		return []PrereqFinding{binaryExecFinding(path, "spawn refused: "+err.Error())}
	case errors.As(err, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return []PrereqFinding{binaryExecFinding(path, "killed by signal "+status.Signal().String())}
		}
		if len(bytes.TrimSpace(output)) == 0 {
			return []PrereqFinding{binaryExecFinding(path, fmt.Sprintf("exited %d with no output", exitErr.ExitCode()))}
		}
		return nil
	default:
		return []PrereqFinding{binaryExecFinding(path, "spawn failed: "+err.Error())}
	}
}

// darwinSystemBlockingFlagsMask is SF_IMMUTABLE | SF_APPEND.
const darwinSystemBlockingFlagsMask = 0x00020000 | 0x00040000

func checkSystemImmutableFlags(root string, probes HostPrereqProbes) []PrereqFinding {
	if probes.Securelevel == nil || probes.Flags == nil {
		return nil
	}
	level, ok := probes.Securelevel()
	if !ok || level <= 0 {
		// At securelevel 0 root clears schg and sappnd; the repairers do.
		return nil
	}
	paths := []string{root, DarwinManagedLogDir}
	if probes.ReadDir != nil {
		for _, dir := range []string{root, filepath.Join(root, "bin"), filepath.Join(root, "lib"), filepath.Join(root, "libexec"), filepath.Join(root, "etc")} {
			entries, err := probes.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				paths = append(paths, filepath.Join(dir, entry.Name()))
			}
		}
	}
	seen := map[string]struct{}{}
	var findings []PrereqFinding
	for _, path := range paths {
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		flags, ok := probes.Flags(path)
		if !ok || flags&darwinSystemBlockingFlagsMask == 0 {
			continue
		}
		findings = append(findings, PrereqFinding{
			Check:  PrereqSystemImmutableFlag,
			Path:   path,
			Detail: "securelevel " + strconv.Itoa(level),
			Remedy: fmt.Sprintf("%s carries the system-immutable flag and securelevel is %d. Reboot (securelevel returns to 0) and run `sudo chflags noschg,nosappnd %s`, or clear it from Recovery.", path, level, path),
		})
	}
	return findings
}

func loopbackFinding(port int, detail string) PrereqFinding {
	return PrereqFinding{
		Check:  PrereqGatewayLoopbackPort,
		Path:   "127.0.0.1:" + strconv.Itoa(port),
		Detail: detail,
		Remedy: fmt.Sprintf("TCP 127.0.0.1:%d is %s. Free the port, or allow loopback for DefenseClaw in pf, Little Snitch, LuLu or the network filter.", port, detail),
	}
}

// checkGatewayLoopbackPorts reports a port held by a process that is not
// DefenseClaw (a squatter would receive hook tokens and could answer
// "allow"), and a port DefenseClaw holds that loopback cannot reach (a
// filter). A free port is not a finding: the gateway may be restarting, and
// its own health covers that.
func checkGatewayLoopbackPorts(ports []int, probes HostPrereqProbes) []PrereqFinding {
	if probes.PortHolder == nil {
		return nil
	}
	var findings []PrereqFinding
	seen := map[int]struct{}{}
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), darwinPrereqProbeTimeout)
		pid, command, held, err := probes.PortHolder(ctx, port)
		cancel()
		if err != nil || !held {
			continue
		}
		if !defenseClawProcessName(command) {
			findings = append(findings, loopbackFinding(port, fmt.Sprintf("held by pid %d (%s)", pid, command)))
			continue
		}
		if probes.DialLoopback != nil {
			if err := probes.DialLoopback(port); err != nil {
				findings = append(findings, loopbackFinding(port, "unreachable over loopback"))
			}
		}
	}
	return findings
}

func defenseClawProcessName(command string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Base(strings.TrimSpace(command))), "defenseclaw")
}

// darwinLoopbackPortHolder asks lsof which process listens on the TCP port.
func darwinLoopbackPortHolder(ctx context.Context, port int) (int, string, bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpc")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(bytes.TrimSpace(output)) == 0 {
			// lsof exits 1 when nothing matches.
			return 0, "", false, nil
		}
		return 0, "", false, err
	}
	pid, command := parseLsofListener(output)
	return pid, command, pid > 0, nil
}

// parseLsofListener reads the first process from lsof -F p and c fields.
func parseLsofListener(output []byte) (int, string) {
	pid := 0
	command := ""
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			if pid != 0 {
				return pid, command
			}
			pid, _ = strconv.Atoi(line[1:])
		case 'c':
			if command == "" {
				command = line[1:]
			}
		}
	}
	return pid, command
}

func darwinDialLoopback(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), darwinLoopbackDialBound)
	if err != nil {
		return err
	}
	return conn.Close()
}

// hookPATHDirs is the PATH the hardened hook helper uses.
var hookPATHDirs = []string{"/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"}

func checkHookTransportTools(probes HostPrereqProbes) []PrereqFinding {
	if probes.Lstat == nil {
		return nil
	}
	remedy := "Allow /usr/bin/curl for user processes in the EDR policy, and install jq (macOS 15 and later ship /usr/bin/jq) or the Xcode Command Line Tools, so managed hooks can reach the gateway and read its structured responses."
	var findings []PrereqFinding
	curl := "/usr/bin/curl"
	if info, err := probes.Lstat(curl); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		findings = append(findings, PrereqFinding{Check: PrereqHookTransportTools, Path: curl, Detail: "curl is missing or not executable", Remedy: remedy})
	} else if probes.RunCurl != nil {
		ctx, cancel := context.WithTimeout(context.Background(), darwinPrereqProbeTimeout)
		err := probes.RunCurl(ctx)
		cancel()
		if err != nil {
			findings = append(findings, PrereqFinding{Check: PrereqHookTransportTools, Path: curl, Detail: "curl cannot run: " + err.Error(), Remedy: remedy})
		}
	}
	if !hookParserAvailable(probes) {
		findings = append(findings, PrereqFinding{
			Check:  PrereqHookTransportTools,
			Path:   "jq",
			Detail: "neither jq nor a usable python3 is on the hook PATH; Claude Code's structured responses cannot be read",
			Remedy: remedy,
		})
	}
	return findings
}

// executableOnHookPATH lists the executables named name on the hook PATH. A
// symlink (a Homebrew jq, for one) counts when its target is executable.
func executableOnHookPATH(name string, probes HostPrereqProbes) []string {
	if probes.Stat == nil {
		return nil
	}
	var found []string
	for _, dir := range hookPATHDirs {
		path := filepath.Join(dir, name)
		info, err := probes.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			found = append(found, path)
		}
	}
	return found
}

func hookParserAvailable(probes HostPrereqProbes) bool {
	if len(executableOnHookPATH("jq", probes)) > 0 {
		return true
	}
	for _, python := range executableOnHookPATH("python3", probes) {
		if !strings.HasPrefix(python, "/usr/bin/") {
			return true
		}
		// /usr/bin/python3 is a stub that opens an installer dialog unless
		// the Command Line Tools are installed.
		if probes.CommandLineToolsPresent != nil {
			ctx, cancel := context.WithTimeout(context.Background(), darwinPrereqProbeTimeout)
			present := probes.CommandLineToolsPresent(ctx)
			cancel()
			if present {
				return true
			}
		}
	}
	return false
}

// darwinTCCHomeFolders are the per-user folders TCC protects from a daemon
// without Full Disk Access.
var darwinTCCHomeFolders = []string{
	"Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures",
	"Library/Mail", "Library/Messages", "Library/Safari",
	"Library/Containers", "Library/Group Containers",
	"Library/Application Support/AddressBook", "Library/Calendars",
}

// TCCProtectedRoot returns the TCC-protected folder that contains path (for
// example /Users/u/Documents), or "" when path is not under one. Removable and
// network volumes under /Volumes count as protected roots too.
func TCCProtectedRoot(path string) string {
	clean := filepath.Clean(path)
	if rest, ok := strings.CutPrefix(clean, "/Volumes/"); ok {
		volume, _, _ := strings.Cut(rest, "/")
		if volume != "" {
			return "/Volumes/" + volume
		}
		return ""
	}
	rest, ok := strings.CutPrefix(clean, "/Users/")
	if !ok {
		return ""
	}
	user, tail, _ := strings.Cut(rest, "/")
	if user == "" || tail == "" {
		return ""
	}
	for _, folder := range darwinTCCHomeFolders {
		if tail == folder || strings.HasPrefix(tail, folder+"/") {
			return filepath.Join("/Users", user, folder)
		}
	}
	return ""
}

func tccFinding(root string) PrereqFinding {
	return PrereqFinding{
		Check:  PrereqTCCFullDiskAccess,
		Detail: "AI inventory cannot read a TCC-protected folder; enforcement is unaffected",
		Remedy: fmt.Sprintf("AI inventory can't read %s without Full Disk Access. Deploy a PPPC profile granting SystemPolicyAllFiles to defenseclaw-gateway (signed build: identifier plus Team ID DE8Y96K9QP), or accept partial inventory.", root),
	}
}

// ReportInventoryScanDenial handles a denied read under an AI inventory scan
// root. When the denial is TCC (EPERM from policy under a protected folder)
// it logs `defenseclaw_skip` once per protected root and the
// tcc_full_disk_access prerequisite once per process, and returns true; the
// caller skips the path as it already does. Any other error returns false.
func ReportInventoryScanDenial(path string, err error) bool {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return false
	}
	root := TCCProtectedRoot(path)
	if root == "" || ClassifyDenial(path, err) != DenialPolicy {
		return false
	}
	if _, seen := prereqOnce.LoadOrStore("tcc-skip\x00"+root, struct{}{}); !seen {
		EmitResilienceEvent(MarkerSkip, map[string]string{
			"unit":   "path:" + root,
			"path":   root,
			"reason": "tcc_protected",
		})
	}
	reportPrereqOnce(PrereqTCCFullDiskAccess+"\x00", tccFinding(root))
	return true
}

// ReportPolicyDenial classifies a failed file operation and, when an Endpoint
// Security client or TCC denied it, logs the matching prerequisite once per
// operation and path and returns true. Mode, ACL and flag denials (drift a
// re-stamp fixes), SIP and other errors return false.
func ReportPolicyDenial(op, path string, err error) bool {
	if ClassifyDenial(path, err) != DenialPolicy {
		return false
	}
	if root := TCCProtectedRoot(path); root != "" {
		return ReportInventoryScanDenial(path, err)
	}
	reportPrereqOnce(PrereqEndpointSecurityDenied+"\x00"+op+"\x00"+filepath.Clean(path), PrereqFinding{
		Check:  PrereqEndpointSecurityDenied,
		Path:   path,
		Detail: op + ": " + err.Error(),
		Remedy: fmt.Sprintf("An Endpoint Security client denied %s on %s. Add a DefenseClaw exclusion (Team ID or path) to the EDR policy.", op, path),
	})
	return true
}

// sortedFindings orders findings for stable output.
func sortedFindings(findings []PrereqFinding) []PrereqFinding {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Check != findings[j].Check {
			return findings[i].Check < findings[j].Check
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}
