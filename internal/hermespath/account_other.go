// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermespath

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// accountHomeDir is the account's ~/.hermes. VerifyAccountHome proves that
// nothing the account's processes start with names another home.
func accountHomeDir(userHome string) (string, error) {
	return ResolveHomeDir(runtime.GOOS, "", "", userHome), nil
}

// Where the host-wide evidence is read from; tests replace them
// (OverrideAccountEnvironmentForTest).
var (
	accountSystemRoot        = "/"
	accountLaunchdHermesHome = launchdHermesHome
	accountProcessEvidence   = runningProcessEvidence
)

// OverrideAccountEnvironmentForTest reads the host-wide environment files and
// the running processes under root instead of / (<root>/proc, on macOS
// too), and the launchd environment as empty, for tests that must not see
// the host's. It returns the function that restores them.
func OverrideAccountEnvironmentForTest(root string) (restore func()) {
	previousRoot, previousLaunchd, previousProcesses := accountSystemRoot, accountLaunchdHermesHome, accountProcessEvidence
	accountSystemRoot = root
	accountLaunchdHermesHome = func(int) (string, error) { return "", nil }
	accountProcessEvidence = procProcessEvidence
	return func() {
		accountSystemRoot, accountLaunchdHermesHome, accountProcessEvidence = previousRoot, previousLaunchd, previousProcesses
	}
}

const (
	// accountEvidenceFileLimit bounds one environment or startup file read.
	accountEvidenceFileLimit = 1 << 20
	// accountProcessEnvironLimit bounds one process environment read.
	accountProcessEnvironLimit = 1 << 20
)

// accountEnvironmentEvidence returns what sets HERMES_HOME for the
// account's processes on Linux and macOS:
//
//   - KEY=VALUE environment files the sign-in reads: ~/.config/environment.d,
//     /etc/environment.d and /etc/environment (systemd, pam_env), and the
//     pam_env files ~/.pam_environment and /etc/security/pam_env.conf;
//   - shell startup files, which only the shell can evaluate, so any line
//     naming HERMES_HOME is a value that cannot be resolved;
//   - on macOS the account's launchd environment (launchctl setenv);
//   - the environment of every running process of the account (Linux
//     /proc, macOS kern.procargs2), which shows what a file a startup file
//     sources, a terminal profile or an IDE set.
func accountEnvironmentEvidence(userHome string) ([]homeEvidence, error) {
	info, err := os.Stat(userHome)
	if err != nil {
		return nil, fmt.Errorf("inspect the account home: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("the owner of the account home cannot be read")
	}
	uid := int(stat.Uid)
	system := func(path string) string { return filepath.Join(accountSystemRoot, filepath.FromSlash(path)) }

	var out []homeEvidence
	add := func(found []homeEvidence, err error) error {
		out = append(out, found...)
		return err
	}
	for _, dir := range []string{filepath.Join(userHome, ".config", "environment.d"), system("etc/environment.d")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		for _, file := range files {
			if err := add(environmentFileEvidence(file, userHome, false)); err != nil {
				return nil, err
			}
		}
	}
	for _, file := range []string{system("etc/environment")} {
		if err := add(environmentFileEvidence(file, userHome, false)); err != nil {
			return nil, err
		}
	}
	for _, file := range []string{filepath.Join(userHome, ".pam_environment"), system("etc/security/pam_env.conf")} {
		if err := add(environmentFileEvidence(file, userHome, true)); err != nil {
			return nil, err
		}
	}
	startup := []string{
		filepath.Join(userHome, ".profile"), filepath.Join(userHome, ".bash_profile"),
		filepath.Join(userHome, ".bash_login"), filepath.Join(userHome, ".bashrc"),
		filepath.Join(userHome, ".zshenv"), filepath.Join(userHome, ".zprofile"),
		filepath.Join(userHome, ".zshrc"), filepath.Join(userHome, ".zlogin"),
		filepath.Join(userHome, ".config", "fish", "config.fish"),
		system("etc/profile"), system("etc/bashrc"), system("etc/bash.bashrc"),
		system("etc/zshenv"), system("etc/zprofile"), system("etc/zshrc"),
		system("etc/zsh/zshenv"), system("etc/zsh/zprofile"), system("etc/zsh/zshrc"),
	}
	for _, dir := range []string{system("etc/profile.d"), filepath.Join(userHome, ".config", "fish", "conf.d")} {
		files, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		startup = append(startup, files...)
	}
	for _, file := range startup {
		if err := add(startupFileEvidence(file)); err != nil {
			return nil, err
		}
	}
	if runtime.GOOS == "darwin" {
		value, err := accountLaunchdHermesHome(uid)
		if err != nil {
			return nil, fmt.Errorf("read the launchd environment of uid %d: %w", uid, err)
		}
		if strings.TrimSpace(value) != "" {
			out = append(out, homeEvidence{source: "the launchd environment of uid " + strconv.Itoa(uid), home: absoluteHome(value)})
		}
	}
	if err := add(accountProcessEvidence(uid)); err != nil {
		return nil, err
	}
	return out, nil
}

// readEvidenceFile reads a bounded regular file; a missing one is nil.
func readEvidenceFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, nil
	}
	if !info.Mode().IsRegular() || info.Size() > accountEvidenceFileLimit {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// environmentFileEvidence reads the HERMES_HOME assignments of a KEY=VALUE
// environment file, or of a pam_env file (`HERMES_HOME DEFAULT=v
// OVERRIDE=v` or KEY=VALUE).
func environmentFileEvidence(path, userHome string, pam bool) ([]homeEvidence, error) {
	data, err := readEvidenceFile(path)
	if err != nil || data == nil {
		return nil, err
	}
	var out []homeEvidence
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), accountEvidenceFileLimit)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !hermesHomeName.MatchString(line) {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		var values []string
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) == "HERMES_HOME" {
			values = append(values, value)
		} else if fields := strings.Fields(line); pam && len(fields) > 1 && fields[0] == "HERMES_HOME" {
			for _, field := range fields[1:] {
				if option, value, ok := strings.Cut(field, "="); ok && (option == "DEFAULT" || option == "OVERRIDE") {
					values = append(values, value)
				} else {
					values = append(values, "")
				}
			}
		} else {
			// A line that names HERMES_HOME some other way is not one a
			// service can evaluate.
			values = append(values, "")
		}
		for _, value := range values {
			out = append(out, homeEvidence{source: path, home: expandAccountHome(value, userHome)})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

// expandAccountHome resolves an environment file value: quotes are
// removed and the account's home stands for $HOME, ${HOME}, @{HOME} and a
// leading ~. Any other reference cannot be resolved ("").
func expandAccountHome(value, userHome string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	for _, reference := range []string{"${HOME}", "@{HOME}", "$HOME"} {
		value = strings.ReplaceAll(value, reference, userHome)
	}
	if value == "~" || strings.HasPrefix(value, "~/") {
		value = userHome + value[1:]
	}
	if strings.ContainsAny(value, "$@`~") {
		return ""
	}
	return absoluteHome(value)
}

// hermesHomeName matches the variable name HERMES_HOME, not a longer name.
var hermesHomeName = regexp.MustCompile(`(^|[^A-Za-z0-9_])HERMES_HOME($|[^A-Za-z0-9_])`)

// startupFileEvidence reports a shell startup file that names HERMES_HOME
// outside a comment: only the shell can tell what it sets.
func startupFileEvidence(path string) ([]homeEvidence, error) {
	data, err := readEvidenceFile(path)
	if err != nil || data == nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && hermesHomeName.MatchString(line) {
			return []homeEvidence{{source: path}}, nil
		}
	}
	return nil, nil
}

// procProcessEvidence reads HERMES_HOME from the environment of every
// running process of uid (Linux /proc). A process that exits or cannot be
// read is skipped; a caller that is neither root nor uid can read none,
// which fails.
func procProcessEvidence(uid int) ([]homeEvidence, error) {
	if err := canReadProcessesOf(uid); err != nil {
		return nil, err
	}
	proc := filepath.Join(accountSystemRoot, "proc")
	entries, err := os.ReadDir(proc)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", proc, err)
	}
	var out []homeEvidence
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		dir := filepath.Join(proc, entry.Name())
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != uid {
			continue
		}
		source := func() string {
			name, _ := readProcessFile(filepath.Join(dir, "comm"), 256)
			return fmt.Sprintf("running process %s (%s)", entry.Name(), strings.TrimSpace(string(name)))
		}
		environ, err := readProcessFile(filepath.Join(dir, "environ"), accountProcessEnvironLimit)
		if errors.Is(err, errProcessFileTooLarge) {
			// An environment too large to read can set any home.
			out = append(out, homeEvidence{source: source()})
			continue
		}
		if err != nil {
			continue
		}
		out = append(out, environEvidence(bytes.Split(environ, []byte{0}), source)...)
	}
	return out, nil
}

// canReadProcessesOf fails unless the caller is root or uid: another
// account's process environments cannot be read.
func canReadProcessesOf(uid int) error {
	if euid := os.Geteuid(); euid != 0 && euid != uid {
		return fmt.Errorf("the environment of the processes of uid %d cannot be read without root", uid)
	}
	return nil
}

// environEvidence returns the HERMES_HOME values of a process environment;
// source names the process.
func environEvidence(environ [][]byte, source func() string) []homeEvidence {
	var out []homeEvidence
	for _, variable := range environ {
		value, ok := bytes.CutPrefix(variable, []byte("HERMES_HOME="))
		if !ok || len(bytes.TrimSpace(value)) == 0 {
			continue
		}
		out = append(out, homeEvidence{source: source(), home: absoluteHome(string(value))})
	}
	return out
}

// procargs2Environment returns the environment in a macOS kern.procargs2
// buffer: argc as a 32-bit integer, the executable path, NUL padding, argc
// arguments and then the environment, each NUL-terminated, up to an empty
// string. A buffer that does not hold argc arguments has none.
func procargs2Environment(buf []byte) [][]byte {
	if len(buf) < 4 {
		return nil
	}
	argc := int(int32(binary.LittleEndian.Uint32(buf)))
	end := bytes.IndexByte(buf[4:], 0)
	if argc < 0 || end < 0 {
		return nil
	}
	fields := bytes.Split(bytes.TrimLeft(buf[4+end:], "\x00"), []byte{0})
	if len(fields) < argc {
		return nil
	}
	var environ [][]byte
	for _, field := range fields[argc:] {
		if len(field) == 0 {
			break
		}
		environ = append(environ, field)
	}
	return environ
}

// errProcessFileTooLarge reports a /proc file over its read limit.
var errProcessFileTooLarge = errors.New("exceeds the read limit")

// readProcessFile reads a /proc file, whose size stat does not report, and
// fails when it holds more than limit bytes.
func readProcessFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w (%d bytes)", path, errProcessFileTooLarge, limit)
	}
	return data, nil
}

// launchdHermesHome returns HERMES_HOME of uid's launchd domain.
func launchdHermesHome(uid int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"getenv", "HERMES_HOME"}
	if os.Geteuid() != uid {
		if os.Geteuid() != 0 {
			return "", errors.New("another account's launchd environment cannot be read without root")
		}
		args = append([]string{"asuser", strconv.Itoa(uid), "/bin/launchctl"}, args...)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// getenv of an unset variable prints nothing; a domain that cannot
		// be read says why.
		var exit *exec.ExitError
		if !errors.As(err, &exit) || stdout.Len() != 0 || len(bytes.TrimSpace(stderr.Bytes())) != 0 {
			return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return "", nil
	}
	return strings.TrimSpace(stdout.String()), nil
}
