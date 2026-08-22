// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const protectedDarwinAgentChildMode = "__defenseclaw_protected_darwin_agent_child_v1"

var (
	protectedDarwinRealUID      = os.Getuid
	protectedDarwinEffectiveUID = os.Geteuid
	protectedDarwinEffectiveGID = os.Getegid
	protectedDarwinSetEUID      = syscall.Seteuid
	protectedDarwinKill         = syscall.Kill
	protectedDarwinExecutable   = os.Executable
	protectedDarwinCommandStart = func(command *exec.Cmd) error { return command.Start() }
	protectedDarwinCommandWait  = func(command *exec.Cmd) error { return command.Wait() }
	protectedDarwinLauncher     = trustedProtectedDarwinLauncherExecutable
	protectedDarwinStageImage   = stageProtectedDarwinAgentImage
	protectedDarwinCreateStage  = func() (string, error) {
		return os.MkdirTemp("/private/var/tmp", ".defenseclaw-agent-")
	}
	protectedDarwinChown               = os.Chown
	protectedDarwinValidateStagedImage = func(connectorName, path string) error {
		switch connectorName {
		case "codex":
			return validateCodexNativeExecutablePlatform(path)
		case "claudecode":
			return validateClaudeCodeDarwinNativeImage(path)
		default:
			return errors.New("unsupported protected Darwin staged image")
		}
	}
)

type protectedDarwinStagedImage struct {
	directory string
	path      string
}

func init() {
	if len(os.Args) < 2 || os.Args[1] != protectedDarwinAgentChildMode {
		return
	}
	err := runProtectedDarwinAgentChild(os.Args[2:])
	if err == nil {
		os.Exit(0)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
		os.Exit(exitErr.ExitCode())
	}
	_, _ = fmt.Fprintln(os.Stderr, "DefenseClaw protected Darwin agent launcher failed")
	os.Exit(126)
}

// startProtectedDarwinAgentCommand prevents a soft-dropped enterprise
// guardian from leaking its recoverable real/saved uid 0 into a selected
// third-party image. Darwin credentials are process-wide, so the trusted
// parent never regains euid 0 around Start. It starts a root-custodied copy of
// DefenseClaw, which seals and revalidates the exact selected bytes before
// starting them with an irreversible child Credential.
func startProtectedDarwinAgentCommand(command *exec.Cmd, connectorName, expectedDigest string) error {
	if command == nil {
		return errors.New("start protected Darwin agent command: nil command")
	}
	targetUID := protectedDarwinEffectiveUID()
	targetGID := protectedDarwinEffectiveGID()
	if targetUID < 0 || targetGID < 0 {
		return errors.New("start protected Darwin agent command: invalid target credentials")
	}
	// Ordinary user setup has no recoverable privileged identity to contain.
	// Preserve its existing environment, cwd, supplementary groups, and start
	// behavior exactly.
	if protectedDarwinRealUID() != 0 || targetUID == 0 {
		return protectedDarwinCommandStart(command)
	}
	connectorName = normalizeConnectorName(connectorName)
	if (connectorName != "codex" && connectorName != "claudecode") || !validLowerHexSHA256(expectedDigest) {
		return errors.New("start protected Darwin agent command: invalid protected image identity")
	}
	helper, err := protectedDarwinLauncher()
	if err != nil {
		return err
	}
	selectedPath := command.Path
	selectedArgs := append([]string(nil), command.Args...)
	if len(selectedArgs) == 0 {
		selectedArgs = []string{selectedPath}
	}
	if selectedPath == "" || !filepath.IsAbs(selectedPath) || filepath.Clean(selectedPath) != selectedPath ||
		strings.ContainsAny(selectedPath, "\x00\r\n") {
		return errors.New("start protected Darwin agent command: selected executable is not canonical and absolute")
	}
	command.Path = helper
	command.Args = append(
		[]string{
			helper,
			protectedDarwinAgentChildMode,
			strconv.Itoa(targetUID),
			strconv.Itoa(targetGID),
			connectorName,
			strings.ToLower(expectedDigest),
			selectedPath,
		},
		selectedArgs[1:]...,
	)
	command.Dir = "/"
	command.Env = protectedDarwinAgentEnvironment(command.Env)
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	// The broker inherits the parent's soft-dropped identity. A Credential here
	// would make Go call setgroups while euid is non-root. A private process
	// group lets context cancellation and app-server cleanup contain the sealed
	// grandchild as well as the broker.
	command.SysProcAttr.Credential = nil
	command.SysProcAttr.Setpgid = true
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := protectedDarwinKill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return protectedDarwinCommandStart(command)
}

// trustedProtectedDarwinLauncherExecutable admits only a root-owned immutable
// launcher path. Generic connector custody deliberately accepts the target
// user and therefore is not sufficient for a process that inherits ruid 0.
func trustedProtectedDarwinLauncherExecutable() (string, error) {
	path, err := protectedDarwinExecutable()
	if err != nil {
		return "", fmt.Errorf("resolve protected Darwin launcher: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("resolve protected Darwin launcher: executable path is not canonical")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", errors.New("protected Darwin launcher path resolves through a symlink")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return "", fmt.Errorf("inspect protected Darwin launcher path %s: %w", current, statErr)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", fmt.Errorf("protected Darwin launcher path is not root-owned: %s", current)
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("protected Darwin launcher path is mutable or redirected: %s", current)
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Size() <= 0 {
				return "", errors.New("protected Darwin launcher is not a non-empty regular file")
			}
		} else if !info.IsDir() {
			return "", fmt.Errorf("protected Darwin launcher ancestor is not a directory: %s", current)
		}
		if err := hookAPIValidateDirectoryACL(current); err != nil {
			return "", fmt.Errorf("validate protected Darwin launcher ACL: %w", err)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return path, nil
}

func runProtectedDarwinAgentChild(arguments []string) error {
	if len(arguments) < 5 || protectedDarwinRealUID() != 0 {
		return errors.New("invalid protected Darwin agent child invocation")
	}
	targetUID, uidErr := strconv.Atoi(arguments[0])
	targetGID, gidErr := strconv.Atoi(arguments[1])
	connectorName := normalizeConnectorName(arguments[2])
	expectedDigest := strings.ToLower(arguments[3])
	selectedPath := arguments[4]
	if uidErr != nil || gidErr != nil || targetUID <= 0 || targetGID < 0 ||
		protectedDarwinEffectiveUID() != targetUID || protectedDarwinEffectiveGID() != targetGID ||
		(connectorName != "codex" && connectorName != "claudecode") ||
		!validLowerHexSHA256(expectedDigest) ||
		!filepath.IsAbs(selectedPath) || filepath.Clean(selectedPath) != selectedPath ||
		strings.ContainsAny(selectedPath, "\x00\r\n") {
		return errors.New("invalid protected Darwin agent child target")
	}
	if err := protectedDarwinSetEUID(0); err != nil {
		return fmt.Errorf("regain broker euid: %w", err)
	}
	staged, err := protectedDarwinStageImage(connectorName, selectedPath, expectedDigest, targetGID)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged.directory)

	command := exec.Command(staged.path, arguments[5:]...)
	command.Args[0] = selectedPath
	command.Dir = "/"
	command.Env = protectedDarwinAgentEnvironment(os.Environ())
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(targetUID),
			Gid:    uint32(targetGID),
			Groups: []uint32{uint32(targetGID)},
		},
	}
	if err := protectedDarwinCommandStart(command); err != nil {
		return err
	}
	// Start returns only after the exec side of fork/exec has either succeeded
	// or reported an error. Darwin permits unlinking a mapped executable, so
	// remove the sealed copy immediately while the child runs. Cleanup cannot
	// rely only on a broker defer: normal app-server cancellation SIGKILLs the
	// broker process group and SIGKILL skips defers.
	if err := os.RemoveAll(staged.directory); err != nil {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		waitErr := protectedDarwinCommandWait(command)
		return errors.Join(fmt.Errorf("remove sealed Darwin agent staging: %w", err), waitErr)
	}
	staged.directory = ""
	return protectedDarwinCommandWait(command)
}

func stageProtectedDarwinAgentImage(
	connectorName, selectedPath, expectedDigest string,
	targetGID int,
) (staged protectedDarwinStagedImage, retErr error) {
	sourceFD, err := unix.Open(selectedPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return staged, fmt.Errorf("open selected Darwin agent image: %w", err)
	}
	source := os.NewFile(uintptr(sourceFD), selectedPath)
	if source == nil {
		_ = unix.Close(sourceFD)
		return staged, errors.New("open selected Darwin agent image: invalid file descriptor")
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > setupAgentExecutableMaxBytes {
		return staged, errors.New("selected Darwin agent image is not a bounded regular file")
	}
	quarantine := make([]byte, 4096)
	if size, xattrErr := unix.Fgetxattr(sourceFD, "com.apple.quarantine", quarantine); xattrErr == nil {
		return staged, fmt.Errorf("selected Darwin agent image is quarantined: %q", strings.TrimSpace(string(quarantine[:size])))
	} else if !errors.Is(xattrErr, unix.ENOATTR) {
		return staged, fmt.Errorf("inspect selected Darwin agent quarantine attribute: %w", xattrErr)
	}

	directory, err := protectedDarwinCreateStage()
	if err != nil {
		return staged, fmt.Errorf("create sealed Darwin agent staging directory: %w", err)
	}
	staged.directory = directory
	defer func() {
		if retErr != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := protectedDarwinChown(directory, 0, targetGID); err != nil {
		return staged, fmt.Errorf("set sealed Darwin agent staging owner: %w", err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return staged, fmt.Errorf("protect sealed Darwin agent staging directory: %w", err)
	}
	name := "codex"
	if connectorName == "claudecode" {
		name = "claude"
	}
	staged.path = filepath.Join(directory, name)
	destination, err := os.OpenFile(staged.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		return staged, fmt.Errorf("create sealed Darwin agent image: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(source, setupAgentExecutableMaxBytes+1))
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() || written <= 0 || written > setupAgentExecutableMaxBytes {
		return staged, errors.New("copy selected Darwin agent image into sealed staging failed")
	}
	actualDigest := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(actualDigest, expectedDigest) {
		return staged, errors.New("selected Darwin agent image digest does not match protected evidence")
	}
	if err := protectedDarwinChown(staged.path, 0, targetGID); err != nil {
		return staged, fmt.Errorf("set sealed Darwin agent image owner: %w", err)
	}
	if err := os.Chmod(staged.path, 0o550); err != nil {
		return staged, fmt.Errorf("protect sealed Darwin agent image: %w", err)
	}
	// Signature, identifier, team, architecture, quarantine, ACL, and native
	// image checks run against this exact root-owned copy. This prevents a
	// target user from presenting signed bytes only during pathname checks and
	// restoring different receipt-bound bytes before execution.
	err = protectedDarwinValidateStagedImage(connectorName, staged.path)
	if err != nil {
		return staged, fmt.Errorf("validate sealed Darwin agent image: %w", err)
	}
	return staged, nil
}

func protectedDarwinAgentEnvironment(source []string) []string {
	environment := []string{
		"HOME=/var/empty",
		"LANG=C",
		"LC_ALL=C",
		"NO_COLOR=1",
		"PATH=/usr/bin:/bin",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/var/empty",
		"XDG_CONFIG_HOME=/var/empty",
		"XDG_DATA_HOME=/var/empty",
	}
	for _, entry := range source {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key != "CODEX_HOME" || value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value ||
			strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		environment = append(environment, "CODEX_HOME="+value)
		break
	}
	return environment
}
