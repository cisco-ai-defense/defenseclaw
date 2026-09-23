// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	delegationLockTimeout       = 2 * time.Minute
	delegationGenerationEnvName = "DEFENSECLAW_INTERNAL_HOOK_DELEGATION"
	delegationGenerationPrefix  = "v2:"
)

// Delegate synchronously invokes the exact installed full hook selected by
// trusted active state. Any state or target failure is an intentional success
// no-op, preserving cached hook behavior after disable or uninstall.
func Delegate(
	executable string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	paths, err := CurrentUserPaths()
	if err != nil {
		return 0
	}
	return delegateAt(paths, executable, args, stdin, stdout, stderr)
}

func delegateAt(
	paths Paths,
	executable string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	var command *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), delegationLockTimeout)
	defer cancel()
	err := WithGatewayStartLock(ctx, func() error {
		// Setup publishes and disables under this same mutex. Re-read only after
		// acquisition so disable wins cleanly when it linearizes first.
		state, recognized, readErr := readTrustedAt(paths, executable)
		if readErr != nil || !recognized || !state.Active() || !state.DelegationCapable() {
			return nil
		}
		locked, lockErr := LockVerifiedHook(state)
		if lockErr != nil {
			return nil
		}
		defer locked.Close()
		candidate := exec.Command(state.HookPath, args...)
		candidate.Stdin = stdin
		candidate.Stdout = stdout
		candidate.Stderr = stderr
		parentProof, proofErr := inheritableCurrentProcessProof()
		if proofErr == nil {
			defer windows.CloseHandle(parentProof)
			candidate.Env = delegatedHookEnvironment(os.Environ(), state, parentProof)
			candidate.SysProcAttr = &syscall.SysProcAttr{
				AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(parentProof)},
			}
		}
		// Dir intentionally remains unset so os/exec preserves the launcher's
		// current directory. Environment is preserved except for the reserved
		// parent-owned generation marker, which is replaced with the exact state
		// whose full-hook handle remains locked through CreateProcess.
		if startErr := candidate.Start(); startErr != nil {
			return nil
		}
		command = candidate
		return nil
	})
	if err != nil || command == nil {
		return 0
	}
	if err := command.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

func delegatedHookEnvironment(environ []string, state State, parentProof windows.Handle) []string {
	marker := delegationGenerationPrefix + strconv.FormatUint(uint64(parentProof), 10) + ":" +
		state.TransactionID + ":" + state.HookSHA256
	clean := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), delegationGenerationEnvName) {
			continue
		}
		clean = append(clean, entry)
	}
	return append(clean, delegationGenerationEnvName+"="+marker)
}

// ReadTrustedDelegatedForExecutable reuses the full-image admission already
// completed by the canonical stable launcher. The child must still prove that
// its live OS parent is that exact protected launcher and that the current
// protected state is the same generation whose target was held locked through
// CreateProcess. Direct and legacy invocations return recognized=false and keep
// the ordinary full-image validation path.
func ReadTrustedDelegatedForExecutable(executable string) (state State, recognized bool, err error) {
	marker, present := lookupDelegationGeneration(os.Environ())
	if !present {
		return State{}, false, nil
	}
	paths, err := CurrentUserPaths()
	if err != nil || strings.TrimSpace(paths.Launcher) == "" {
		return State{}, false, err
	}
	parentProof, err := delegationParentProofHandle(marker)
	if err != nil {
		// Without an inherited handle, a project-controlled environment value
		// has no parent authority and must retain the ordinary full validation.
		return State{}, false, nil
	}
	trustedParent, err := liveCanonicalDelegatingParent(paths.Launcher, parentProof)
	if err != nil || !trustedParent {
		return State{}, false, nil
	}
	// Only a handle proven to name the live canonical parent belongs to this
	// child. Never close an arbitrary handle selected by inherited environment.
	defer windows.CloseHandle(parentProof)
	return validateTrustedDelegatedGenerationAt(paths, executable, marker)
}

func lookupDelegationGeneration(environ []string) (string, bool) {
	for index := len(environ) - 1; index >= 0; index-- {
		name, value, ok := strings.Cut(environ[index], "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), delegationGenerationEnvName) {
			return value, true
		}
	}
	return "", false
}

func readTrustedDelegatedForExecutableAt(
	paths Paths,
	executable string,
	marker string,
	parentProof func(string, windows.Handle) (bool, error),
) (state State, recognized bool, err error) {
	if samePath(executable, paths.Launcher) {
		return State{}, false, nil
	}
	proofHandle, err := delegationParentProofHandle(marker)
	if err != nil {
		return State{}, false, nil
	}
	trustedParent, err := parentProof(paths.Launcher, proofHandle)
	if err != nil || !trustedParent {
		// A project can forge the reserved environment name. It cannot turn a
		// non-launcher parent into authority; retain the ordinary full hash.
		return State{}, false, nil
	}
	return validateTrustedDelegatedGenerationAt(paths, executable, marker)
}

func validateTrustedDelegatedGenerationAt(
	paths Paths,
	executable string,
	marker string,
) (state State, recognized bool, err error) {
	transactionID, hookDigest, err := parseDelegationGeneration(marker)
	if err != nil {
		return State{}, true, err
	}
	state, stateRecognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil {
		return State{}, true, err
	}
	if !stateRecognized {
		return State{}, true, errors.New("delegating stable launcher is no longer recognized")
	}
	if !state.Active() || !state.DelegatesTo(executable) ||
		state.TransactionID != transactionID || !strings.EqualFold(state.HookSHA256, hookDigest) {
		return State{}, true, errors.New("delegated full-hook generation no longer matches protected runtime state")
	}
	return state, true, nil
}

func parseDelegationGeneration(marker string) (transactionID string, hookDigest string, err error) {
	parts := strings.Split(marker, ":")
	if len(parts) != 4 || parts[0] != strings.TrimSuffix(delegationGenerationPrefix, ":") ||
		len(parts[2]) != 32 || len(parts[3]) != 64 ||
		strings.ToLower(parts[2]) != parts[2] {
		return "", "", errors.New("delegated full-hook generation marker is malformed")
	}
	if _, err := delegationParentProofHandle(marker); err != nil {
		return "", "", errors.New("delegated full-hook parent handle is malformed")
	}
	if _, err := strconv.ParseUint(parts[2][:16], 16, 64); err != nil {
		return "", "", errors.New("delegated full-hook transaction identity is malformed")
	}
	if _, err := strconv.ParseUint(parts[2][16:], 16, 64); err != nil {
		return "", "", errors.New("delegated full-hook transaction identity is malformed")
	}
	for offset := 0; offset < len(parts[3]); offset += 16 {
		if _, err := strconv.ParseUint(parts[3][offset:offset+16], 16, 64); err != nil {
			return "", "", errors.New("delegated full-hook digest is malformed")
		}
	}
	return parts[2], parts[3], nil
}

func delegationParentProofHandle(marker string) (windows.Handle, error) {
	parts := strings.Split(marker, ":")
	if len(parts) != 4 || parts[0] != strings.TrimSuffix(delegationGenerationPrefix, ":") {
		return 0, errors.New("delegated full-hook parent marker is malformed")
	}
	raw, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || raw == 0 || uint64(uintptr(windows.Handle(raw))) != raw {
		return 0, errors.New("delegated full-hook parent handle is malformed")
	}
	return windows.Handle(raw), nil
}

func inheritableCurrentProcessProof() (windows.Handle, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(os.Getpid()),
	)
	if err != nil {
		return 0, err
	}
	if err := windows.SetHandleInformation(
		handle,
		windows.HANDLE_FLAG_INHERIT,
		windows.HANDLE_FLAG_INHERIT,
	); err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func liveCanonicalDelegatingParent(expectedLauncher string, parent windows.Handle) (bool, error) {
	parentPID, err := currentProcessParentID()
	if err != nil || parentPID == 0 {
		return false, err
	}
	if boundPID, err := windows.GetProcessId(parent); err != nil || boundPID != parentPID {
		if err == nil {
			err = errors.New("delegating parent process identity changed")
		}
		return false, err
	}
	waitResult, err := windows.WaitForSingleObject(parent, 0)
	if err != nil || waitResult != uint32(windows.WAIT_TIMEOUT) {
		if err == nil {
			err = errors.New("delegating parent process is not live")
		}
		return false, err
	}
	image, err := processImageFromHandle(parent)
	if err != nil || !samePath(image, expectedLauncher) {
		return false, err
	}

	parentCreated, err := processCreationTime(parent)
	if err != nil {
		return false, err
	}
	childCreated, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		return false, err
	}
	if parentCreated >= childCreated {
		return false, errors.New("delegating parent does not precede the full-hook child")
	}
	return true, nil
}

func currentProcessParentID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}
	want := uint32(os.Getpid())
	for {
		if entry.ProcessID == want {
			return entry.ParentProcessID, nil
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return 0, errors.New("current process is absent from the Windows process snapshot")
			}
			return 0, err
		}
	}
}

func processImageFromHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	if size == 0 || size > uint32(len(buffer)) {
		return "", errors.New("delegating parent image path is empty or oversized")
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func processCreationTime(handle windows.Handle) (int64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, fmt.Errorf("read process creation time: %w", err)
	}
	return creation.Nanoseconds(), nil
}
