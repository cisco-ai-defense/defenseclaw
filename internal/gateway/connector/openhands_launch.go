// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// openHandsLifecycleMu complements the owned cross-process lock. Setup,
// rollback, launch admission, and teardown all use this same transaction so a
// failed setup can never revoke a token another concurrent setup just adopted.
var openHandsLifecycleMu sync.Mutex

func withOpenHandsLifecycleTransaction(opts SetupOpts, fn func() error) error {
	if strings.TrimSpace(opts.DataDir) == "" || !filepath.IsAbs(opts.DataDir) {
		return errors.New("openhands lifecycle transaction requires an absolute data dir")
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return fmt.Errorf("openhands lifecycle transaction: create lock dir: %w", err)
	}

	openHandsLifecycleMu.Lock()
	defer openHandsLifecycleMu.Unlock()
	return withOwnedFileLock(filepath.Join(opts.DataDir, ".openhands-lifecycle.lock"), fn)
}

type openHandsNativeProcess interface {
	Start() error
	Wait() error
}

var newOpenHandsNativeProcess = func(
	ctx context.Context,
	executable string,
	args []string,
	env []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) openHandsNativeProcess {
	cmd := processutil.CommandContext(ctx, executable, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd
}

// LaunchOpenHandsWithNativeOTLP starts one OpenHands process through the only
// production boundary that receives DefenseClaw's Darwin native-OTLP
// environment. The connector-scoped token is loaded from its owner-only file
// and placed only in cmd.Env; it is never returned, printed, or passed in argv.
// CommandContext owns cancellation and process teardown after Start succeeds.
func LaunchOpenHandsWithNativeOTLP(
	ctx context.Context,
	opts SetupOpts,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) error {
	return launchOpenHandsWithNativeOTLPForOS(ctx, opts, args, stdin, stdout, stderr, runtime.GOOS)
}

func launchOpenHandsWithNativeOTLPForOS(
	ctx context.Context,
	opts SetupOpts,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	goos string,
) error {
	if strings.ToLower(strings.TrimSpace(goos)) != "darwin" {
		return errors.New("OpenHands native OTLP launch is supported only on Darwin")
	}
	var child openHandsNativeProcess
	err := withOpenHandsLifecycleTransaction(opts, func() error {
		executable, env, err := prepareOpenHandsNativeLaunchLocked(opts, goos)
		if err != nil {
			return err
		}
		child = newOpenHandsNativeProcess(ctx, executable, append([]string(nil), args...), env, stdin, stdout, stderr)
		if child == nil {
			return errors.New("openhands launch process factory returned no process")
		}
		// Re-hash the exact protected path in the last DefenseClaw operation
		// before exec. This catches replacement during environment rendering;
		// the protected ancestry prevents an untrusted directory swap.
		if err := revalidateOpenHandsSealedExecutable(opts, executable); err != nil {
			return fmt.Errorf("openhands launch executable revalidation: %w", err)
		}
		if err := child.Start(); err != nil {
			return fmt.Errorf("start protected OpenHands process: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := child.Wait(); err != nil {
		return fmt.Errorf("protected OpenHands process exited: %w", err)
	}
	return nil
}

func revalidateOpenHandsSealedExecutable(opts SetupOpts, executable string) error {
	entries, err := LoadProtectedHookContractLockEntries(opts.DataDir)
	if err != nil {
		return fmt.Errorf("reload protected contract: %w", err)
	}
	entry, ok := entries["openhands"]
	if !ok || !validSetupSelectedAgentExecutableEvidence(entry, "openhands") {
		return errors.New("protected OpenHands executable evidence is no longer valid")
	}
	opts.AgentExecutable = executable
	opts.AgentVersion = entry.RawAgentVersion
	_, err = validateOpenHandsDarwinExecutable(opts, true)
	return err
}

func prepareOpenHandsNativeLaunchLocked(opts SetupOpts, goos string) (string, []string, error) {
	if strings.ToLower(strings.TrimSpace(goos)) != "darwin" {
		return "", nil, errors.New("OpenHands native OTLP launch is supported only on Darwin")
	}
	if err := validateOpenHandsLoopbackAPIAddr(opts.APIAddr); err != nil {
		return "", nil, err
	}
	active, err := LoadProtectedActiveConnectors(opts.DataDir)
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch active registration: %w", err)
	}
	if !containsConnectorName(active, "openhands") || ConnectorExplicitlyInactive(opts.DataDir, "openhands") {
		return "", nil, errors.New("openhands launch requires an active protected connector registration")
	}

	entries, err := LoadProtectedHookContractLockEntries(opts.DataDir)
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch protected contract: %w", err)
	}
	entry, ok := entries["openhands"]
	if !ok || !validSetupSelectedAgentExecutableEvidence(entry, "openhands") {
		return "", nil, errors.New("openhands launch requires valid setup-selected executable evidence")
	}
	opts.AgentExecutable = entry.AgentExecutable
	opts.AgentVersion = entry.RawAgentVersion
	executable, err := validateOpenHandsDarwinExecutable(opts, false)
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch executable: %w", err)
	}

	conn := NewOpenHandsConnector()
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch hook registration: %w", err)
	}
	if !present {
		return "", nil, errors.New("openhands launch hook registration is not current")
	}
	currentDigests := HookScriptDigests(opts, conn)
	expectedHookDigest := entry.HookScriptDigests["openhands-hook.sh"]
	if expectedHookDigest == "" || currentDigests["openhands-hook.sh"] != expectedHookDigest {
		return "", nil, errors.New("openhands launch hook runtime digest does not match protected evidence")
	}

	token, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands)
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch scoped OTLP credential: %w", err)
	}
	if !otlpTokenHexRE.MatchString(token) {
		return "", nil, errors.New("openhands launch scoped OTLP credential is missing or invalid")
	}
	opts.OTLPPathToken = token
	spec := openhandsNativeOTLPSpecForOS(opts, goos)
	if spec == nil {
		return "", nil, errors.New("openhands launch has no native OTLP contract for this platform")
	}
	envBlock, err := spec.EnvBlock()
	if err != nil {
		return "", nil, fmt.Errorf("openhands launch render native OTLP environment: %w", err)
	}
	env := scrubOpenHandsLaunchEnvironment(os.Environ())
	for key, value := range envBlock {
		env = replaceProcessEnv(env, key, value)
	}
	return executable, env, nil
}

func validateOpenHandsLoopbackAPIAddr(apiAddr string) error {
	trimmed := strings.TrimSpace(apiAddr)
	if trimmed == "" || trimmed != apiAddr || strings.ContainsAny(trimmed, "\x00\r\n") {
		return errors.New("openhands launch requires a canonical loopback API address")
	}
	host, port, err := net.SplitHostPort(trimmed)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return errors.New("openhands launch requires a canonical loopback API address")
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || !ip.IsLoopback() {
		return errors.New("openhands launch refuses a non-loopback OTLP endpoint")
	}
	return nil
}

func validateOpenHandsDarwinExecutable(opts SetupOpts, sealedOnly bool) (string, error) {
	selected := strings.TrimSpace(opts.AgentExecutable)
	if selected == "" || selected != opts.AgentExecutable || strings.ContainsAny(selected, "\x00\r\n") ||
		!filepath.IsAbs(selected) || filepath.Clean(selected) != selected || filepath.Base(selected) != "openhands" {
		return "", errors.New("selected OpenHands executable is not an absolute normalized openhands path")
	}

	expectedPath, expectedVersion, expectedDigest := "", "", ""
	entry, lockExists := loadProtectedHookContractEntry(opts.DataDir, "openhands")
	if selection, supersedes := supersedingProtectedSetupSelection(opts.DataDir, "openhands", entry); supersedes {
		if sealedOnly {
			return "", errors.New("newer OpenHands setup selection supersedes the active registration")
		}
		expectedPath, expectedVersion, expectedDigest = selection.Executable, selection.RawVersion, selection.SHA256
	} else if lockExists {
		if !validSetupSelectedAgentExecutableEvidence(entry, "openhands") {
			return "", errors.New("OpenHands hook contract has invalid setup-selected executable evidence")
		}
		expectedPath, expectedVersion, expectedDigest = entry.AgentExecutable, entry.RawAgentVersion, entry.AgentExecutableSHA256
	} else if !sealedOnly {
		if selection, ok := loadSetupAgentSelection(opts.DataDir, "openhands"); ok {
			expectedPath, expectedVersion, expectedDigest = selection.Executable, selection.RawVersion, selection.SHA256
		}
	}
	if expectedPath == "" {
		return "", errors.New("OpenHands requires protected setup-selected executable evidence")
	}
	if !sameCodexExecutablePath(selected, expectedPath) {
		return "", errors.New("selected OpenHands executable does not match protected evidence")
	}
	if strings.TrimSpace(opts.AgentVersion) != strings.TrimSpace(expectedVersion) {
		return "", errors.New("selected OpenHands executable evidence is bound to a different agent version")
	}

	info, err := os.Lstat(selected)
	if err != nil {
		return "", fmt.Errorf("inspect selected OpenHands executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		(runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", errors.New("selected OpenHands executable is not an executable regular non-link file")
	}
	if err := hookAPIValidateDirectory(filepath.Dir(selected)); err != nil {
		return "", fmt.Errorf("validate selected OpenHands executable ancestry: %w", err)
	}
	if err := hookAPIValidateOwner(selected, info); err != nil {
		return "", fmt.Errorf("validate selected OpenHands executable custody: %w", err)
	}
	stablePath, digest, ok := setupSelectedAgentExecutableEvidence(selected)
	if !ok || !sameCodexExecutablePath(stablePath, selected) {
		return "", errors.New("selected OpenHands executable changed during validation")
	}
	if digest != expectedDigest {
		return "", errors.New("selected OpenHands executable digest does not match protected evidence")
	}
	return selected, nil
}

func validateOpenHandsDarwinLockPublication(dataDir string, entry HookContractLockEntry) error {
	if !validSetupSelectedAgentExecutableEvidence(entry, "openhands") {
		return errors.New("OpenHands hook contract publication has invalid executable evidence")
	}
	if _, err := validateOpenHandsDarwinExecutable(SetupOpts{
		DataDir:         dataDir,
		AgentVersion:    entry.RawAgentVersion,
		AgentExecutable: entry.AgentExecutable,
	}, false); err != nil {
		return fmt.Errorf("OpenHands hook contract publication executable: %w", err)
	}
	return nil
}

func scrubOpenHandsLaunchEnvironment(env []string) []string {
	blockedExact := map[string]bool{
		"BASH_ENV": true,
		"ENV":      true,
	}
	out := make([]string, 0, len(env))
	for _, item := range env {
		key, _, found := strings.Cut(item, "=")
		upper := strings.ToUpper(strings.TrimSpace(key))
		if !found || blockedExact[upper] || strings.HasPrefix(upper, "PYTHON") || strings.HasPrefix(upper, "DYLD_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "OTEL_") {
			continue
		}
		out = append(out, item)
	}
	return out
}
