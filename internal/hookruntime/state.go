// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookruntime defines the stable Windows hook-launcher location and
// its installer-owned activation state. Keeping this tiny contract outside the
// application install tree lets long-running agent clients safely retain a
// cached hook command across repair, upgrade, uninstall, and reinstall.
package hookruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	LegacySchemaVersion = 1
	SchemaVersion       = 2
	LauncherName        = "defenseclaw-hook.exe"
	HookLauncherName    = "defenseclaw-hook-launcher.exe"
	GatewayName         = "defenseclaw-gateway.exe"
	StateName           = "hook-runtime-state.json"

	LauncherKindTrampoline = "trampoline"

	StatusPublishing = "publishing"
	StatusActive     = "active"
	StatusDisabled   = "disabled"

	maxStateBytes        = 64 << 10
	MaxHookLauncherBytes = 8 << 20
)

// Paths are derived from the current user's LocalAppData Known Folder on
// Windows. The environment is deliberately not consulted.
type Paths struct {
	Root     string
	Launcher string
	State    string
}

// State is the durable handshake between native setup and the no-console hook
// launcher. A launcher treats any missing, malformed, or insufficiently
// protected state at its canonical stable path as disabled.
type State struct {
	SchemaVersion  int    `json:"schema_version"`
	Status         string `json:"status"`
	RuntimeRoot    string `json:"runtime_root"`
	LauncherPath   string `json:"launcher_path"`
	LauncherSHA256 string `json:"launcher_sha256"`
	LauncherKind   string `json:"launcher_kind,omitempty"`
	HookPath       string `json:"hook_path,omitempty"`
	HookSHA256     string `json:"hook_sha256,omitempty"`
	DataRoot       string `json:"data_root,omitempty"`
	GatewayPath    string `json:"gateway_path,omitempty"`
	GatewaySHA256  string `json:"gateway_sha256,omitempty"`
	TransactionID  string `json:"transaction_id"`
}

func (state State) Active() bool { return state.Status == StatusActive }

// DelegationCapable reports whether state binds a small stable launcher to one
// exact installed full hook. The fields are additive to schema 2 so previously
// released full launchers can continue to read and ignore them.
func (state State) DelegationCapable() bool {
	if state.SchemaVersion != SchemaVersion || state.LauncherKind != LauncherKindTrampoline ||
		!filepath.IsAbs(state.HookPath) || filepath.Clean(state.HookPath) != state.HookPath ||
		!strings.EqualFold(filepath.Base(state.HookPath), LauncherName) || len(state.HookSHA256) != 64 {
		return false
	}
	_, err := hex.DecodeString(state.HookSHA256)
	return err == nil
}

// DelegatesTo reports whether this generation names executable as its exact
// installed full-hook target. Disabled generations intentionally retain this
// identity so a child created immediately before Setup disabled the runtime
// still fails closed instead of falling back to project environment.
func (state State) DelegatesTo(executable string) bool {
	return state.DelegationCapable() && samePath(state.HookPath, executable)
}

// ColdStartCapable distinguishes version-2 installer state, which binds an
// exact gateway executable, from legacy active state. Legacy state remains a
// valid hook configuration across upgrade, but it can only contact an already
// running gateway and never gains authority to start a path it did not record.
func (state State) ColdStartCapable() bool {
	if !state.Active() || state.SchemaVersion != SchemaVersion ||
		!filepath.IsAbs(state.DataRoot) || filepath.Clean(state.DataRoot) != state.DataRoot ||
		!filepath.IsAbs(state.GatewayPath) || filepath.Clean(state.GatewayPath) != state.GatewayPath ||
		!strings.EqualFold(filepath.Base(state.GatewayPath), GatewayName) || len(state.GatewaySHA256) != 64 {
		return false
	}
	_, err := hex.DecodeString(state.GatewaySHA256)
	return err == nil
}

// Validate checks the serialized state contract without consulting mutable
// process environment. File ownership and DACL validation are performed by
// ReadTrustedForExecutable before a launcher consumes the result.
func (state State) Validate(paths Paths) error {
	if state.SchemaVersion != LegacySchemaVersion && state.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported hook runtime state schema %d", state.SchemaVersion)
	}
	switch state.Status {
	case StatusPublishing, StatusActive, StatusDisabled:
	default:
		return fmt.Errorf("invalid hook runtime status %q", state.Status)
	}
	if !samePath(state.RuntimeRoot, paths.Root) || !samePath(state.LauncherPath, paths.Launcher) {
		return errors.New("hook runtime state does not match the current user's LocalAppData Known Folder")
	}
	if len(state.LauncherSHA256) != 64 {
		return errors.New("hook runtime state has an invalid launcher digest")
	}
	if _, err := hex.DecodeString(state.LauncherSHA256); err != nil {
		return errors.New("hook runtime state has an invalid launcher digest")
	}
	if len(state.TransactionID) != 32 || state.TransactionID != strings.ToLower(state.TransactionID) {
		return errors.New("hook runtime state has an invalid transaction identity")
	}
	if _, err := hex.DecodeString(state.TransactionID); err != nil {
		return errors.New("hook runtime state has an invalid transaction identity")
	}
	if state.Status == StatusActive || state.Status == StatusPublishing {
		if !filepath.IsAbs(state.DataRoot) || filepath.Clean(state.DataRoot) != state.DataRoot {
			return errors.New("enabled hook runtime state has an invalid data root")
		}
	}
	if state.SchemaVersion == LegacySchemaVersion {
		if state.LauncherKind != "" || state.HookPath != "" || state.HookSHA256 != "" ||
			state.GatewayPath != "" || state.GatewaySHA256 != "" {
			return errors.New("legacy hook runtime state unexpectedly records a delegated executable identity")
		}
		return nil
	}
	switch state.LauncherKind {
	case "":
		if state.HookPath != "" || state.HookSHA256 != "" {
			return errors.New("full hook runtime state unexpectedly records a delegation target")
		}
	case LauncherKindTrampoline:
		if !state.DelegationCapable() || samePath(state.HookPath, paths.Launcher) {
			return errors.New("hook runtime state has an invalid delegation target")
		}
	default:
		return fmt.Errorf("invalid stable hook launcher kind %q", state.LauncherKind)
	}
	if state.Status == StatusDisabled {
		if state.DataRoot != "" || state.GatewayPath != "" || state.GatewaySHA256 != "" {
			return errors.New("disabled hook runtime state retains active gateway data")
		}
		return nil
	}
	if !filepath.IsAbs(state.GatewayPath) || filepath.Clean(state.GatewayPath) != state.GatewayPath ||
		!strings.EqualFold(filepath.Base(state.GatewayPath), GatewayName) {
		return errors.New("hook runtime state has an invalid gateway path")
	}
	if len(state.GatewaySHA256) != 64 {
		return errors.New("hook runtime state has an invalid gateway digest")
	}
	if _, err := hex.DecodeString(state.GatewaySHA256); err != nil {
		return errors.New("hook runtime state has an invalid gateway digest")
	}
	return nil
}

// ReadTrustedForExecutable identifies either the canonical stable launcher or
// the exact installed full hook named by its trusted delegation state.
// recognized remains true for an unsafe canonical launcher, or for a named
// target that becomes unsafe, so the caller fails closed to a no-op instead of
// falling back to project-controlled environment.
func ReadTrustedForExecutable(executable string) (state State, recognized bool, err error) {
	paths, err := CurrentUserPaths()
	if err != nil || strings.TrimSpace(paths.Launcher) == "" {
		return State{}, false, err
	}
	return readTrustedForExecutableAt(paths, executable)
}

// RevalidatePreparedGenerationForExecutable refreshes the protected state for
// a full-hook process whose executable image was already admitted by
// ReadTrustedForExecutable or ReadTrustedDelegatedForExecutable. Trampoline
// generations validate the small canonical launcher plus byte-exact state and
// process/image binding; they do not re-read the already mapped full-hook image.
// This is intentionally narrower than ReadTrustedForExecutable and must never
// be used as initial executable admission.
func RevalidatePreparedGenerationForExecutable(executable string, prepared State) (State, error) {
	paths, err := CurrentUserPaths()
	if err != nil {
		return State{}, err
	}
	if strings.TrimSpace(paths.Launcher) == "" {
		return State{}, errors.New("canonical stable hook launcher path is empty")
	}
	return revalidatePreparedGenerationForExecutableAt(paths, executable, prepared)
}

func revalidatePreparedGenerationForExecutableAt(
	paths Paths,
	executable string,
	prepared State,
) (State, error) {
	if !prepared.Active() || !prepared.DelegationCapable() || !prepared.DelegatesTo(executable) {
		return State{}, errors.New("prepared hook runtime does not authorize this full-hook executable")
	}
	current, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil {
		return State{}, err
	}
	if !recognized {
		return State{}, errors.New("canonical stable hook launcher is not recognized")
	}
	if current != prepared {
		return State{}, errors.New("protected hook runtime generation changed after executable admission")
	}
	return current, nil
}

func readTrustedForExecutableAt(paths Paths, executable string) (state State, recognized bool, err error) {
	if samePath(executable, paths.Launcher) {
		return readTrustedAt(paths, executable)
	}
	state, _, err = readTrustedAt(paths, paths.Launcher)
	if err != nil || !state.DelegatesTo(executable) {
		// An ordinary installed hook remains directly runnable. Only an exact
		// target named by trusted stable state is recognized here.
		return State{}, false, err
	}
	locked, err := LockVerifiedHook(state)
	if err != nil {
		return State{}, true, err
	}
	if err := locked.Close(); err != nil {
		return State{}, true, err
	}
	return state, true, nil
}

func readTrustedAt(paths Paths, executable string) (state State, recognized bool, err error) {
	if !samePath(executable, paths.Launcher) {
		return State{}, false, nil
	}
	if err := safefile.ValidatePrivateDirectory(paths.Root); err != nil {
		return State{}, true, fmt.Errorf("validate stable hook runtime directory: %w", err)
	}
	if err := safefile.ValidatePrivateFile(paths.Launcher); err != nil {
		return State{}, true, fmt.Errorf("validate stable hook launcher: %w", err)
	}
	if err := safefile.ValidatePrivateFile(paths.State); err != nil {
		return State{}, true, fmt.Errorf("validate stable hook runtime state: %w", err)
	}
	info, err := os.Lstat(paths.State)
	if err != nil {
		return State{}, true, err
	}
	if info.Size() > maxStateBytes {
		return State{}, true, errors.New("stable hook runtime state is too large")
	}
	file, err := os.Open(paths.State)
	if err != nil {
		return State{}, true, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return State{}, true, readErr
	}
	if closeErr != nil {
		return State{}, true, closeErr
	}
	if len(body) > maxStateBytes {
		return State{}, true, errors.New("stable hook runtime state is too large")
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return State{}, true, fmt.Errorf("parse stable hook runtime state: %w", err)
	}
	if err := state.Validate(paths); err != nil {
		return State{}, true, err
	}
	digest, err := fileSHA256(paths.Launcher)
	if err != nil {
		return State{}, true, fmt.Errorf("hash stable hook launcher: %w", err)
	}
	if !strings.EqualFold(digest, state.LauncherSHA256) {
		return State{}, true, errors.New("stable hook launcher digest does not match activation state")
	}
	return state, true, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func samePath(left, right string) bool {
	return pathidentity.Same(left, right)
}
