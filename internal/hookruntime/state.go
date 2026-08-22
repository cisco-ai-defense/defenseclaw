// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookruntime defines the stable Windows hook-launcher location and
// its installer-owned activation state. Keeping this tiny contract outside the
// application install tree lets long-running agent clients safely retain a
// cached hook command across repair, upgrade, uninstall, and reinstall.
package hookruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	maxStateBytes            = 64 << 10
	stateMutationLockTimeout = 2 * time.Minute
	MaxHookLauncherBytes     = 8 << 20
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

// Publish atomically refreshes the stable launcher and activates it for the
// committed native-setup transaction. The publishing state is made visible
// before the executable changes, so a hook process can observe either a fully
// verified old generation, an intentional no-op, or the fully verified new
// generation -- never a new executable paired with stale activation data.
func Publish(source, hookPath, gatewayPath, dataRoot, transactionID string) error {
	paths, err := CurrentUserPaths()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stateMutationLockTimeout)
	defer cancel()
	return WithGatewayStartLock(ctx, func() error {
		return publishAt(paths, source, hookPath, gatewayPath, dataRoot, transactionID)
	})
}

// Disable leaves the stable launcher in place for already-running Codex and
// Claude clients while atomically turning every subsequent invocation into a
// successful no-op. The runtime intentionally survives both data-preserving
// and DELETEUSERDATA uninstall modes.
func Disable(transactionID string) error {
	paths, err := CurrentUserPaths()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stateMutationLockTimeout)
	defer cancel()
	return WithGatewayStartLock(ctx, func() error {
		return disableAt(paths, transactionID)
	})
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

func publishAt(paths Paths, source, hookPath, gatewayPath, dataRoot, transactionID string) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if !validTransactionID(transactionID) {
		return errors.New("stable hook runtime requires a valid setup transaction identity")
	}
	dataRoot = filepath.Clean(dataRoot)
	if !filepath.IsAbs(dataRoot) {
		return errors.New("stable hook runtime requires an absolute data root")
	}
	source = filepath.Clean(source)
	hookPath = filepath.Clean(hookPath)
	if !filepath.IsAbs(source) || !filepath.IsAbs(hookPath) ||
		!strings.EqualFold(filepath.Base(hookPath), LauncherName) {
		return errors.New("stable hook runtime requires absolute launcher and installed hook paths")
	}
	delegating := !samePath(source, hookPath)
	gatewayPath = filepath.Clean(gatewayPath)
	if !filepath.IsAbs(gatewayPath) || !strings.EqualFold(filepath.Base(gatewayPath), GatewayName) {
		return errors.New("stable hook runtime requires an absolute installed gateway path")
	}
	// The native installer is the writer for this per-user executable. Give the
	// gateway the same current-user/SYSTEM DACL as other protected runtime state
	// before recording its identity, then require that protection on every cold
	// start. This prevents a project or another local principal from replacing
	// the image selected by the hook launcher.
	if err := safefile.ProtectFile(gatewayPath); err != nil {
		return fmt.Errorf("protect installed gateway for hook recovery: %w", err)
	}
	if err := safefile.ValidatePrivateFile(gatewayPath); err != nil {
		return fmt.Errorf("validate installed gateway for hook recovery: %w", err)
	}
	gatewayDigest, err := fileSHA256(gatewayPath)
	if err != nil {
		return fmt.Errorf("hash installed gateway for hook recovery: %w", err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect packaged hook launcher: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("packaged hook launcher is not a regular file: %s", source)
	}
	if delegating && info.Size() > MaxHookLauncherBytes {
		return fmt.Errorf(
			"packaged stable hook launcher is %d bytes; maximum is %d",
			info.Size(),
			MaxHookLauncherBytes,
		)
	}
	var hookDigest string
	if delegating {
		if err := safefile.ProtectFile(hookPath); err != nil {
			return fmt.Errorf("protect installed full hook for delegation: %w", err)
		}
		if err := safefile.ValidatePrivateFile(hookPath); err != nil {
			return fmt.Errorf("validate installed full hook for delegation: %w", err)
		}
		hookDigest, err = fileSHA256(hookPath)
		if err != nil {
			return fmt.Errorf("hash installed full hook for delegation: %w", err)
		}
	}
	if err := safefile.ProtectDirectory(paths.Root); err != nil {
		return fmt.Errorf("protect stable hook runtime directory: %w", err)
	}
	if err := safefile.ValidatePrivateDirectory(paths.Root); err != nil {
		return fmt.Errorf("validate stable hook runtime directory: %w", err)
	}

	temporary, digest, err := copyPrivateExecutable(paths, source, transactionID)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary) }()

	state := State{
		SchemaVersion:  SchemaVersion,
		Status:         StatusPublishing,
		RuntimeRoot:    filepath.Clean(paths.Root),
		LauncherPath:   filepath.Clean(paths.Launcher),
		LauncherSHA256: digest,
		DataRoot:       dataRoot,
		GatewayPath:    gatewayPath,
		GatewaySHA256:  gatewayDigest,
		TransactionID:  transactionID,
	}
	if delegating {
		state.LauncherKind = LauncherKindTrampoline
		state.HookPath = hookPath
		state.HookSHA256 = hookDigest
	}
	if err := writeState(paths, state); err != nil {
		return fmt.Errorf("publish stable hook runtime barrier: %w", err)
	}
	if err := safefile.ReplaceFile(temporary, paths.Launcher); err != nil {
		return fmt.Errorf("publish stable hook launcher: %w", err)
	}
	if err := safefile.ValidatePrivateFile(paths.Launcher); err != nil {
		return fmt.Errorf("validate published stable hook launcher: %w", err)
	}
	publishedDigest, err := fileSHA256(paths.Launcher)
	if err != nil {
		return fmt.Errorf("hash published stable hook launcher: %w", err)
	}
	if !strings.EqualFold(publishedDigest, digest) {
		return errors.New("published stable hook launcher digest changed")
	}
	state.Status = StatusActive
	if err := writeState(paths, state); err != nil {
		return fmt.Errorf("activate stable hook runtime: %w", err)
	}
	verified, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || !verified.Active() || verified.TransactionID != transactionID ||
		!samePath(verified.DataRoot, dataRoot) || !samePath(verified.GatewayPath, gatewayPath) ||
		!strings.EqualFold(verified.GatewaySHA256, gatewayDigest) ||
		(delegating && (!verified.DelegatesTo(hookPath) || !strings.EqualFold(verified.HookSHA256, hookDigest))) {
		if err == nil {
			err = errors.New("active state did not round-trip")
		}
		return fmt.Errorf("verify active stable hook runtime: %w", err)
	}
	return nil
}

func disableAt(paths Paths, transactionID string) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if !validTransactionID(transactionID) {
		return errors.New("stable hook runtime requires a valid setup transaction identity")
	}
	if _, err := os.Lstat(paths.Root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	// This is a writer owned by the native installer, not a reader consuming
	// trust. Repair a current-user-owned runtime DACL so ordinary permission
	// drift cannot strand uninstall; ProtectDirectory still rejects reparse
	// points and foreign ownership.
	if err := safefile.ProtectDirectory(paths.Root); err != nil {
		return fmt.Errorf("protect stable hook runtime directory: %w", err)
	}
	if err := safefile.ValidatePrivateDirectory(paths.Root); err != nil {
		return fmt.Errorf("validate stable hook runtime directory: %w", err)
	}
	previous, _, _ := readTrustedAt(paths, paths.Launcher)
	if _, err := os.Lstat(paths.Launcher); err == nil {
		if err := safefile.ProtectFileWhileInUse(paths.Launcher); err != nil {
			return fmt.Errorf("protect stable hook launcher before disable: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := safefile.ValidatePrivateFile(paths.Launcher); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No executable means no cached command can launch. Still publish a
			// disabled marker whose impossible all-zero digest prevents a launcher
			// copied into this path later from inheriting stale active state.
			return writeState(paths, State{
				SchemaVersion:  SchemaVersion,
				Status:         StatusDisabled,
				RuntimeRoot:    filepath.Clean(paths.Root),
				LauncherPath:   filepath.Clean(paths.Launcher),
				LauncherSHA256: strings.Repeat("0", 64),
				LauncherKind:   previous.LauncherKind,
				HookPath:       previous.HookPath,
				HookSHA256:     previous.HookSHA256,
				TransactionID:  transactionID,
			})
		}
		return fmt.Errorf("validate stable hook launcher before disable: %w", err)
	}
	digest, err := fileSHA256(paths.Launcher)
	if err != nil {
		return fmt.Errorf("hash stable hook launcher before disable: %w", err)
	}
	state := State{
		SchemaVersion:  SchemaVersion,
		Status:         StatusDisabled,
		RuntimeRoot:    filepath.Clean(paths.Root),
		LauncherPath:   filepath.Clean(paths.Launcher),
		LauncherSHA256: digest,
		LauncherKind:   previous.LauncherKind,
		HookPath:       previous.HookPath,
		HookSHA256:     previous.HookSHA256,
		TransactionID:  transactionID,
	}
	if err := writeState(paths, state); err != nil {
		return fmt.Errorf("disable stable hook runtime: %w", err)
	}
	verified, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || verified.Active() || verified.TransactionID != transactionID {
		if err == nil {
			err = errors.New("disabled state did not round-trip")
		}
		return fmt.Errorf("verify disabled stable hook runtime: %w", err)
	}
	return nil
}

func copyPrivateExecutable(paths Paths, source, transactionID string) (string, string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", "", fmt.Errorf("generate stable hook staging name: %w", err)
	}
	temporary := paths.Launcher + ".new." + transactionID + "." + hex.EncodeToString(suffix)
	target, err := safefile.CreateExclusive(temporary)
	if err != nil {
		return "", "", err
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		_ = target.Close()
		_ = os.Remove(temporary)
		return "", "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(target, hash), sourceFile)
	sourceCloseErr := sourceFile.Close()
	syncErr := target.Sync()
	targetCloseErr := target.Close()
	if err := errors.Join(copyErr, sourceCloseErr, syncErr, targetCloseErr); err != nil {
		_ = os.Remove(temporary)
		return "", "", fmt.Errorf("stage stable hook launcher: %w", err)
	}
	if err := safefile.ProtectFile(temporary); err != nil {
		_ = os.Remove(temporary)
		return "", "", err
	}
	if err := safefile.ValidatePrivateFile(temporary); err != nil {
		_ = os.Remove(temporary)
		return "", "", err
	}
	return temporary, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeState(paths Paths, state State) error {
	if err := state.Validate(paths); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return safefile.WritePrivate(paths.State, body)
}

func validatePaths(paths Paths) error {
	if strings.TrimSpace(paths.Root) == "" || strings.TrimSpace(paths.Launcher) == "" ||
		strings.TrimSpace(paths.State) == "" {
		return errors.New("stable hook runtime paths are incomplete")
	}
	if !filepath.IsAbs(paths.Root) || !samePath(filepath.Dir(paths.Launcher), paths.Root) ||
		!samePath(filepath.Dir(paths.State), paths.Root) || filepath.Base(paths.Launcher) != LauncherName ||
		filepath.Base(paths.State) != StateName {
		return errors.New("stable hook runtime paths are not canonical")
	}
	return nil
}

func validTransactionID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
