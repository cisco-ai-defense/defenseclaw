// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookruntime defines the stable Windows hook-launcher location and
// its installer-owned activation state. Keeping this tiny contract outside the
// application install tree lets long-running agent clients safely retain a
// cached hook command across repair, upgrade, uninstall, and reinstall.
package hookruntime

import (
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

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	SchemaVersion = 1
	LauncherName  = "defenseclaw-hook.exe"
	StateName     = "hook-runtime-state.json"

	StatusPublishing = "publishing"
	StatusActive     = "active"
	StatusDisabled   = "disabled"

	maxStateBytes = 64 << 10
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
	DataRoot       string `json:"data_root,omitempty"`
	TransactionID  string `json:"transaction_id"`
}

func (state State) Active() bool { return state.Status == StatusActive }

// Publish atomically refreshes the stable launcher and activates it for the
// committed native-setup transaction. The publishing state is made visible
// before the executable changes, so a hook process can observe either a fully
// verified old generation, an intentional no-op, or the fully verified new
// generation -- never a new executable paired with stale activation data.
func Publish(source, dataRoot, transactionID string) error {
	paths, err := CurrentUserPaths()
	if err != nil {
		return err
	}
	return publishAt(paths, source, dataRoot, transactionID)
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
	return disableAt(paths, transactionID)
}

// Validate checks the serialized state contract without consulting mutable
// process environment. File ownership and DACL validation are performed by
// ReadTrustedForExecutable before a launcher consumes the result.
func (state State) Validate(paths Paths) error {
	if state.SchemaVersion != SchemaVersion {
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
	if state.Status == StatusActive {
		if !filepath.IsAbs(state.DataRoot) || filepath.Clean(state.DataRoot) != state.DataRoot {
			return errors.New("active hook runtime state has an invalid data root")
		}
	}
	return nil
}

// ReadTrustedForExecutable identifies the canonical stable launcher and, only
// for that path, reads its private activation state. recognized remains true
// when state is absent or unsafe so the caller can fail closed to a no-op
// instead of falling back to project-controlled environment.
func ReadTrustedForExecutable(executable string) (state State, recognized bool, err error) {
	paths, err := CurrentUserPaths()
	if err != nil || strings.TrimSpace(paths.Launcher) == "" {
		return State{}, false, err
	}
	return readTrustedAt(paths, executable)
}

func readTrustedAt(paths Paths, executable string) (state State, recognized bool, err error) {
	if !samePath(executable, paths.Launcher) {
		return State{}, false, nil
	}
	recognized = true
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

func publishAt(paths Paths, source, dataRoot, transactionID string) error {
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
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect packaged hook launcher: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("packaged hook launcher is not a regular file: %s", source)
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
		TransactionID:  transactionID,
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
		!samePath(verified.DataRoot, dataRoot) {
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
	if _, err := os.Lstat(paths.Launcher); err == nil {
		if err := safefile.ProtectFile(paths.Launcher); err != nil {
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
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil &&
		strings.EqualFold(filepath.Clean(leftAbs), filepath.Clean(rightAbs))
}
