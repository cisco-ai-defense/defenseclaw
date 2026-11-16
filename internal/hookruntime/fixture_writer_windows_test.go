// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

// The stable hook runtime has no production writer in 1.0: only the per-user
// DefenseClaw Setup 0.8.x published and disabled it, and install.ps1 retargets
// an imported runtime with its own PowerShell writer. The reader side
// (readTrustedAt, Delegate, LockVerifiedHook, LockVerifiedGateway) stays live
// for those imported installs, so its tests build their state with this
// test-only copy of the 0.8.x writer.

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
	if err := protectInstalledGateway(gatewayPath); err != nil {
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

// protectInstalledGateway applies the private gateway DACL. The image can
// still be mapped by a gateway that is exiting, held by a hook cold start's
// read-only lock, or opened by an antivirus scan, and each of those denies the
// read/write open safefile.ProtectFile uses. A current-user-owned image is
// therefore protected through one share-all handle that needs only DACL
// access. An image that needs an owner repair keeps the ProtectFile path,
// which is the only one allowed to change the owner.
func protectInstalledGateway(path string) error {
	if err := safefile.ValidatePrivateFileOwnership(path); err != nil {
		return safefile.ProtectFile(path)
	}
	return safefile.ProtectFileWhileInUse(path)
}
