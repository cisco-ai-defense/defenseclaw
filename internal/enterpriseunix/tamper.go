// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// What the hook guardian finds changed between lifecycle runs, and the
// lifecycle puts back without a transaction (GAP-1217): a missing hook
// binary (an antivirus quarantine), which every agent treats as a
// non-blocking hook error and so runs tool calls without DefenseClaw. The
// guardian runs sandboxed and cannot write the install root on Linux, so it
// only notices it (TamperedFiles) and starts the config-apply job
// (RequestTamperRestore). That job's ensure restores it under the lifecycle
// lock before it checks for changes, from the copy the lifecycle sealed when
// it committed the deployment.

// codeHookBinaryNotRestored warns that a missing hook binary could not be
// put back from the sealed copy.
const codeHookBinaryNotRestored = "hook_binary_not_restored"

// maxSealedBinaryBytes bounds the sealed hook binary.
const maxSealedBinaryBytes = 512 << 20

// installedHookPath is the hook binary every vendor policy names.
func (e *Env) installedHookPath() string {
	return filepath.Join(e.Layout.BinDir, binHook)
}

// sealedHookPath is the root-only copy of the installed hook binary next
// to the deployment record.
func (e *Env) sealedHookPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), "sealed", binHook)
}

// sealHookBinary keeps the sealed copy current while the installed hook
// binary is the one the record names. It runs after every committed
// transaction and on a no-op ensure (a deployment from before the copy).
func (e *Env) sealHookBinary(record *Deployment) error {
	if record == nil {
		return nil
	}
	want := record.Files[e.installedHookPath()]
	if want == "" {
		return nil
	}
	if got, err := sha256File(e.sealedHookPath()); err == nil && got == want {
		return nil
	}
	if got, err := sha256File(e.P(e.installedHookPath())); err != nil || got != want {
		return err
	}
	if err := e.ensureDir(filepath.Dir(e.sealedHookPath()), 0o700, rootOwner()); err != nil {
		return err
	}
	return e.copyFileAtomic(e.P(e.installedHookPath()), e.sealedHookPath(), 0o600, rootOwner())
}

// sealedHookValid reports whether the sealed copy is the recorded binary.
func (e *Env) sealedHookValid(record *Deployment) bool {
	want := ""
	if record != nil {
		want = record.Files[e.installedHookPath()]
	}
	got, err := sha256File(e.sealedHookPath())
	return want != "" && err == nil && got == want
}

// restoreHookBinary puts the recorded hook binary back from the sealed copy
// when it is missing. The copy is written without execute permission, its
// SHA-256 is checked against the deployment record through the open file,
// and only then is it made executable and renamed into place, so bytes that
// are not the recorded binary never become runnable.
func (e *Env) restoreHookBinary(record *Deployment) (bool, error) {
	if record == nil {
		return false, nil
	}
	want := record.Files[e.installedHookPath()]
	path := e.P(e.installedHookPath())
	if _, err := os.Lstat(path); want == "" || !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	in, err := os.OpenFile(e.sealedHookPath(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, errors.New("the lifecycle keeps no copy of it")
	}
	if err != nil {
		return false, err
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil || !info.Mode().IsRegular() {
		return false, errors.New("the lifecycle's copy of it is not a regular file")
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+binHook+".dc-"+hex.EncodeToString(suffix))
	out, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	if n, err := io.Copy(out, io.LimitReader(in, maxSealedBinaryBytes+1)); err != nil || n > maxSealedBinaryBytes {
		return false, fmt.Errorf("copy the lifecycle's copy of it: %v", err)
	}
	if err := out.Sync(); err != nil {
		return false, err
	}
	hash := sha256.New()
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := io.Copy(hash, out); err != nil {
		return false, err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != want {
		return false, fmt.Errorf("the lifecycle's copy of it (sha256 %s) is not the binary the deployment recorded (sha256 %s)", got, want)
	}
	if err := out.Chmod(0o755); err != nil {
		return false, err
	}
	if err := out.Close(); err != nil {
		return false, err
	}
	if err := e.Lchown(tmp, 0, 0); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	committed = true
	syncDir(dir)
	return true, nil
}

// restoreTamperedHookBinary runs restoreHookBinary for a lifecycle action
// and reports what it did. It reports whether it restored the binary.
func (l *lifecycle) restoreTamperedHookBinary(record *Deployment) bool {
	env := l.env
	restored, err := env.restoreHookBinary(record)
	path := env.installedHookPath()
	switch {
	case err != nil:
		next := env.packageReinstallStep(record.ProductVersion)
		if record.Channel != ChannelPackage {
			next = "rerun with --payload <staged payload directory>"
		}
		l.result.AddWarning(codeHookBinaryNotRestored, fmt.Sprintf("%s is missing and was not put back: %v; %s", path, err, next))
	case restored:
		l.result.Changes = append(l.result.Changes, fmt.Sprintf(
			"restored the missing %s from the copy the lifecycle sealed when it committed the deployment (sha256 %s)", path, record.Files[path]))
	}
	return restored
}

// TamperedFiles lists what the hook guardian finds changed since the last
// lifecycle run that ensure puts back: a missing hook binary.
func (e *Env) TamperedFiles() []string {
	e.fillDefaults()
	var out []string
	if _, err := os.Lstat(e.P(e.installedHookPath())); errors.Is(err, os.ErrNotExist) {
		if record, err := e.loadDeployment(); err == nil && record != nil && record.Files[e.installedHookPath()] != "" {
			out = append(out, e.installedHookPath())
		}
	}
	return out
}

// RequestTamperRestore starts the config-apply job without waiting for it;
// its ensure restores what TamperedFiles lists.
func (e *Env) RequestTamperRestore(ctx context.Context) error {
	e.fillDefaults()
	var err error
	switch e.GOOS {
	case "linux":
		_, err = e.Runner.Run(ctx, "systemctl", "start", "--no-block", unitApplyService)
	case "darwin":
		_, err = e.Runner.Run(ctx, "launchctl", "kickstart", "system/"+labelApply)
	}
	return err
}

// RepairCommand is the lifecycle repair command line of this host.
func (e *Env) RepairCommand() string {
	return e.lifecycleCommand(ActionRepair)
}
