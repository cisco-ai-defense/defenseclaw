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
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// What the hook guardian finds changed between lifecycle runs, and the
// lifecycle puts back without a transaction (GAP-1178, GAP-1217, GAP-0680):
// a damaged hook binary (missing after an antivirus quarantine, empty after
// a crash during the package unpack, not executable, not owned by root, or
// not the recorded binary), with which every agent runs tool calls without
// DefenseClaw, and a DefenseClaw machine-policy drop-in that was edited or
// deleted. The guardian runs sandboxed and cannot write the install root or
// the lifecycle state on Linux, so it only notices them (TamperedFiles) and
// starts the config-apply job (RequestTamperRestore). That job's ensure
// restores them under the lifecycle lock before it checks for changes: the
// hook binary from the copy the lifecycle sealed when it committed the
// deployment, and the machine policy from the applied config.

// codeHookBinaryNotRestored warns that a damaged hook binary could not be
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

// The states of an installed hook binary that the lifecycle puts back from
// the sealed copy. A missing or non-executable binary cannot start, which
// Claude Code, Codex and most other agents treat as a non-blocking error;
// the agents start the hook through sh, which runs an empty file as an
// empty script that exits 0; and a binary another account owns, or one that
// is not the recorded binary, is not the hook DefenseClaw installed.
const (
	hookBinaryMissing       = "missing"
	hookBinaryNotRegular    = "not a regular file"
	hookBinaryEmpty         = "empty"
	hookBinaryNotExecutable = "not executable"
	hookBinaryNotRootOwned  = "not owned by root"
	hookBinaryHashMismatch  = "hash mismatch"
)

// hookBinaryDamage is why the installed hook binary is not the recorded
// binary every account can run.
type hookBinaryDamage struct {
	state  string
	detail string
}

// String reads after "<path> is".
func (d *hookBinaryDamage) String() string {
	switch {
	case d.state == hookBinaryHashMismatch:
		return "not the binary the deployment installed (hash mismatch: " + d.detail + ")"
	case d.detail == "":
		return d.state
	}
	return d.state + " (" + d.detail + ")"
}

// inspectHookBinary reports why the installed hook binary is not the
// recorded binary, or nil when it is or the record names none. A hash
// mismatch counts only while the gateway binary is still the recorded one
// and no transaction is pending: a package upgrade replaces the gateway
// with the hook and an interrupted transaction leaves the files of two
// deployments, which verify names, and an older sealed copy must not be put
// back over a newer package's hook.
func (e *Env) inspectHookBinary(record *Deployment) *hookBinaryDamage {
	if record == nil || record.Files[e.installedHookPath()] == "" {
		return nil
	}
	path := e.P(e.installedHookPath())
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &hookBinaryDamage{state: hookBinaryMissing}
	case err != nil || info.IsDir():
		return nil // verify names it
	case !info.Mode().IsRegular():
		return &hookBinaryDamage{state: hookBinaryNotRegular}
	case info.Size() == 0:
		return &hookBinaryDamage{state: hookBinaryEmpty, detail: "0 bytes"}
	case info.Mode().Perm()&0o111 != 0o111:
		return &hookBinaryDamage{state: hookBinaryNotExecutable, detail: fmt.Sprintf("mode %04o", info.Mode().Perm())}
	}
	if uid, _, err := e.OwnerOf(path); err == nil && uid != 0 {
		return &hookBinaryDamage{state: hookBinaryNotRootOwned, detail: fmt.Sprintf("uid %d", uid)}
	}
	want := record.Files[e.installedHookPath()]
	got, err := sha256File(path)
	if err != nil || got == want || !e.gatewayIsRecorded(record) {
		return nil
	}
	if pending, err := e.loadPending(); err != nil || pending != nil {
		return nil
	}
	return &hookBinaryDamage{state: hookBinaryHashMismatch, detail: "sha256 " + got + ", the deployment recorded " + want}
}

// gatewayIsRecorded reports whether the installed gateway binary is the one
// the deployment recorded, that is no package replaced it since.
func (e *Env) gatewayIsRecorded(record *Deployment) bool {
	gateway := filepath.Join(e.Layout.BinDir, binGateway)
	got, err := sha256File(e.P(gateway))
	return err == nil && record.Files[gateway] != "" && got == record.Files[gateway]
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
// when inspectHookBinary found it damaged, replacing what is there. The
// copy is written without execute permission, its SHA-256 is checked
// against the deployment record through the open file, and only then is it
// made executable (0755, root) and renamed into place, so bytes that are
// not the recorded binary never become runnable.
func (e *Env) restoreHookBinary(record *Deployment, damage *hookBinaryDamage) (bool, error) {
	if record == nil || damage == nil {
		return false, nil
	}
	want := record.Files[e.installedHookPath()]
	path := e.P(e.installedHookPath())
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
// and reports what it did. It reports whether it restored the binary. On
// Linux the new file is relabeled as a transaction relabels the install
// root, so SELinux-confined agents can still run it.
func (l *lifecycle) restoreTamperedHookBinary(ctx context.Context, record *Deployment) bool {
	env := l.env
	damage := env.inspectHookBinary(record)
	if damage != nil && l.opts.Reason == "package" && !env.gatewayIsRecorded(record) {
		// The package's own install run applies the binaries it placed. One
		// it left damaged fails the payload check, so the package manager or
		// MDM installs it again, instead of the run recording the newer
		// package with the older hook binary.
		damage = nil
	}
	restored, err := env.restoreHookBinary(record, damage)
	path := env.installedHookPath()
	if restored && env.GOOS == "linux" {
		if _, err := env.Runner.Run(ctx, "restorecon", env.P(path)); err != nil && !errors.Is(err, ErrCommandNotFound) {
			l.result.AddWarning("selinux_relabel", err.Error())
		}
	}
	switch {
	case err != nil:
		next := env.packageReinstallStep(record.ProductVersion)
		if record.Channel != ChannelPackage {
			next = "rerun with --payload <staged payload directory>"
		}
		l.result.AddWarning(codeHookBinaryNotRestored, fmt.Sprintf("%s is %s and was not put back: %v; %s", path, damage, err, next))
	case restored:
		l.result.Changes = append(l.result.Changes, fmt.Sprintf(
			"restored %s, which was %s, from the copy the lifecycle sealed when it committed the deployment (sha256 %s)", path, damage, record.Files[path]))
	}
	return restored
}

// restoreTamperedMachinePolicy puts DefenseClaw's machine policy back before
// ensure checks for changes, when the installed config is the applied one
// and a connector the deployment published has lost hook coverage or an
// owned drop-in changed bytes. It publishes what the last transaction published, as
// reconcile does, so the config-apply job the hook guardian starts for an
// edited or deleted drop-in restores it with no transaction and no service
// restart. A change of the covered connectors still takes the transaction.
func (l *lifecycle) restoreTamperedMachinePolicy(record *Deployment) bool {
	env := l.env
	raw, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil || sha256Bytes(raw) != record.ConfigSHA256 || len(record.MachinePolicyConnectors) == 0 {
		return false
	}
	validated, err := env.validateConfig(raw)
	if err != nil {
		return false
	}
	intended, err := env.MachinePolicy.Intended(validated.Loaded)
	if err != nil {
		return false
	}
	want := intersectSorted(record.MachinePolicyConnectors, intended)
	// Verify checks hook command coverage, but a narrowed Claude matcher can
	// leave those commands present while disabling the hook for other tools.
	// The guardian detects byte drift in the drop-ins DefenseClaw owns whole
	// (Claude Code and Copilot); use those same ownership records before
	// deciding that ensure is a no-op.
	tamperedDropIn := false
	if contains(want, enterprisepolicy.ConnectorClaudeCode) || contains(want, enterprisepolicy.ConnectorCopilot) {
		if manager, ok := env.MachinePolicy.(*policyManager); ok {
			if opts, err := manager.options(nil); err == nil {
				tamperedDropIn = len(enterprisepolicy.TamperedDropIns(opts)) != 0
			}
		}
	}
	result, err := env.MachinePolicy.Verify(validated.Loaded)
	if isCoded(err, codeMachinePolicy) || (sameStrings(coveredMachinePolicy(want, result), want) && missingClaudeVersionFloor(result) == "" && !tamperedDropIn) {
		return false
	}
	published, err := env.MachinePolicy.Publish(validated.Loaded)
	if isCoded(err, codeMachinePolicy) {
		return false
	}
	restored := false
	for _, state := range published.States {
		if state.Changed && contains(want, state.Connector) {
			l.result.Changes = append(l.result.Changes, fmt.Sprintf(
				"put back DefenseClaw's %s machine policy (%s), which was changed or removed after the last lifecycle run",
				state.Connector, strings.Join(state.Paths, ", ")))
			restored = true
		}
	}
	return restored
}

// TamperedFiles lists what the hook guardian finds changed since the last
// lifecycle run that ensure puts back: a damaged hook binary, and a
// DefenseClaw machine-policy drop-in whose bytes are not the ones the
// lifecycle published.
func (e *Env) TamperedFiles() []string {
	e.fillDefaults()
	var out []string
	if record, err := e.loadDeployment(); err == nil && e.inspectHookBinary(record) != nil {
		out = append(out, e.installedHookPath())
	}
	manager, ok := e.MachinePolicy.(*policyManager)
	if !ok {
		return out
	}
	opts, err := manager.options(nil)
	if err != nil {
		return out
	}
	for _, path := range enterprisepolicy.TamperedDropIns(opts) {
		if e.Root != "" {
			path = strings.TrimPrefix(path, e.Root)
		}
		out = append(out, path)
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
