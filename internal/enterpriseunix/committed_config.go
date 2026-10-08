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
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The documented config flow has the MDM write config.yaml in place and the
// apply trigger run ensure. The gateway follows that file directly, and the
// transaction snapshot of an in-place edit already holds the edited bytes,
// so without a copy of the last applied config a rejected edit would stay
// live (or go live on the next gateway restart) with nothing to return to.
// The lifecycle therefore keeps a root-only copy of the config each
// committed transaction applied, and puts it back when a run rejects an
// in-place edit; the rejected file is kept next to it for the administrator.
//
// The kept rejected file is also the record that the administrator's
// config is not the one running: status warns and verify fails with
// config_rejected while it is current. It stops being current once
// config.yaml is written again after the revert (a corrected push, or the
// last applied config pushed back) and a run applies or confirms it, or a
// run applies an explicit --config. The revert stamps the kept file with
// the reverted config.yaml's modification time, so the apply trigger the
// revert itself fires does not count as a new push.
const (
	committedConfigName = "committed-config.yaml"
	rejectedConfigName  = "rejected-config.yaml"
	// rejectedReasonName keeps the first error of the run that rejected an
	// in-place edit, so status and verify can name it (GAP-0587).
	rejectedReasonName = "rejected-config.reason"
	codeConfigReverted = "config_reverted"
	codeConfigRejected = "config_rejected"
)

func (e *Env) committedConfigPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), committedConfigName)
}

func (e *Env) rejectedConfigPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), rejectedConfigName)
}

func (e *Env) rejectedReasonPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), rejectedReasonName)
}

// removeRejectedConfig drops the kept rejected edit and its reason.
func (e *Env) removeRejectedConfig() {
	_ = removeFile(e.rejectedConfigPath())
	_ = removeFile(e.rejectedReasonPath())
}

// saveCommittedConfig records the config a committed transaction applied.
func (e *Env) saveCommittedConfig(raw []byte) error {
	return e.writeFileAtomic(e.committedConfigPath(), raw, 0o600, rootOwner())
}

// inPlaceConfigEdit returns the last applied config when this run takes
// its config from an installed config.yaml that differs from the one the
// record says was applied, and a copy of that applied config exists.
func (l *lifecycle) inPlaceConfigEdit(record *Deployment) []byte {
	env := l.env
	if record == nil || l.opts.ConfigFile != "" {
		return nil
	}
	current, err := sha256File(env.P(env.Layout.ConfigPath))
	if err != nil || current == record.ConfigSHA256 {
		return nil
	}
	committed, err := readBounded(env.committedConfigPath(), maxInputBytes)
	if err != nil || sha256Bytes(committed) != record.ConfigSHA256 {
		return nil
	}
	return committed
}

// revertRejectedConfig puts the last applied config back in place of a
// rejected in-place edit and keeps the rejected bytes for the
// administrator. planned are the bytes this run applied, when it got as far
// as planning. When config.yaml holds other bytes by now, configuration
// management wrote a newer file during the run: the kept file is the planned
// edit, not the newer one nobody checked, and the newer bytes are returned
// so the caller puts them back once the rollback restart is done and the
// apply trigger applies them in their own transaction.
func (l *lifecycle) revertRejectedConfig(record *Deployment, committed, planned []byte) (newer []byte) {
	env, r := l.env, l.result
	rejected := planned
	if current, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes); err == nil {
		if planned == nil {
			rejected = current
		} else if sha256Bytes(current) != sha256Bytes(planned) {
			newer = current
		}
	}
	if rejected != nil {
		if err := env.writeFileAtomic(env.rejectedConfigPath(), rejected, 0o600, rootOwner()); err != nil {
			r.AddWarning(codeConfigReverted, "could not keep a copy of the rejected config: "+err.Error())
		}
		_ = removeFile(env.rejectedReasonPath())
		if len(r.Errors) > 0 {
			reason := r.Errors[0].Code + ": " + r.Errors[0].Message
			if len(reason) > 600 {
				reason = reason[:600] + "..."
			}
			_ = env.writeFileAtomic(env.rejectedReasonPath(), []byte(reason), 0o600, rootOwner())
		}
	}
	owner := fileOwner{UID: 0, GID: record.ServiceGID}
	if err := env.writeFileAtomic(env.P(env.Layout.ConfigPath), committed, 0o640, owner); err != nil {
		r.AddWarning(codeConfigReverted, "the rejected config.yaml is still in place; restoring the last applied config failed: "+err.Error())
		return nil
	}
	if reverted, err := os.Stat(env.P(env.Layout.ConfigPath)); err == nil {
		_ = os.Chtimes(env.rejectedConfigPath(), reverted.ModTime(), reverted.ModTime())
	}
	kept := filepath.Join(env.Layout.LifecycleDir, rejectedConfigName)
	if newer != nil {
		r.AddWarning(codeConfigReverted, "the config.yaml edit this run applied was not applied and is kept at "+kept+"; config.yaml was written again during the run, and that newer file is put back after the rollback to be applied next")
		return newer
	}
	r.AddWarning(codeConfigReverted, "config.yaml was not applied; the last applied config is back in place and the rejected file is kept at "+kept)
	return nil
}

// restoreNewerConfig puts back a config.yaml written during a run whose
// in-place edit was rejected and reverted (revertRejectedConfig), after the
// rollback restarted the previous deployment. inputsChanged then sees it and
// the apply trigger runs ensure for it once this run ends.
func (l *lifecycle) restoreNewerConfig(record *Deployment, newer []byte) {
	env, r := l.env, l.result
	owner := fileOwner{UID: 0, GID: record.ServiceGID}
	if err := env.writeFileAtomic(env.P(env.Layout.ConfigPath), newer, 0o640, owner); err != nil {
		r.AddWarning(codeConfigReverted, "the config.yaml written during this run could not be put back ("+err.Error()+"); the last applied config is in place, push the newer config.yaml again")
		return
	}
	// The newer file supersedes the kept rejection (rejectionSuperseded),
	// also when it lands in the same file-time tick as the revert.
	current, err := os.Stat(env.P(env.Layout.ConfigPath))
	if kept, keptErr := os.Stat(env.rejectedConfigPath()); err == nil && keptErr == nil && kept.ModTime().Equal(current.ModTime()) {
		earlier := current.ModTime().Add(-time.Second)
		_ = os.Chtimes(env.rejectedConfigPath(), earlier, earlier)
	}
}

// rejectedConfigProblem describes a rejected in-place edit that is still
// current, or returns "".
func (e *Env) rejectedConfigProblem() string {
	rejected, err := os.Stat(e.rejectedConfigPath())
	if err != nil || e.rejectionSuperseded(rejected) {
		return ""
	}
	// The run may have failed for a reason other than the file (a service
	// that did not start), so the hint does not call the file invalid.
	why := "the lifecycle log says why"
	if reason, err := readBounded(e.rejectedReasonPath(), 4096); err == nil && len(reason) > 0 {
		why = string(reason)
	}
	return fmt.Sprintf("the config.yaml edit rejected at %s is not applied: the run that applied it failed (%s), the last applied config is in place and the rejected file is kept at %s. Write config.yaml again, even unchanged, to retry it, or push a corrected one",
		rejected.ModTime().UTC().Format(time.RFC3339), why, filepath.Join(e.Layout.LifecycleDir, rejectedConfigName))
}

// rejectionSuperseded reports whether config.yaml was written after the
// revert that kept rejected.
func (e *Env) rejectionSuperseded(rejected os.FileInfo) bool {
	current, err := os.Stat(e.P(e.Layout.ConfigPath))
	return err != nil || !current.ModTime().Equal(rejected.ModTime())
}

// settleRejectedConfig drops the kept rejected edit once a run has applied
// or confirmed a config that supersedes it: an explicit --config, or a
// config.yaml written after the revert.
func (l *lifecycle) settleRejectedConfig() {
	env := l.env
	rejected, err := os.Stat(env.rejectedConfigPath())
	if err != nil {
		return
	}
	if l.opts.ConfigFile != "" || env.rejectionSuperseded(rejected) {
		env.removeRejectedConfig()
	}
}
