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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// codeDiskSpaceLow names a nearly full filesystem under the gateway's audit
// database or logs.
const codeDiskSpaceLow = "disk_space_low"

// diskSpaceLowBytes and diskSpaceLowPercent are the warning thresholds: less
// than 256 MiB, or less than 2% of the filesystem, available.
const (
	diskSpaceLowBytes   = 256 << 20
	diskSpaceLowPercent = 2
)

// diskSpace reports the bytes available to unprivileged writers, the size
// and the device of the filesystem holding path.
func diskSpace(path string) (avail, total, device uint64, err error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, 0, 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, 0, 0, err
	}
	block := uint64(fs.Bsize)
	return uint64(fs.Bavail) * block, uint64(fs.Blocks) * block, uint64(st.Dev), nil
}

// warnLowDiskSpace warns when the filesystem holding the audit database or
// the logs is nearly full. Enforcement holds on a full disk, but nothing an
// administrator reads said so before the audit trail stopped (GAP-0514).
func (l *lifecycle) warnLowDiskSpace() {
	env := l.env
	seen := map[uint64]bool{}
	for _, dir := range []string{env.Layout.DataDir, env.Layout.LogDir} {
		avail, total, device, err := env.DiskSpace(env.P(dir))
		if err != nil || total == 0 || seen[device] {
			continue
		}
		seen[device] = true
		if avail >= diskSpaceLowBytes && avail*100 >= total*diskSpaceLowPercent {
			continue
		}
		l.result.AddWarning(codeDiskSpaceLow, fmt.Sprintf("the filesystem holding %s has %.1f MiB free (%.1f%%): enforcement continues, but the audit database and logs stop recording when it fills; free space on it",
			dir, float64(avail)/(1<<20), float64(avail)*100/float64(total)))
	}
}

// codeDiskFull names the filesystem a failed transaction ran out of space
// on. It follows the error of the step that failed, whose code callers
// already match, so the result says the disk is the cause.
const codeDiskFull = "disk_full"

// diskFullBytes is the free space below which a failed transaction names a
// filesystem it writes as the likely cause. The services write their state
// as they start, and on a filesystem this full they fail before verify sees
// them active: ensure then reported only that the services were not active
// (GAP-0662).
const diskFullBytes = 16 << 20

// transactionDirs are the directories a lifecycle transaction and the
// services it starts write.
func (l *lifecycle) transactionDirs() []string {
	layout := l.env.Layout
	return []string{
		layout.LifecycleDir, layout.DataDir, layout.LogDir, layout.GuardianAuthDir,
		layout.ConfigDir, layout.InstallRoot, layout.HookSocketDir, layout.SensorSocketDir,
	}
}

// noSpace reports an error that a full filesystem or an exhausted quota
// caused, also one wrapped as text only.
func noSpace(err error) bool {
	return err != nil && (errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) ||
		strings.Contains(err.Error(), syscall.ENOSPC.Error()))
}

// stateWriteCode is the code of a state write that failed: codeDiskFull when
// the filesystem or quota is full, code otherwise. A full disk read as
// bundle_state_unreadable or state_unreadable, a read problem, although
// the write was what failed (GAP-0609).
func stateWriteCode(err error, code string) string {
	if noSpace(err) {
		return codeDiskFull
	}
	return code
}

// stateWriteAction is the next step for a state write that failed for lack
// of space, appended to its message, and "" for any other failure.
func stateWriteAction(err error) string {
	if noSpace(err) {
		return "; free space on that filesystem and run the command again"
	}
	return ""
}

// failedWritePath is the path the failed operation in err named, or "".
func failedWritePath(err error) string {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.New
	}
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Path
	}
	return ""
}

// diskSpaceOf is DiskSpace of the nearest existing directory holding path
// (a file the failed write could not create does not exist).
func (l *lifecycle) diskSpaceOf(path string) (avail, total, device uint64, ok bool) {
	for dir := path; ; dir = filepath.Dir(dir) {
		if avail, total, device, err := l.env.DiskSpace(dir); err == nil && total > 0 {
			return avail, total, device, true
		}
		if parent := filepath.Dir(dir); parent == dir {
			return 0, 0, 0, false
		}
	}
}

// canonicalPath is path without the test root (Env.P).
func (l *lifecycle) canonicalPath(path string) string {
	if root := l.env.Root; root != "" {
		if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
			return string(filepath.Separator) + rel
		}
	}
	return path
}

// reportDiskFull adds codeDiskFull to a failed transaction: the path a write
// failed on for lack of space, and each filesystem the transaction writes
// with less than diskFullBytes free. A disk filled during the run made the
// services stop before verify, and ensure reported only verify_failed with
// the services not active, naming neither the condition nor the path
// (GAP-0662).
func (l *lifecycle) reportDiskFull(cause error) {
	var problems []string
	seen := map[uint64]bool{}
	if noSpace(cause) {
		if path := failedWritePath(cause); path != "" {
			problem := "no space left on the filesystem holding " + l.canonicalPath(path)
			if avail, total, device, ok := l.diskSpaceOf(path); ok {
				seen[device] = true
				problem += fmt.Sprintf(" (%s free of %s)", formatDiskBytes(avail), formatDiskBytes(total))
			}
			problems = append(problems, problem)
		} else {
			problems = append(problems, "a write failed with no space left on device")
		}
	}
	for _, dir := range l.transactionDirs() {
		if dir == "" {
			continue
		}
		avail, total, device, ok := l.diskSpaceOf(l.env.P(dir))
		if !ok || seen[device] || avail >= diskFullBytes {
			continue
		}
		seen[device] = true
		problems = append(problems, fmt.Sprintf("the filesystem holding %s has %s free of %s", dir, formatDiskBytes(avail), formatDiskBytes(total)))
	}
	if len(problems) == 0 {
		return
	}
	l.result.AddError(codeDiskFull, strings.Join(problems, "; ")+
		": the transaction and the services it starts cannot write their state on a full disk; free space on it and run "+
		l.opts.Action+" again")
}

// reportNoSpace adds codeDiskFull to a run refused before its transaction
// started (the lifecycle directory, the lock or the plan) only when the
// write failed for lack of space: a refusal of the config is not blamed on
// a nearly full disk.
func (l *lifecycle) reportNoSpace(err error) {
	if noSpace(err) {
		l.reportDiskFull(err)
	}
}

// formatDiskBytes prints a free-space figure in KiB below 1 MiB, in MiB
// below 1 GiB and in GiB above.
func formatDiskBytes(n uint64) string {
	switch {
	case n < 1<<20:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	case n < 1<<30:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
}
