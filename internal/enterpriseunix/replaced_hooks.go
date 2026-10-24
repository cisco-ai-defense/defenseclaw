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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The replaced release's managed shell hooks (GAP-1123). A 1.0.3 managed
// shell hook bakes the administrator's fail mode and, under open, lets a
// call run when it cannot reach the gateway; it does not read the lifecycle
// run marker, so a call could run while this run had the gateway stopped,
// until the guardian rendered this release's hooks after the new gateway
// was ready. Those hooks cannot change, but each one sources the
// _hardening.sh of its hook folder when it starts and decides an
// unreachable gateway through defenseclaw_should_fail_closed_on_unreachable,
// which that file defines. Before it stops the gateway, the run therefore
// replaces each enrolled account's _hardening.sh that does not read the
// marker itself with the same bytes and a fence: the function answers
// closed while the marker exists, and as before once it is gone. A hook
// that starts from then on is fenced. It then waits, for at most
// replacedHookCallsBudget, for the hook processes that started before the
// fence (they still run the unfenced function) while the gateway still
// answers them. Those still running are reported. The guardian renders
// this release's hooks, the fence included, after the run.
const (
	codeReplacedHooks = "replaced_hooks_not_fenced"
	// codeReplacedHookCalls names hook calls of the replaced release that
	// were still running when the run stopped the gateway.
	codeReplacedHookCalls = "replaced_hook_calls_running"

	// replacedHookCallsBudget is the longest hook timeout DefenseClaw
	// registers with an agent (Claude Code's 90 s Stop, SubagentStop and
	// PostToolBatch hooks; tool calls have 30 s at most), with 30 s for the
	// agent's own launch delay: an agent ends a hook it registered by then.
	replacedHookCallsBudget = 120 * time.Second

	hardeningFile = "_hardening.sh"
	// hardeningMaxBytes bounds the _hardening.sh a run reads (it is about
	// 80 KiB).
	hardeningMaxBytes = 4 << 20
	// lifecycleMarkerReader is defined by every _hardening.sh that reads
	// the lifecycle run marker itself (1.0.4 and later).
	lifecycleMarkerReader = "defenseclaw_managed_lifecycle_held()"
	// lifecycleFenceTag starts the fence a run appends.
	lifecycleFenceTag = "# defenseclaw-lifecycle-fence v1"
)

// lifecycleFence is the fence appended to a replaced release's
// _hardening.sh, for the platform's lifecycle run marker. While the marker
// exists it answers a gateway the hook cannot reach closed
// (defenseclaw_should_fail_closed_on_unreachable), turns the hook's open
// into closed when it logs a delivery failure (a reply that is no answer,
// which the replaced hooks decide by FAIL_MODE itself), and answers a
// Copilot CLI failure with Copilot's deny (the 1.0.2 Copilot hook allowed
// every failed call, whatever its fail mode).
// Each function keeps its replaced body for when the marker is gone.
func lifecycleFence(marker string) string {
	quoted := "'" + strings.ReplaceAll(marker, "'", `'\''`) + "'"
	return "\n" + lifecycleFenceTag + `: added by the DefenseClaw enterprise lifecycle before it
# stopped the gateway. While its run marker exists, a hook that cannot get an
# answer from the gateway answers closed; the guardian renders this file again
# after the run.
_dc_lifecycle_held() {
  [ -e ` + quoted + ` ] || [ -L ` + quoted + ` ]
}
if declare -F defenseclaw_should_fail_closed_on_unreachable >/dev/null 2>&1; then
  eval "_dc_unfenced_$(declare -f defenseclaw_should_fail_closed_on_unreachable)"
  defenseclaw_should_fail_closed_on_unreachable() {
    _dc_lifecycle_held && return 0
    _dc_unfenced_defenseclaw_should_fail_closed_on_unreachable "$@"
  }
fi
if declare -F defenseclaw_log_hook_failure >/dev/null 2>&1; then
  eval "_dc_unfenced_$(declare -f defenseclaw_log_hook_failure)"
  defenseclaw_log_hook_failure() {
    if [ "$#" -ge 5 ] && _dc_lifecycle_held; then
      [ "${FAIL_MODE:-}" = closed ] || FAIL_MODE=closed
      set -- "$1" "$2" "$3" "$4" closed "${@:6}"
      if [ "$1" = copilot ]; then
        _dc_unfenced_defenseclaw_log_hook_failure "$@"
        printf '%s\n' '{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw is being installed or upgraded on this computer; try again in a moment"}'
        exit 0
      fi
    fi
    _dc_unfenced_defenseclaw_log_hook_failure "$@"
  }
fi
if declare -F defenseclaw_log_hook_delivery_failure >/dev/null 2>&1; then
  eval "_dc_unfenced_$(declare -f defenseclaw_log_hook_delivery_failure)"
  defenseclaw_log_hook_delivery_failure() {
    if [ "$#" -ge 5 ] && _dc_lifecycle_held; then
      [ "${FAIL_MODE:-}" = closed ] || FAIL_MODE=closed
      set -- "$1" "$2" "$3" "$4" closed "${@:6}"
    fi
    _dc_unfenced_defenseclaw_log_hook_delivery_failure "$@"
  }
fi
`
}

// replacedHookFolder is an enrolled account's hook folder whose
// _hardening.sh is the replaced release's (fenced now or by an earlier run).
type replacedHookFolder struct {
	user string
	uid  int
	path string
}

// fenceReplacedHooks fences the replaced release's shell hooks of every
// enrolled account and waits for their calls already running. It runs
// once, just before the run first stops the gateway.
func (l *lifecycle) fenceReplacedHooks(ctx context.Context) {
	env := l.env
	if l.replacedHooksFenced || env.Layout.LifecycleMarkerPath == "" {
		return
	}
	l.replacedHooksFenced = true
	targets := l.replacedHookTargets()
	if len(targets) == 0 {
		return
	}
	fencedAt := env.Now()
	fence := lifecycleFence(env.Layout.LifecycleMarkerPath)
	var folders []replacedHookFolder
	for _, target := range targets {
		replaced, err := fenceHardeningBounded(env.P(target.home), target.rel, target.uid, fence)
		if err != nil {
			l.result.AddWarning(codeReplacedHooks, fmt.Sprintf("the DefenseClaw hooks of user %s (%s) were not fenced for the gateway restart: %v; "+
				"a hook of the replaced release there follows its fail mode while the gateway is stopped", target.user, target.folder(), err))
			continue
		}
		if replaced {
			folders = append(folders, replacedHookFolder{user: target.user, uid: target.uid, path: target.folder()})
		}
	}
	if len(folders) == 0 {
		return
	}
	running := l.waitForReplacedHookCalls(ctx, folders, fencedAt)
	if len(running) == 0 {
		return
	}
	l.result.AddWarning(codeReplacedHookCalls, fmt.Sprintf("hook calls of the replaced release were still running %s after their hooks were fenced, and the gateway was stopped: %s; "+
		"a call such a hook sends before the new gateway answers follows the replaced release's fail mode",
		env.ReplacedHookCallsTimeout, strings.Join(running, ", ")))
}

// replacedHookTarget is one hook folder of an enrolled account, below its
// home.
type replacedHookTarget struct {
	user string
	uid  int
	home string
	rel  string
}

func (t replacedHookTarget) folder() string { return filepath.Join(t.home, t.rel) }

// replacedHookTargets are the hook folders of the guardian manifest's
// accounts: the target's data_dir, by default ~/.defenseclaw, and its hooks
// folder.
func (l *lifecycle) replacedHookTargets() []replacedHookTarget {
	env := l.env
	manifest, err := enterprisehooks.LoadStandaloneManifest(env.P(env.Layout.ManifestPath))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			l.result.AddWarning(codeReplacedHooks, "the enrolled accounts' DefenseClaw hooks were not fenced for the gateway restart: read "+env.Layout.ManifestPath+": "+err.Error())
		}
		return nil
	}
	homes := map[int]string{}
	for _, account := range env.sessionFactsAccounts() {
		homes[account.uid] = account.home
	}
	seen := map[string]bool{}
	var out []replacedHookTarget
	for _, target := range manifest.Targets {
		if target.UID == nil || *target.UID <= 0 {
			continue
		}
		uid := *target.UID
		home := filepath.Clean(strings.TrimSpace(target.UserHome))
		if strings.TrimSpace(target.UserHome) == "" {
			home = homes[uid]
		}
		if !filepath.IsAbs(home) || home == "/" {
			continue
		}
		rel := filepath.Join(".defenseclaw", "hooks")
		if dataDir := strings.TrimSpace(target.DataDir); dataDir != "" {
			inner, err := filepath.Rel(home, filepath.Clean(dataDir))
			if err != nil || inner == "." || inner == ".." || strings.HasPrefix(inner, "../") || filepath.IsAbs(inner) {
				l.result.AddWarning(codeReplacedHooks, fmt.Sprintf("the DefenseClaw hooks of user %s were not fenced for the gateway restart: its data_dir %s is not below its home %s", target.User, dataDir, home))
				continue
			}
			rel = filepath.Join(inner, "hooks")
		}
		key := strconv.Itoa(uid) + "\x00" + filepath.Join(home, rel)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, replacedHookTarget{user: target.User, uid: uid, home: home, rel: rel})
	}
	return out
}

// fenceHardeningBounded is fenceHardening with a deadline: a home that
// does not answer (a hard-mounted network home whose server is gone) is
// reported instead of holding the run.
func fenceHardeningBounded(home, rel string, uid int, fence string) (bool, error) {
	type outcome struct {
		replaced bool
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		replaced, err := fenceHardening(home, rel, uid, fence)
		done <- outcome{replaced, err}
	}()
	select {
	case result := <-done:
		return result.replaced, result.err
	case <-time.After(enterprisehooks.UnixHomeCheckTimeout):
		return false, fmt.Errorf("the home did not answer within %s", enterprisehooks.UnixHomeCheckTimeout)
	}
}

// fenceHardening appends fence to home/rel/_hardening.sh when that file is
// a replaced release's (it does not read the lifecycle marker itself). The
// new bytes go to a new file in the same folder, which is then renamed over
// the old one, so a hook that starts sources either the old or the fenced
// file whole. It runs as root in a home the account controls: every folder
// is opened without following a symlink and must belong to uid, the file
// must be a regular file uid owns, and the writes go through the opened
// folder. replaced reports a replaced release's file (fenced now or
// before); a folder or file that does not exist is not one.
func fenceHardening(home, rel string, uid int, fence string) (replaced bool, err error) {
	dirFD, err := openOwnedDir(unix.AT_FDCWD, home, uid)
	if err != nil || dirFD < 0 {
		return false, err
	}
	for _, name := range strings.Split(filepath.ToSlash(rel), "/") {
		next, err := openOwnedDir(dirFD, name, uid)
		_ = unix.Close(dirFD)
		if err != nil || next < 0 {
			return false, err
		}
		dirFD = next
	}
	defer unix.Close(dirFD)
	fd, err := unix.Openat(dirFD, hardeningFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return false, nil
	case errors.Is(err, unix.ELOOP):
		return false, fmt.Errorf("%s is a symlink, which is not followed", hardeningFile)
	case err != nil:
		return false, err
	}
	file := os.NewFile(uintptr(fd), hardeningFile)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid {
		return false, fmt.Errorf("%s is not a regular file the account owns", hardeningFile)
	}
	if st.Size > hardeningMaxBytes {
		return false, fmt.Errorf("%s is larger than %d bytes", hardeningFile, hardeningMaxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, hardeningMaxBytes+1))
	if err != nil {
		return false, err
	}
	if len(data) > hardeningMaxBytes {
		return false, fmt.Errorf("%s is larger than %d bytes", hardeningFile, hardeningMaxBytes)
	}
	switch {
	case bytes.Contains(data, []byte(lifecycleMarkerReader)):
		return false, nil
	case bytes.Contains(data, []byte(lifecycleFenceTag)):
		return true, nil
	}
	temp := fmt.Sprintf(".%s.fence-%d", hardeningFile, os.Getpid())
	_ = unix.Unlinkat(dirFD, temp, 0)
	out, err := unix.Openat(dirFD, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	written := os.NewFile(uintptr(out), temp)
	publish := func() error {
		if _, err := written.Write(append(append([]byte{}, data...), fence...)); err != nil {
			return err
		}
		if err := unix.Fchown(out, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
		if err := unix.Fchmod(out, uint32(st.Mode&0o7777)); err != nil {
			return err
		}
		if err := written.Sync(); err != nil {
			return err
		}
		if err := written.Close(); err != nil {
			return err
		}
		return unix.Renameat(dirFD, temp, dirFD, hardeningFile)
	}
	if err := publish(); err != nil {
		_ = written.Close()
		_ = unix.Unlinkat(dirFD, temp, 0)
		return false, err
	}
	return true, nil
}

// waitForReplacedHookCalls waits, for at most env.ReplacedHookCallsTimeout,
// until no process of an account runs a hook from its replaced hook folder
// that started before the fence (a second later: ps on macOS counts whole
// seconds). The gateway still answers them meanwhile. It returns those still
// running, as "user (pid N)".
func (l *lifecycle) waitForReplacedHookCalls(ctx context.Context, folders []replacedHookFolder, fencedAt time.Time) []string {
	env := l.env
	deadline := time.Now().Add(env.ReplacedHookCallsTimeout)
	for {
		running := env.replacedHookCalls(ctx, folders, fencedAt.Add(time.Second))
		if len(running) == 0 || !time.Now().Before(deadline) {
			return running
		}
		select {
		case <-ctx.Done():
			return running
		case <-time.After(env.PollInterval):
		}
	}
}

// replacedHookCalls are the processes that started before before and run a
// hook from one of folders as its account.
func (e *Env) replacedHookCalls(ctx context.Context, folders []replacedHookFolder, before time.Time) []string {
	var out []string
	for _, process := range e.hostProcesses(ctx) {
		if !process.Started.Before(before) {
			continue
		}
		for _, folder := range folders {
			if process.UID == folder.uid && runsFromFolder(process.Argv, folder.path) {
				out = append(out, fmt.Sprintf("%s (pid %d)", folder.user, process.PID))
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// runsFromFolder reports an argument that names a file in folder: the hook
// script a shell runs, or the command line of the agent's sh -c wrapper.
func runsFromFolder(argv []string, folder string) bool {
	prefix := strings.TrimSuffix(folder, "/") + "/"
	for _, arg := range argv {
		if strings.Contains(arg, prefix) {
			return true
		}
	}
	return false
}
