// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// openCodePortClearGeteuid and openCodePortClearRecordPath are seams for
// tests.
var (
	openCodePortClear = func(path string, port int, by string, now time.Time) ([]int, error) {
		return enterprisehooks.ClearUnixOpenCodeContestedPortLocked(path, port, by, now, 2*time.Minute)
	}
	openCodePortUnknownClear = func(path string, uid int, hasAccount func(uid int) (bool, error)) (enterprisehooks.UnixOpenCodeServicePortUnknown, error) {
		return enterprisehooks.ClearUnixOpenCodeUnknownLocked(path, uid, 2*time.Minute, hasAccount)
	}
	openCodePortClearGeteuid    = os.Geteuid
	openCodePortClearRecordPath = func(goos string) (string, error) {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			return "", err
		}
		return filepath.Join(layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName), nil
	}
)

// openCodePortClearCommand is the exact command that clears the contested
// mark of port (status, verify, doctor and the guardian name it).
func openCodePortClearCommand(goos string, port int) string {
	group, bin := "linux", "/opt/defenseclaw/bin"
	if goos == "darwin" {
		group = "macos"
	}
	if layout, err := managed.StandaloneLayoutFor(goos); err == nil && layout.BinDir != "" {
		bin = layout.BinDir
	}
	return fmt.Sprintf("sudo %s enterprise %s opencode-port-clear %d --yes", filepath.Join(bin, "defenseclaw-gateway"), group, port)
}

// newUnixOpenCodePortClearCommand is `enterprise linux|macos
// opencode-port-clear <port> --yes`: the administrator's operation that
// clears the contested mark of an OpenCode service port in the guardian's
// record (gas-ux-r1 GAP-0053, REVIEW-gx053-11). Root only; the clear is
// logged in the record and printed.
func newUnixOpenCodePortClearCommand(platform string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "opencode-port-clear <port>",
		Short: "Clear the contested mark of an OpenCode service port so the guardian may give it again",
		Long: `Clear the contested mark of one OpenCode background-server port in the hook
guardian's record. A port is marked contested when, in the pass that built the
record, the files of two or more accounts named it: no account is given it
until this command clears the mark. The bindings of every account stay as they
are; the guardian may give the port to an account from its next pass. The
clear is logged in the record. Run as root.`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil || port <= 0 || port > 65535 {
				return lifecycleFlagError(cmd, fmt.Errorf("%q is not a port", args[0]))
			}
			if !yes {
				return lifecycleFlagError(cmd, errors.New("clearing a contested OpenCode port needs --yes"))
			}
			if openCodePortClearGeteuid() != 0 {
				return errors.New("opencode-port-clear must run as root (sudo)")
			}
			goos := runtime.GOOS
			if platform == "macos" {
				goos = "darwin"
			}
			path, err := openCodePortClearRecordPath(goos)
			if err != nil {
				return err
			}
			by := strings.TrimSpace(os.Getenv("SUDO_USER"))
			if by == "" {
				by = "root"
			}
			claimants, err := openCodePortClear(path, port, by, time.Now())
			if err != nil {
				return err
			}
			names := make([]string, 0, len(claimants))
			for _, uid := range claimants {
				names = append(names, strconv.Itoa(uid))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cleared the contested mark of OpenCode port %d (claimed by uids %s; logged in %s by %s); the guardian may give it again from its next pass\n",
				port, strings.Join(names, ", "), path, by)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the clear")
	return cmd
}

// openCodePortUnknownUIDHasAccount asks the host whether any account holds
// uid (tests replace it).
var openCodePortUnknownUIDHasAccount = func(goos string, uid int) (bool, error) {
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return false, err
	}
	return env.UIDHasAccount(context.Background(), uid)
}

// newUnixOpenCodePortUnknownClearCommand is `enterprise linux|macos
// opencode-port-unknown-clear <uid> --yes`: the administrator removal of the
// stale unknown entry the guardian record keeps for a uid that no longer has an
// account (GAP-0904). It refuses while any account source (NSS, altfiles,
// /etc/passwd, the macOS directory) still holds the uid, and when the lookup
// does not answer. Root only.
func newUnixOpenCodePortUnknownClearCommand(platform string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "opencode-port-unknown-clear <uid>",
		Short: "Remove the stale OpenCode port record entry of a uid that has no account",
		Long: `Remove the unknown entry of one uid from the hook guardian OpenCode port
record. The guardian keeps that entry for an account whose service.json it
could not read or write; when the account has since been deleted, status and
verify report "OpenCode port record for UID <n> (no account found)" and nothing
is left to repair. The command checks the uid again and refuses while any
account of the host still holds it, or when the lookup does not answer. The
recorded port binding and the contested marks stay. Run as root.`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			uid, err := strconv.Atoi(strings.TrimSpace(args[0]))
			if err != nil || uid < 0 {
				return lifecycleFlagError(cmd, fmt.Errorf("%q is not a uid", args[0]))
			}
			if !yes {
				return lifecycleFlagError(cmd, errors.New("removing the OpenCode port record entry of a uid needs --yes"))
			}
			if openCodePortClearGeteuid() != 0 {
				return errors.New("opencode-port-unknown-clear must run as root (sudo)")
			}
			goos := runtime.GOOS
			if platform == "macos" {
				goos = "darwin"
			}
			path, err := openCodePortClearRecordPath(goos)
			if err != nil {
				return err
			}
			removed, err := openCodePortUnknownClear(path, uid, func(uid int) (bool, error) {
				return openCodePortUnknownUIDHasAccount(goos, uid)
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed the OpenCode port record entry of uid %d (no account found; recorded for %s) from %s; its port binding stays\n", uid, removed.User, path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the removal")
	return cmd
}
