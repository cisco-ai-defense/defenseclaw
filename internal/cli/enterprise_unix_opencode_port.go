// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
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
