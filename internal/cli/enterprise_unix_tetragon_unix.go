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

package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

func runUnixTetragon(cmd *cobra.Command, action string, opts *unixTetragonOptions) error {
	if goos := enterpriseunix.CurrentGOOS(); goos != "linux" {
		return withExitCode(fmt.Errorf("`enterprise linux tetragon` reads Linux hosts; this host is %s", goos), enterprisestatus.UnixExitInvalidArgs)
	}
	env, err := newUnixLifecycleEnv("linux")
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if action == enterpriseunix.TetragonActionVerify {
		readiness := enterpriseunix.RunTetragonVerify(cmd.Context(), env, opts.readyFor)
		if err := enterpriseunix.WriteTetragonReadiness(cmd.OutOrStdout(), readiness, opts.json); err != nil {
			return err
		}
		if readiness.OK {
			return nil
		}
		if len(readiness.Errors) > 0 {
			return withExitCode(errors.New("tetragon verify failed; see the "+countNoun(len(readiness.Errors), "problem")+" listed above"), readiness.ExitCode)
		}
		return withExitCode(errors.New("not ready for "+readiness.ReadyFor+"; see the failing checks above"), readiness.ExitCode)
	}
	report := enterpriseunix.RunTetragon(cmd.Context(), env, enterpriseunix.TetragonOptions{
		Action: action, For: opts.pauseFor, UntilReboot: opts.untilReboot, Reason: opts.reason, User: opts.user,
	})
	if err := enterpriseunix.WriteTetragonReport(cmd.OutOrStdout(), report, opts.json); err != nil {
		return err
	}
	if report.OK {
		return nil
	}
	return withExitCode(errors.New("tetragon "+action+" failed; see the "+countNoun(len(report.Errors), "problem")+" listed above"), report.ExitCode)
}
