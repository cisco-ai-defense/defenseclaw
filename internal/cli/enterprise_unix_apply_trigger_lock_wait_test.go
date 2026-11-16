// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// rel-1-0-3 GAP-0142: a second ensure --reason path five seconds after the
// first exited lifecycle_busy after the 5 s MDM default, although the
// config-apply trigger that runs the same command waits 10 m for the lock
// and applies the push after the run in progress. ensure --reason path
// without --lock-wait waits as the trigger does; a typed wait, another
// reason and other actions keep theirs.
func TestEnsureForTheApplyTriggerWaitsForTheLockAsTheTriggerDoes(t *testing.T) {
	newCmd := func() (*cobra.Command, *unixLifecycleOptions) {
		opts := &unixLifecycleOptions{}
		cmd := &cobra.Command{Use: "ensure"}
		addLockWaitFlag(cmd.Flags(), &opts.lockWait)
		return cmd, opts
	}
	cmd, opts := newCmd()
	opts.reason = "path"
	if got := applyTriggerLockWait(cmd, enterpriseunix.ActionEnsure, opts); got != 10*time.Minute {
		t.Fatalf("ensure --reason path waits %s; want the apply trigger wait 10m", got)
	}
	cmd, opts = newCmd()
	opts.reason = "path"
	if err := cmd.Flags().Set("lock-wait", "0"); err != nil {
		t.Fatal(err)
	}
	if got := applyTriggerLockWait(cmd, enterpriseunix.ActionEnsure, opts); got != 0 {
		t.Fatalf("a typed --lock-wait 0 was replaced with %s", got)
	}
	cmd, opts = newCmd()
	opts.reason = "mdm"
	if got := applyTriggerLockWait(cmd, enterpriseunix.ActionEnsure, opts); got != 0 {
		t.Fatalf("ensure --reason mdm waits %s; want the MDM default", got)
	}
	cmd, opts = newCmd()
	opts.reason = "path"
	if got := applyTriggerLockWait(cmd, enterpriseunix.ActionRepair, opts); got != 0 {
		t.Fatalf("repair --reason path waits %s; want the MDM default", got)
	}
}
