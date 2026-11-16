// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
)

// GAP-0117: a pass started by an in-place overwrite names the Write even
// when the truncation's Chmod came first (macOS kqueue order).
func TestEnterpriseHookWatchNoteTriggerJoinsTheOpsOfTheTriggerPath(t *testing.T) {
	token := filepath.FromSlash("/Users/u/.defenseclaw/hooks/.hook-hermes.token")
	path, op := enterpriseHookWatchNoteTrigger("", 0, fsnotify.Event{Name: token, Op: fsnotify.Chmod})
	path, op = enterpriseHookWatchNoteTrigger(path, op, fsnotify.Event{Name: filepath.FromSlash("/Users/u/.defenseclaw/hooks/.hookcfg.hermes"), Op: fsnotify.Remove})
	path, op = enterpriseHookWatchNoteTrigger(path, op, fsnotify.Event{Name: token + string(filepath.Separator), Op: fsnotify.Write})
	if path != token || !op.Has(fsnotify.Write) || !op.Has(fsnotify.Chmod) || op.Has(fsnotify.Remove) {
		t.Fatalf("trigger = %s %s, want %s WRITE|CHMOD", path, op, token)
	}
	if got := op.String(); got != "WRITE|CHMOD" {
		t.Fatalf("trigger op logs as %q, want WRITE|CHMOD", got)
	}
}
