// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A saved snapshot cannot authorize rewriting an inode that an operator can
// still edit through another name. Teardown must leave every name and token
// intact for manual recovery, including when a link appears during the save.
func TestRemovedOpenHandsConcurrentHardLinkEditsAreNotErased(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the old OpenHands shell script ran on Unix")
	}
	t.Run("existing link edited after save", checkRemovedOpenHandsExistingLinkEdit)
	t.Run("link added during save", checkRemovedOpenHandsNewLinkEdit)
}

func checkRemovedOpenHandsExistingLinkEdit(t *testing.T) {
	t.Helper()
	c := removedOpenHands
	h := newRemovedHost(t)
	h.stage(t, c)
	old := removedOpenHands103Script + "# operator's first edit\n"
	writeRemovedFile(t, h.script(c), old, c.mode)
	outside := filepath.Join(h.home, "elsewhere", c.script)
	removedLinkOrSkip(t, h.script(c), outside)
	appendix := "# later edit through the other name\n"
	write := removedKeepEditedWrite
	t.Cleanup(func() { removedKeepEditedWrite = write })
	appended := false
	removedKeepEditedWrite = func(path string, data []byte, mode os.FileMode) error {
		if err := write(path, data, mode); err != nil {
			return err
		}
		if !appended {
			file, err := os.OpenFile(outside, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(appendix); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			appended = true
		}
		return nil
	}
	err := c.Teardown(context.Background(), h.opts)
	if !appended || err == nil || !strings.Contains(err.Error(), c.hardLinkStep(h.script(c))) {
		t.Fatalf("Teardown = %v, appended = %v; want a hard-link refusal after the save", err, appended)
	}
	for _, name := range []string{h.script(c), outside} {
		if got, readErr := os.ReadFile(name); readErr != nil || string(got) != old+appendix {
			t.Fatalf("%s = %q, %v; want the later edit intact", name, got, readErr)
		}
	}
	h.requireTokensKept(t, c)
	if err := c.VerifyClean(h.opts); err == nil {
		t.Fatal("VerifyClean accepted the still-active hard-linked hook")
	}
}

func checkRemovedOpenHandsNewLinkEdit(t *testing.T) {
	t.Helper()
	c := removedOpenHands
	h := newRemovedHost(t)
	h.stage(t, c)
	old := removedOpenHands103Script + "# operator's first edit\n"
	writeRemovedFile(t, h.script(c), old, c.mode)
	outside := filepath.Join(h.home, "elsewhere", c.script)
	appendix := "# edit through a new hard link\n"
	write := removedKeepEditedWrite
	t.Cleanup(func() { removedKeepEditedWrite = write })
	linked := false
	removedKeepEditedWrite = func(path string, data []byte, mode os.FileMode) error {
		if err := write(path, data, mode); err != nil {
			return err
		}
		if !linked {
			removedLinkOrSkip(t, h.script(c), outside)
			file, err := os.OpenFile(outside, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(appendix); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			linked = true
		}
		return nil
	}
	err := c.Teardown(context.Background(), h.opts)
	if !linked || err == nil || !strings.Contains(err.Error(), c.hardLinkStep(h.script(c))) {
		t.Fatalf("Teardown = %v, linked = %v; want refusal before an in-place write", err, linked)
	}
	for _, name := range []string{h.script(c), outside} {
		if got, readErr := os.ReadFile(name); readErr != nil || string(got) != old+appendix {
			t.Fatalf("%s = %q, %v; want the later edit intact", name, got, readErr)
		}
	}
	h.requireTokensKept(t, c)
}
