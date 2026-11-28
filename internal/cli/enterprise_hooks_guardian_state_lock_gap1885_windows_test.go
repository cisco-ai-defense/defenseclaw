//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/windows"
)

const (
	gap1885ChildDataDirEnv = "DEFENSECLAW_TEST_GAP1885_CHILD_DATA_DIR"
	gap1885ChildStartedEnv = "DEFENSECLAW_TEST_GAP1885_CHILD_STARTED"
	// gap1885Window is how long the first writer stays between its release
	// protection record and its ledger once the second writer has started.
	// An unserialized second writer publishes in milliseconds.
	gap1885Window = 5 * time.Second
)

// rel-1-0-10 GAP-1885 (after GAP-1763): on Windows nothing serialized two
// guardian state writers of one release, the guardian service and an
// administrator's `defenseclaw enterprise hooks reconcile`. Both read ledger
// G0; A wrote its record, B wrote its record (built on G0) and its ledger,
// then A wrote its ledger. The record then named neither the ledger
// generation nor the one it was built on, so the next pass rebuilt it from
// its own successes: a target failing that pass (its lock edited to the
// earlier release, its hooks stripped) lost its protection and read as
// awaiting sign-in. Writer B here is another process, started while A is
// between its record and its ledger; it must wait for A.
func TestGAP1885SecondGuardianWriterWaitsForTheFirst(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: the lock file is administrator-only (the Windows CI runners and the native test hosts run elevated)")
	}
	g := newGAP1763Guardian(t)
	g.mustPass("1.0.11 protects", true, true, "2026-11-23T08:00:00Z")

	started := filepath.Join(t.TempDir(), "started")
	var (
		child         *exec.Cmd
		childOut      bytes.Buffer
		childErr      error
		childDone     = make(chan struct{})
		insideTheGap  bool
		childStartErr error
	)
	enterpriseHookAuthorizationOwnershipSetter = func(path string) error {
		if path != g.recordPath || child != nil {
			return nil
		}
		// A has written its record and not yet its ledger.
		child = exec.Command(os.Args[0], "-test.run=^TestGAP1885GuardianStateChildWriter$", "-test.v", "-test.count=1")
		child.Env = append(os.Environ(), gap1885ChildDataDirEnv+"="+g.dataDir, gap1885ChildStartedEnv+"="+started)
		child.Stdout, child.Stderr = &childOut, &childOut
		if childStartErr = child.Start(); childStartErr != nil {
			return childStartErr
		}
		go func() {
			childErr = child.Wait()
			close(childDone)
		}()
		deadline := time.Now().Add(2 * time.Minute)
		for {
			if _, err := os.Stat(started); err == nil {
				break
			}
			select {
			case <-childDone:
				return nil
			case <-time.After(20 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				childStartErr = errors.New("the second writer did not start")
				return childStartErr
			}
		}
		select {
		case <-childDone:
			insideTheGap = true
		case <-time.After(gap1885Window):
		}
		return nil
	}
	if err := g.pass("1.0.11 publishes while a second writer starts", true, true, ""); err != nil {
		t.Fatalf("first writer: %v (second writer: %v)", err, childStartErr)
	}
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	if child == nil {
		t.Fatal("the first writer never wrote its release protection record")
	}
	select {
	case <-childDone:
	case <-time.After(3 * time.Minute):
		_ = child.Process.Kill()
		<-childDone
	}
	if childErr != nil {
		t.Fatalf("second writer: %v\n%s", childErr, childOut.String())
	}
	if !bytes.Contains(childOut.Bytes(), []byte("--- PASS: TestGAP1885GuardianStateChildWriter")) {
		t.Fatalf("the second writer did not publish:\n%s", childOut.String())
	}
	if insideTheGap {
		t.Errorf("GAP-1885: a second guardian writer published between the first writer's release protection record and its ledger")
	}

	record, _, err := loadEnterpriseHookReleaseProtection(g.authorizationDir)
	if err != nil {
		t.Fatal(err)
	}
	ledger, _, err := loadEnterpriseHookGuardianAuthorization(g.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if record.Generation != ledger.UpdatedAt {
		t.Errorf("GAP-1885: the release protection record was written for generation %s (built on %s), the ledger is %s",
			record.Generation, record.BaseGeneration, ledger.UpdatedAt)
	}
	g.mustPass("1.0.11 finds it drifted", true, false, "")
	g.mustPass("1.0.11 finds it drifted again", true, false, "")
	g.expect("after two concurrent writers, lock edited to 1.0.10", false)
}

// TestGAP1885GuardianStateChildWriter is the second writer of
// TestGAP1885SecondGuardianWriterWaitsForTheFirst, run in its own process.
func TestGAP1885GuardianStateChildWriter(t *testing.T) {
	dataDir := os.Getenv(gap1885ChildDataDirEnv)
	if dataDir == "" {
		t.Skip("the second writer of TestGAP1885SecondGuardianWriterWaitsForTheFirst")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previousCfg, previousRecorded, previousOwner := cfg, enterpriseHookReleaseProtectionRecorded, enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		cfg, enterpriseHookReleaseProtectionRecorded, enterpriseHookAuthorizationOwnershipSetter = previousCfg, previousRecorded, previousOwner
	})
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	cfg = &config.Config{DataDir: dataDir}
	enterpriseHookReleaseProtectionRecorded = func() bool { return true }
	if err := os.WriteFile(os.Getenv(gap1885ChildStartedEnv), []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	row := enterpriseHookReconcileRow{SID: gap1763SID, UserHome: `C:\Users\alice`, Connector: "codex", OK: true}
	if err := writeEnterpriseHookGuardianState(dataDir, "targets.yaml", testEnterpriseHookManifestSHA256,
		[]enterpriseHookReconcileRow{row}, 0, true); err != nil {
		t.Fatal(err)
	}
}
