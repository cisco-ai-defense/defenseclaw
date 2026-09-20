// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestEnterpriseHookVerifyRetriesChangedGenerationAndDiscardsMixedResult(t *testing.T) {
	old := enterpriseHookVerifyGenerationForTest("old")
	next := enterpriseHookVerifyGenerationForTest("next")
	captures := []enterpriseHookVerifyGenerationSnapshot{old, next, next, next}
	captureIndex := 0
	verifyCalls := 0

	run, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			if captureIndex >= len(captures) {
				t.Fatal("unexpected selector capture")
			}
			result := captures[captureIndex]
			captureIndex++
			return result, true, nil
		},
		2,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			if verifyCalls == 1 {
				return enterpriseHookVerifyRun{
					Failures: 1,
					Rows: []enterpriseHookReconcileRow{{
						Connector: "cursor",
						Error:     "mixed-generation Cursor contract",
					}},
				}, nil
			}
			return enterpriseHookVerifyRun{
				Rows: []enterpriseHookReconcileRow{{Connector: "cursor", OK: true}},
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifyCalls != 2 {
		t.Fatalf("verify calls = %d, want 2", verifyCalls)
	}
	if run.Failures != 0 || len(run.Rows) != 1 || !run.Rows[0].OK {
		t.Fatalf("accepted run = %+v, want only stable second generation", run)
	}
}

func TestEnterpriseHookVerifyRetriesPrecommitFailureWithUnchangedSelector(t *testing.T) {
	generation := enterpriseHookVerifyGenerationForTest("stable")
	verifyCalls := 0
	run, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			return generation, true, nil
		},
		3,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			if verifyCalls == 1 {
				return enterpriseHookVerifyRun{
					Failures: 1,
					Rows: []enterpriseHookReconcileRow{{
						Connector: "codex",
						Error:     "access denied during precommit publication",
					}},
				}, nil
			}
			return enterpriseHookVerifyRun{
				Rows: []enterpriseHookReconcileRow{{Connector: "codex", OK: true}},
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verifyCalls != 2 || run.Failures != 0 || !run.Rows[0].OK {
		t.Fatalf("run=%+v calls=%d, want stable retry success", run, verifyCalls)
	}
}

func TestEnterpriseHookVerifyPersistentStableDriftStillFailsClosed(t *testing.T) {
	generation := enterpriseHookVerifyGenerationForTest("tampered")
	verifyCalls := 0
	run, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			return generation, true, nil
		},
		3,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			return enterpriseHookVerifyRun{
				Failures: 1,
				Rows: []enterpriseHookReconcileRow{{
					Connector: "claudecode",
					Error:     "managed runtime ACL is noncanonical",
				}},
			}, nil
		},
	)
	if err != nil {
		t.Fatalf("stable target drift should remain a row failure, got outer error: %v", err)
	}
	if verifyCalls != 3 || run.Failures != 1 || run.Rows[0].OK {
		t.Fatalf("run=%+v calls=%d, want bounded stable failure", run, verifyCalls)
	}
}

func TestEnterpriseHookVerifyContinuousPublicationFailsBounded(t *testing.T) {
	captureCalls := 0
	verifyCalls := 0
	_, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			captureCalls++
			return enterpriseHookVerifyGenerationForTest(string(rune('a' + captureCalls))), true, nil
		},
		3,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			return enterpriseHookVerifyRun{}, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed during 3 bounded attempts") {
		t.Fatalf("continuous publication error = %v", err)
	}
	if verifyCalls != 3 || captureCalls != 6 {
		t.Fatalf("verify calls=%d captures=%d, want 3/6", verifyCalls, captureCalls)
	}
}

func TestEnterpriseHookVerifyStableFatalTrustErrorIsNotRetried(t *testing.T) {
	generation := enterpriseHookVerifyGenerationForTest("stable")
	want := errors.New("manifest trust failed")
	verifyCalls := 0
	_, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			return generation, true, nil
		},
		5,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			return enterpriseHookVerifyRun{}, want
		},
	)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want stable trust error", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("verify calls = %d, want 1", verifyCalls)
	}
}

func TestEnterpriseHookVerifyWithoutWindowsGenerationUsesSinglePass(t *testing.T) {
	verifyCalls := 0
	run, err := runEnterpriseHookVerifyGenerationConsistent(
		t.Context(),
		func() (enterpriseHookVerifyGenerationSnapshot, bool, error) {
			return enterpriseHookVerifyGenerationSnapshot{}, false, nil
		},
		5,
		0,
		func(context.Context) (enterpriseHookVerifyRun, error) {
			verifyCalls++
			return enterpriseHookVerifyRun{Manifest: "targets.yaml"}, nil
		},
	)
	if err != nil || run.Manifest != "targets.yaml" || verifyCalls != 1 {
		t.Fatalf("run=%+v err=%v calls=%d, want one non-Windows pass", run, err, verifyCalls)
	}
}

func enterpriseHookVerifyGenerationForTest(
	digest string,
) enterpriseHookVerifyGenerationSnapshot {
	cas := enterprisehooks.WindowsManagedRuntimeSelectorCAS{
		Exists: true,
		SHA256: digest,
	}
	return enterpriseHookVerifyGenerationSnapshot{
		Claude: cas,
		Codex:  cas,
		Cursor: cas,
	}
}
