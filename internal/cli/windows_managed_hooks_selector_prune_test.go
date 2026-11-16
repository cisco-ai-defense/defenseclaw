// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type selectorPruneFixture struct {
	selectors     map[string][]byte
	activation    bool
	authorization bool
	state         bool
	recordsErr    error
	existing      map[string]bool
	enrolled      string
	captureErr    map[string]error
	restoreErr    map[string]error
	captures      []string
	restores      []string
	verifyCalled  int
}

func newSelectorPruneFixture() *selectorPruneFixture {
	return &selectorPruneFixture{
		selectors:  map[string][]byte{},
		existing:   map[string]bool{},
		captureErr: map[string]error{},
		restoreErr: map[string]error{},
	}
}

func selectorPruneTestPath(connectorName string) string {
	return `D:\policy\` + connectorName + `\.defenseclaw-managed-runtime-selector.state`
}

func selectorPruneTestBody(connectorName string, sids ...string) []byte {
	type target struct {
		Connector    string `json:"connector"`
		SID          string `json:"sid"`
		DataDir      string `json:"data_dir"`
		GenerationID string `json:"generation_id"`
		BundleSHA256 string `json:"bundle_sha256"`
	}
	body := struct {
		SchemaVersion int      `json:"schema_version"`
		Connector     string   `json:"connector"`
		Targets       []target `json:"targets"`
	}{SchemaVersion: 1, Connector: connectorName, Targets: []target{}}
	for _, sid := range sids {
		body.Targets = append(body.Targets, target{
			Connector:    connectorName,
			SID:          sid,
			DataDir:      `D:\Users\someone\.defenseclaw`,
			GenerationID: "0123456789abcdef",
			BundleSHA256: strings.Repeat("a", 64),
		})
	}
	data, _ := json.Marshal(body)
	return data
}

func (fixture *selectorPruneFixture) prune() windowsManagedHooksSelectorPrune {
	return windowsManagedHooksSelectorPrune{
		transactionID:  "20261027T204757Z-0001",
		journalPath:    `D:\state\install\managed-hooks-lifecycle-journal.json`,
		quarantinePath: `D:\state\install\transactions\tx\managed-hooks-lifecycle-journal.v3.quarantine`,
		guardianRecords: func() (bool, bool, bool, error) {
			return fixture.activation, fixture.authorization, fixture.state, fixture.recordsErr
		},
		machinePolicyEnrollment: func() (string, string, error) {
			if fixture.enrolled == "" {
				return "", "", nil
			}
			return fixture.enrolled, fixture.enrolled + " policy enrolls targets", nil
		},
		selectorPaths: func() (map[string]string, error) {
			paths := map[string]string{}
			for _, name := range windowsManagedHooksLifecycleSelectorConnectors {
				paths[name] = selectorPruneTestPath(name)
			}
			return paths, nil
		},
		pathExists: func(path string) (bool, error) {
			return fixture.existing[path], nil
		},
		capture: func(name string) (enterprisehooks.WindowsManagedRuntimeSelectorSnapshot, error) {
			fixture.captures = append(fixture.captures, name)
			if err := fixture.captureErr[name]; err != nil {
				return enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{}, err
			}
			body, ok := fixture.selectors[name]
			if !ok {
				return enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
					SchemaVersion: 1,
					Connector:     name,
				}, nil
			}
			digest := windowsManagedHooksSelectorPruneTestDigest(body)
			return enterprisehooks.WindowsManagedRuntimeSelectorSnapshot{
				SchemaVersion:  1,
				Connector:      name,
				Existed:        true,
				Selector:       body,
				SelectorSHA256: digest,
				CAS:            enterprisehooks.WindowsManagedRuntimeSelectorCAS{Exists: true, SHA256: digest},
			}, nil
		},
		restore: func(opts enterprisehooks.WindowsManagedRuntimeSelectorFullRestoreOptions) error {
			name := opts.Snapshot.Connector
			fixture.restores = append(fixture.restores, name)
			if opts.Snapshot.Existed || len(opts.Snapshot.Selector) != 0 {
				return errors.New("prune must restore to absent")
			}
			if err := fixture.restoreErr[name]; err != nil {
				return err
			}
			body, ok := fixture.selectors[name]
			if !ok || !opts.ExpectedCurrent.Exists ||
				opts.ExpectedCurrent.SHA256 != windowsManagedHooksSelectorPruneTestDigest(body) {
				return errors.New("selector CAS conflict")
			}
			delete(fixture.selectors, name)
			return nil
		},
		verifyAbsent: func(path, name string) error {
			fixture.verifyCalled++
			if _, ok := fixture.selectors[name]; ok {
				return errWindowsManagedHooksSelectorPruneTestPresent
			}
			return nil
		},
	}
}

var errWindowsManagedHooksSelectorPruneTestPresent = errors.New("selector still present")

func windowsManagedHooksSelectorPruneTestDigest(body []byte) string {
	return windowsManagedHooksSelectorPruneTestHex(len(body))
}

func windowsManagedHooksSelectorPruneTestHex(seed int) string {
	return strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

func captureResilienceEvents(t *testing.T) *[]string {
	t.Helper()
	var events []string
	original := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = original })
	return &events
}

func TestSelectorPruneRemovesEveryOrphanedSelector(t *testing.T) {
	events := captureResilienceEvents(t)
	fixture := newSelectorPruneFixture()
	fixture.selectors["claudecode"] = selectorPruneTestBody("claudecode", "S-1-5-21-1-2-3-500")
	fixture.selectors["codex"] = selectorPruneTestBody("codex", "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-1001")
	fixture.selectors["cursor"] = selectorPruneTestBody("cursor", "S-1-5-21-1-2-3-500")

	result, err := fixture.prune().run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != "pruned" {
		t.Fatalf("phase = %q", result.Phase)
	}
	if len(fixture.selectors) != 0 {
		t.Fatalf("selectors left behind: %v", fixture.selectors)
	}
	if len(result.PrunedSelectors) != 3 {
		t.Fatalf("pruned = %+v", result.PrunedSelectors)
	}
	codex := result.PrunedSelectors[1]
	if codex.Connector != "codex" || codex.Path != selectorPruneTestPath("codex") || codex.SHA256 == "" ||
		!slices.Equal(codex.TargetSIDs, []string{"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-500"}) {
		t.Fatalf("codex evidence = %+v", codex)
	}
	if fixture.verifyCalled != 3 {
		t.Fatalf("absence verified %d times", fixture.verifyCalled)
	}
	if len(*events) != 3 || !strings.HasPrefix((*events)[0], managed.MarkerRecover+" ") {
		t.Fatalf("events = %v", *events)
	}
	if !slices.Equal(result.SelectorPaths, []string{
		selectorPruneTestPath("claudecode"),
		selectorPruneTestPath("codex"),
		selectorPruneTestPath("cursor"),
	}) {
		t.Fatalf("selector paths = %v", result.SelectorPaths)
	}
}

func TestSelectorPruneNonePresentWritesNothing(t *testing.T) {
	fixture := newSelectorPruneFixture()
	result, err := fixture.prune().run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != "none_present" || len(fixture.restores) != 0 || len(result.PrunedSelectors) != 0 {
		t.Fatalf("result = %+v restores = %v", result, fixture.restores)
	}
}

func TestSelectorPruneSkipsWhenGuardianRecordsExist(t *testing.T) {
	for name, set := range map[string]func(*selectorPruneFixture){
		"activation":         func(f *selectorPruneFixture) { f.activation = true },
		"authorization only": func(f *selectorPruneFixture) { f.authorization = true },
		"state only":         func(f *selectorPruneFixture) { f.state = true },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSelectorPruneFixture()
			fixture.selectors["codex"] = selectorPruneTestBody("codex", "S-1-5-21-1-2-3-500")
			set(fixture)
			result, err := fixture.prune().run()
			if err != nil {
				t.Fatal(err)
			}
			if result.Phase != "skipped_recorded_state" || len(fixture.captures) != 0 ||
				len(fixture.restores) != 0 || len(fixture.selectors) != 1 {
				t.Fatalf("result = %+v captures = %v restores = %v", result, fixture.captures, fixture.restores)
			}
		})
	}
}

func TestSelectorPruneFailsClosedOnUnreadableGuardianRecord(t *testing.T) {
	fixture := newSelectorPruneFixture()
	fixture.selectors["codex"] = selectorPruneTestBody("codex", "S-1-5-21-1-2-3-500")
	fixture.recordsErr = errors.New("inspect Guardian state: untrusted owner")
	result, err := fixture.prune().run()
	if err == nil || !strings.Contains(err.Error(), "untrusted owner") {
		t.Fatalf("err = %v", err)
	}
	if result.Phase != "" || len(fixture.restores) != 0 {
		t.Fatalf("result = %+v restores = %v", result, fixture.restores)
	}
}

func TestSelectorPruneSkipsWhenLifecycleRecoveryRecordExists(t *testing.T) {
	for name, pick := range map[string]func(windowsManagedHooksSelectorPrune) string{
		"journal":    func(p windowsManagedHooksSelectorPrune) string { return p.journalPath },
		"quarantine": func(p windowsManagedHooksSelectorPrune) string { return p.quarantinePath },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSelectorPruneFixture()
			fixture.selectors["cursor"] = selectorPruneTestBody("cursor", "S-1-5-21-1-2-3-500")
			prune := fixture.prune()
			fixture.existing[pick(prune)] = true
			result, err := prune.run()
			if err != nil {
				t.Fatal(err)
			}
			if result.Phase != "skipped_recorded_state" || len(fixture.restores) != 0 {
				t.Fatalf("result = %+v restores = %v", result, fixture.restores)
			}
		})
	}
}

func TestSelectorPruneSkipsWhenMachinePolicyStillEnrolls(t *testing.T) {
	for _, connectorName := range windowsManagedHooksLifecycleSelectorConnectors {
		t.Run(connectorName, func(t *testing.T) {
			fixture := newSelectorPruneFixture()
			fixture.selectors["claudecode"] = selectorPruneTestBody("claudecode", "S-1-5-21-1-2-3-500")
			fixture.enrolled = connectorName
			result, err := fixture.prune().run()
			if err != nil {
				t.Fatal(err)
			}
			if result.Phase != "skipped_machine_policy" || result.SkipConnector != connectorName ||
				result.SkipReason == "" || len(fixture.captures) != 0 || len(fixture.restores) != 0 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestSelectorPruneStopsOnCASConflictWithoutRetry(t *testing.T) {
	fixture := newSelectorPruneFixture()
	fixture.selectors["claudecode"] = selectorPruneTestBody("claudecode", "S-1-5-21-1-2-3-500")
	fixture.selectors["codex"] = selectorPruneTestBody("codex", "S-1-5-21-1-2-3-500")
	fixture.selectors["cursor"] = selectorPruneTestBody("cursor", "S-1-5-21-1-2-3-500")
	conflict := errors.New("selector CAS conflict")
	fixture.restoreErr["codex"] = conflict

	result, err := fixture.prune().run()
	if !errors.Is(err, conflict) {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(fixture.restores, []string{"claudecode", "codex"}) {
		t.Fatalf("restores = %v", fixture.restores)
	}
	if !slices.Equal(fixture.captures, []string{"claudecode", "codex"}) {
		t.Fatalf("captures = %v", fixture.captures)
	}
	if _, ok := fixture.selectors["cursor"]; !ok {
		t.Fatal("Cursor selector was touched after the failure")
	}
	if len(result.PrunedSelectors) != 1 || result.PrunedSelectors[0].Connector != "claudecode" {
		t.Fatalf("pruned = %+v", result.PrunedSelectors)
	}
}

func TestSelectorPruneCaptureTrustErrorReportsPaths(t *testing.T) {
	fixture := newSelectorPruneFixture()
	fixture.selectors["codex"] = selectorPruneTestBody("codex", "S-1-5-21-1-2-3-500")
	fixture.captureErr["codex"] = errors.New("managed runtime selector DACL is not canonical")
	result, err := fixture.prune().run()
	if err == nil || !strings.Contains(err.Error(), selectorPruneTestPath("codex")) {
		t.Fatalf("err = %v", err)
	}
	if len(result.SelectorPaths) != 3 {
		t.Fatalf("selector paths = %v", result.SelectorPaths)
	}
}

func TestSelectorPruneRequiresPendingTransaction(t *testing.T) {
	fixture := newSelectorPruneFixture()
	prune := fixture.prune()
	prune.transactionID = ""
	if _, err := prune.run(); err == nil ||
		!strings.Contains(err.Error(), "pending lifecycle transaction") {
		t.Fatalf("err = %v", err)
	}
	if len(fixture.captures) != 0 {
		t.Fatalf("captures = %v", fixture.captures)
	}
}

func TestSelectorPruneEvidenceCarriesNoBundleOrTokenBytes(t *testing.T) {
	events := captureResilienceEvents(t)
	fixture := newSelectorPruneFixture()
	fixture.selectors["cursor"] = selectorPruneTestBody("cursor", "S-1-5-21-1-2-3-500")
	result, err := fixture.prune().run()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(struct {
		Pruned []windowsManagedHooksPrunedSelector `json:"pruned_selectors"`
		Paths  []string                            `json:"selector_paths"`
	}{result.PrunedSelectors, result.SelectorPaths})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range append([]string{string(body)}, *events...) {
		for _, forbidden := range []string{"scoped_token", "bundle_sha256", "generation_id", "data_dir"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("evidence contains %q: %s", forbidden, text)
			}
		}
	}
}

func TestSelectorPruneTargetSIDsRejectsMalformedSelector(t *testing.T) {
	if _, err := windowsManagedHooksSelectorTargetSIDs([]byte(`{"targets":[{"sid":""}]}`)); err == nil {
		t.Fatal("empty SID accepted")
	}
	if _, err := windowsManagedHooksSelectorTargetSIDs([]byte(`not json`)); err == nil {
		t.Fatal("malformed selector accepted")
	}
}
