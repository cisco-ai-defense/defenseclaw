// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// GAP-0617: a config.yaml the lifecycle did not record (an administrator's
// content write the gateway already enforces) is recorded as the next config
// generation, once; a recorded config is left alone.
func TestRecordUnrecordedManagedConfigAdvancesTheGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	generation := func() configwrite.GenerationState {
		t.Helper()
		state, err := configwrite.ReadGenerationState(path)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	var log strings.Builder

	write("config_version: 9\n")
	recordUnrecordedManagedConfig(path, &log, nil)
	first := generation()
	if first.Generation != 1 || !configwrite.IsHandEditActor(first.Actor) || !strings.Contains(log.String(), "recorded as config generation 1") {
		t.Fatalf("first record: %+v\n%s", first, log.String())
	}
	log.Reset()
	recordUnrecordedManagedConfig(path, &log, nil)
	if again := generation(); again.Generation != 1 || log.Len() != 0 {
		t.Fatalf("a recorded config was recorded again: %+v\n%s", again, log.String())
	}
	write("config_version: 9\n# edited\n")
	recordUnrecordedManagedConfig(path, &log, nil)
	if edited := generation(); edited.Generation != 2 || edited.ConfigSHA256 == first.ConfigSHA256 {
		t.Fatalf("an edit did not advance the generation: %+v", edited)
	}
	// A config the lifecycle wrote is recorded by its writer (actor
	// lifecycle) and is not turned into a hand edit.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, []byte("config_version: 9\n# lifecycle\n"),
		configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test"}); err != nil {
		t.Skipf("the writer does not accept the minimal config here: %v", err)
	}
	recordUnrecordedManagedConfig(path, &log, nil)
	if state := generation(); state.Generation != 3 || state.Actor != configwrite.ActorLifecycle {
		t.Fatalf("a lifecycle write was re-recorded: %+v", state)
	}
	recordUnrecordedManagedConfig(filepath.Join(t.TempDir(), "missing.yaml"), &log, nil)
}

// GAP-0646: bytes the record does not name while a lifecycle run owns
// config.yaml are that run's own write. The guardian leaves them to it, says
// so once, and records an edit only while it holds the lifecycle off; a
// recorded config asks for no claim at all.
func TestRecordUnrecordedManagedConfigLeavesALifecycleRunsWriteToIt(t *testing.T) {
	t.Cleanup(func() { managedConfigRecordDeferredTo = "" })
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	claims, releases := 0, 0
	busy := func() managedConfigOwnership {
		claims++
		return managedConfigOwnership{reason: "a DefenseClaw lifecycle run holds lifecycle.lock"}
	}
	recordUnrecordedManagedConfig(path, &log, busy)
	recordUnrecordedManagedConfig(path, &log, busy)
	if state, err := configwrite.ReadGenerationState(path); err == nil {
		t.Fatalf("recorded while a lifecycle run owns config.yaml: %+v", state)
	}
	if claims != 2 || strings.Count(log.String(), "it is not recorded now and is retried each cycle") != 1 {
		t.Fatalf("claims %d, log %q: want two claims and one line", claims, log.String())
	}
	log.Reset()
	free := func() managedConfigOwnership {
		claims++
		return managedConfigOwnership{release: func() { releases++ }}
	}
	recordUnrecordedManagedConfig(path, &log, free)
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Generation != 1 || state.Actor != configwrite.ActorUnattributedHandEdit || releases != 1 {
		t.Fatalf("edit outside a lifecycle run: %+v, %v, releases %d\n%s", state, err, releases, log.String())
	}
	if note, kept := readManagedConfigHandEdit(path); !kept || note.ConfigSHA256 != state.ConfigSHA256 {
		t.Fatalf("the recorded hand edit is not kept: %+v, %t", note, kept)
	}
	claims = 0
	recordUnrecordedManagedConfig(path, &log, busy)
	if claims != 0 {
		t.Fatalf("a recorded config claimed the lifecycle %d times", claims)
	}
}

// GAP-0646 review 3: while the guardian holds lifecycle.lock it waits for a
// busy config.yaml.lock about a second, not the writer's 10 s default, and
// lets lifecycle.lock go before a Go lifecycle step's 5 s wait ends. The edit
// is not recorded this cycle.
func TestRecordUnrecordedManagedConfigBoundsItsLifecycleHoldOnABusyWriterLock(t *testing.T) {
	t.Cleanup(func() { managedConfigRecordDeferredTo = "" })
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	held, done := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = configwrite.Locked(context.Background(), path, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test writer"},
			func() (bool, error) { close(held); <-release; return false, nil })
	}()
	<-held
	t.Cleanup(func() { close(release); <-done })
	var hold time.Duration
	var claimed time.Time
	claim := func() managedConfigOwnership {
		claimed = time.Now()
		return managedConfigOwnership{release: func() { hold = time.Since(claimed) }}
	}
	var log strings.Builder
	recordUnrecordedManagedConfig(path, &log, claim)
	if claimed.IsZero() || hold == 0 {
		t.Fatalf("the guardian did not claim and release lifecycle.lock (claimed %v, hold %v)", claimed, hold)
	}
	if hold >= 5*time.Second {
		t.Fatalf("the guardian held lifecycle.lock %v on a busy config.yaml.lock, want it below a lifecycle step's 5 s wait", hold)
	}
	if !strings.Contains(log.String(), "could not record the config generation") {
		t.Fatalf("log = %q, want the deferred record logged", log.String())
	}
	if _, err := os.Stat(configwrite.GenerationPath(path)); !os.IsNotExist(err) {
		t.Fatalf("a record was written while config.yaml.lock was busy: %v", err)
	}
}

// GAP-0646 review L2 (REVIEW-g646 #5): when the guardian cannot record an
// administrator's edit (it cannot tell whether a lifecycle run owns
// config.yaml, or a run holds lifecycle.lock), it records nothing, keeps the
// bytes it saw in config.hand-edit.json and retries each cycle. Every
// later record of exactly those bytes names the hand edit: the guardian's own
// once the condition clears, a lifecycle config step's that did not install
// them from its approved source, and a rollback's. Only the bytes this run
// installed from its approved source are the lifecycle's; bytes the guardian
// never kept are adopted as before (an upgrade from an earlier build); a
// pending install transaction's recovery puts config.yaml back, so nothing
// is kept for it; an unreadable record proves nothing and keeps nothing.
func TestAnUnrecordedEditTheGuardianCannotRecordIsNeverRecordedWithAFalseOwner(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	t.Cleanup(func() { managedConfigRecordDeferredTo = "" })
	lifecycleBytes := []byte("config_version: 9\nobservability: {}\n")
	edit := []byte("config_version: 9\nobservability: {}\n# an administrator's edit\n")
	cannotTell := managedConfigOwnership{reason: "lifecycle.lock cannot be opened, so the guardian cannot tell whether a lifecycle run owns config.yaml (Access is denied.)"}
	held := managedConfigOwnership{reason: "a DefenseClaw lifecycle run holds lifecycle.lock"}
	pending := managedConfigOwnership{reason: "an install transaction is pending", restored: true}
	free := func(released *int) managedConfigOwnership {
		return managedConfigOwnership{release: func() { *released++ }}
	}
	type outcome struct {
		actor      string
		generation uint64
	}
	handEdit := func(generation uint64) outcome { return outcome{configwrite.ActorUnattributedHandEdit, generation} }
	lifecycle := func(generation uint64) outcome { return outcome{configwrite.ActorLifecycle, generation} }
	for _, tc := range []struct {
		name string
		// recorded records lifecycleBytes as generation 1 before the edit.
		recorded bool
		// brokenRecord makes config.generation.json unreadable.
		brokenRecord bool
		owner        managedConfigOwnership
		kept         bool
		next         func(t *testing.T, path string)
		want         outcome
	}{
		{name: "cannot tell, then the condition clears", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) {
				released := 0
				var log strings.Builder
				recordUnrecordedManagedConfig(path, &log, func() managedConfigOwnership { return free(&released) })
				if released != 1 || !strings.Contains(log.String(), "recorded as config generation 2") {
					t.Fatalf("released %d, log %q", released, log.String())
				}
			}, want: handEdit(2)},
		{name: "cannot tell, then a config step without CONFIG=", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, "") }, want: handEdit(2)},
		{name: "cannot tell on a host with no record, then a config step", owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, "") }, want: handEdit(1)},
		{name: "cannot tell, then a config step that installed other bytes", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, configwrite.SHA256Hex(lifecycleBytes)) }, want: handEdit(2)},
		{name: "cannot tell, then a config step that installed exactly these bytes", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, configwrite.SHA256Hex(edit)) }, want: lifecycle(2)},
		{name: "cannot tell, then a rollback restores these bytes", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) {
				if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
					t.Fatal(err)
				}
			}, want: handEdit(2)},
		{name: "a run holds lifecycle.lock, then its config step without CONFIG=", recorded: true, owner: held, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, "") }, want: handEdit(2)},
		{name: "a run holds lifecycle.lock, then its config step installed these bytes", recorded: true, owner: held, kept: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, configwrite.SHA256Hex(edit)) }, want: lifecycle(2)},
		{name: "a pending transaction keeps nothing (its recovery puts config.yaml back)", recorded: true, owner: pending},
		{name: "bytes the guardian never kept are adopted as before", recorded: true,
			next: func(t *testing.T, path string) { migrateForTest(t, path, "") }, want: lifecycle(2)},
		{name: "kept bytes are evidence for those bytes only", recorded: true, owner: cannotTell, kept: true,
			next: func(t *testing.T, path string) {
				if err := os.WriteFile(path, append(append([]byte(nil), edit...), "# changed again\n"...), 0o600); err != nil {
					t.Fatal(err)
				}
				migrateForTest(t, path, "")
			}, want: lifecycle(2)},
		{name: "an unreadable record keeps nothing", recorded: true, brokenRecord: true, owner: cannotTell},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedConfigRecordDeferredTo = ""
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, lifecycleBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.recorded {
				if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test install"},
					func() (bool, error) { return true, nil }); err != nil {
					t.Fatal(err)
				}
			}
			if tc.brokenRecord {
				if err := os.WriteFile(configwrite.GenerationPath(path), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, edit, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.owner.reason != "" {
				var log strings.Builder
				for range 2 {
					recordUnrecordedManagedConfig(path, &log, func() managedConfigOwnership { return tc.owner })
				}
				if strings.Count(log.String(), tc.owner.reason) != 1 {
					t.Fatalf("log = %q, want the reason once", log.String())
				}
			}
			if state, err := configwrite.ReadGenerationState(path); tc.recorded && !tc.brokenRecord && (err != nil || state.Generation != 1) {
				t.Fatalf("the guardian recorded while it could not claim config.yaml: %+v, %v", state, err)
			}
			note, kept := readManagedConfigHandEdit(path)
			if kept != tc.kept || kept && (note.ConfigSHA256 != configwrite.SHA256Hex(edit) || note.Reason != tc.owner.reason) {
				t.Fatalf("kept edit = %+v, %t; want kept %t", note, kept, tc.kept)
			}
			if tc.next == nil {
				return
			}
			tc.next(t, path)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			state, err := configwrite.ReadGenerationState(path)
			if err != nil || state.Actor != tc.want.actor || state.Generation != tc.want.generation || state.ConfigSHA256 != configwrite.SHA256Hex(raw) {
				t.Fatalf("record = %+v, %v; want generation %d by %s", state, err, tc.want.generation, tc.want.actor)
			}
			if configwrite.IsHandEditActor(state.Actor) && !strings.Contains(state.Reason, "edited outside the lifecycle") {
				t.Fatalf("hand-edit reason = %q", state.Reason)
			}
			// The next cycle keeps a recorded hand edit, forgets an edit a run
			// installed from its approved source, and leaves an edit of other
			// bytes kept (the evidence for a rollback that puts them back).
			recordUnrecordedManagedConfig(path, &strings.Builder{}, func() managedConfigOwnership { return cannotTell })
			note, kept = readManagedConfigHandEdit(path)
			switch {
			case configwrite.IsHandEditActor(state.Actor):
				if !kept || note.ConfigSHA256 != configwrite.SHA256Hex(raw) {
					t.Fatalf("a recorded hand edit is not kept: %+v, %t", note, kept)
				}
			case string(raw) == string(edit):
				if kept {
					t.Fatalf("an edit a run installed from its approved source is still kept: %+v", note)
				}
			case kept != tc.kept || kept && note.ConfigSHA256 != configwrite.SHA256Hex(edit):
				t.Fatalf("kept edit after a record of other bytes = %+v, %t; want kept %t", note, kept, tc.kept)
			}
		})
	}
}

// GAP-0646 review L2: a hand edit the guardian recorded stays a hand edit
// when a Setup run records its own config and a rollback then puts the
// edit back. It was recorded as `lifecycle` ("enterprise windows rollback"),
// and the gateway started on an administrator's unapproved bytes. A run that
// installs exactly those bytes from its approved source approves them.
func TestARecordedHandEditARollbackPutsBackStaysAHandEdit(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	t.Cleanup(func() { managedConfigRecordDeferredTo = "" })
	path := filepath.Join(t.TempDir(), "config.yaml")
	installed := []byte("config_version: 9\nobservability: {}\n")
	edit := []byte("config_version: 9\nobservability: {}\n# an administrator's edit\n")
	approved := []byte("config_version: 9\nobservability: {}\n# the approved config\n")
	record := func(want string, generation uint64) configwrite.GenerationState {
		t.Helper()
		state, err := configwrite.ReadGenerationState(path)
		if err != nil || state.Actor != want || state.Generation != generation {
			t.Fatalf("record = %+v, %v; want generation %d by %s", state, err, generation, want)
		}
		return state
	}
	free := func() managedConfigOwnership { return managedConfigOwnership{release: func() {}} }
	writeTestFile(t, path, installed)
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test install"},
		func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, edit)
	recordUnrecordedManagedConfig(path, &strings.Builder{}, free)
	record(configwrite.ActorUnattributedHandEdit, 2)

	// ensure CONFIG=<approved>: the transaction installs and records it, then fails.
	writeTestFile(t, path, approved)
	migrateForTest(t, path, configwrite.SHA256Hex(approved))
	record(configwrite.ActorLifecycle, 3)
	if note, kept := readManagedConfigHandEdit(path); !kept || note.ConfigSHA256 != configwrite.SHA256Hex(edit) {
		t.Fatalf("the run's own record dropped the kept hand edit: %+v, %t", note, kept)
	}
	// The rollback puts the edit back and records it.
	writeTestFile(t, path, edit)
	if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if state := record(configwrite.ActorUnattributedHandEdit, 4); !strings.Contains(state.Reason, "rollback") {
		t.Fatalf("reason = %q", state.Reason)
	}
	recordUnrecordedManagedConfig(path, &strings.Builder{}, free)
	record(configwrite.ActorUnattributedHandEdit, 4)

	// ensure CONFIG=<the edited bytes>: the administrator approves them.
	migrateForTest(t, path, configwrite.SHA256Hex(edit))
	record(configwrite.ActorLifecycle, 5)
	if note, kept := readManagedConfigHandEdit(path); kept {
		t.Fatalf("approved bytes are still kept as a hand edit: %+v", note)
	}
	// A later run and its rollback put the approved bytes back as the lifecycle's.
	writeTestFile(t, path, approved)
	migrateForTest(t, path, configwrite.SHA256Hex(approved))
	record(configwrite.ActorLifecycle, 6)
	writeTestFile(t, path, edit)
	if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	record(configwrite.ActorLifecycle, 7)
}

// A config.hand-edit.json that is not a regular file, does not decode
// or names no sha256 is no evidence: the config step adopts as before.
func TestAKeptEditThatIsNotAPlainRecordIsNoEvidence(t *testing.T) {
	raw := []byte("config_version: 9\nobservability: {}\n")
	valid, err := json.Marshal(managedConfigHandEdit{ConfigSHA256: configwrite.SHA256Hex(raw), Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, notePath string)
		kept  bool
	}{
		{name: "a plain record", kept: true, write: func(t *testing.T, notePath string) { writeTestFile(t, notePath, valid) }},
		{name: "not json", write: func(t *testing.T, notePath string) { writeTestFile(t, notePath, []byte("{")) }},
		{name: "an upper-case sha256", write: func(t *testing.T, notePath string) {
			writeTestFile(t, notePath, []byte(`{"config_sha256":"`+strings.ToUpper(configwrite.SHA256Hex(raw))+`"}`))
		}},
		{name: "a directory", write: func(t *testing.T, notePath string) {
			if err := os.Mkdir(notePath, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a symbolic link to a plain record", write: func(t *testing.T, notePath string) {
			target := filepath.Join(t.TempDir(), "elsewhere.json")
			writeTestFile(t, target, valid)
			if err := os.Symlink(target, notePath); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("symbolic links need a privilege here: %v", err)
				}
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeTestFile(t, path, raw)
			tc.write(t, managedConfigHandEditPath(path))
			if _, kept := managedConfigHandEditOptions(path, raw, "", "test"); kept != tc.kept {
				t.Fatalf("kept = %t, want %t", kept, tc.kept)
			}
		})
	}
}

func migrateForTest(t *testing.T, path, approvedSHA256 string) {
	t.Helper()
	if err := migrateManagedStandaloneConfig(context.Background(), path, approvedSHA256); err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
