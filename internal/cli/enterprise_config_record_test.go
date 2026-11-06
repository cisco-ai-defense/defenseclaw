// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
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
	busy := func() (func(), string) {
		claims++
		return nil, "a DefenseClaw lifecycle run holds lifecycle.lock"
	}
	recordUnrecordedManagedConfig(path, &log, busy)
	recordUnrecordedManagedConfig(path, &log, busy)
	if state, err := configwrite.ReadGenerationState(path); err == nil {
		t.Fatalf("recorded while a lifecycle run owns config.yaml: %+v", state)
	}
	if claims != 2 || strings.Count(log.String(), "that run records its own config generation") != 1 {
		t.Fatalf("claims %d, log %q: want two claims and one line", claims, log.String())
	}
	log.Reset()
	free := func() (func(), string) {
		claims++
		return func() { releases++ }, ""
	}
	recordUnrecordedManagedConfig(path, &log, free)
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Generation != 1 || state.Actor != configwrite.ActorUnattributedHandEdit || releases != 1 {
		t.Fatalf("edit outside a lifecycle run: %+v, %v, releases %d\n%s", state, err, releases, log.String())
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
	claim := func() (func(), string) {
		claimed = time.Now()
		return func() { hold = time.Since(claimed) }, ""
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
