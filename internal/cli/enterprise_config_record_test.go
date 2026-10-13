// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	recordUnrecordedManagedConfig(path, &log)
	first := generation()
	if first.Generation != 1 || !configwrite.IsHandEditActor(first.Actor) || !strings.Contains(log.String(), "recorded as config generation 1") {
		t.Fatalf("first record: %+v\n%s", first, log.String())
	}
	log.Reset()
	recordUnrecordedManagedConfig(path, &log)
	if again := generation(); again.Generation != 1 || log.Len() != 0 {
		t.Fatalf("a recorded config was recorded again: %+v\n%s", again, log.String())
	}
	write("config_version: 9\n# edited\n")
	recordUnrecordedManagedConfig(path, &log)
	if edited := generation(); edited.Generation != 2 || edited.ConfigSHA256 == first.ConfigSHA256 {
		t.Fatalf("an edit did not advance the generation: %+v", edited)
	}
	// A config the lifecycle wrote is recorded by its writer (actor
	// lifecycle) and is not turned into a hand edit.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, []byte("config_version: 9\n# lifecycle\n"),
		configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "test"}); err != nil {
		t.Skipf("the writer does not accept the minimal config here: %v", err)
	}
	recordUnrecordedManagedConfig(path, &log)
	if state := generation(); state.Generation != 3 || state.Actor != configwrite.ActorLifecycle {
		t.Fatalf("a lifecycle write was re-recorded: %+v", state)
	}
	recordUnrecordedManagedConfig(filepath.Join(t.TempDir(), "missing.yaml"), &log)
}
