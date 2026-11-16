package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A hook call asks the audit store whether any skill is denied or held before
// it reads the call for skill folders. That question must not make the call
// wait on a connection something else keeps.
func TestSkillFoldersAreGuardedAnswersWhileTheStoreConnectionIsHeld(t *testing.T) {
	store, _ := testStoreAndLogger(t)
	api := &APIServer{store: store}
	cfg := &config.Config{}

	if api.skillFoldersAreGuarded(context.Background(), cfg) {
		t.Fatal("no skill is denied or held, yet the folders count as guarded")
	}
	if err := store.SetActionFieldForConnector("skill", "held-skill", "codex", "runtime", "disable", "manual"); err != nil {
		t.Fatal(err)
	}
	if !api.skillFoldersAreGuarded(context.Background(), cfg) {
		t.Fatal("a held skill exists, yet the folders do not count as guarded")
	}
	if err := store.SetActionFieldForConnector("skill", "held-skill", "codex", "runtime", "enable", "manual"); err != nil {
		t.Fatal(err)
	}
	if api.skillFoldersAreGuarded(context.Background(), cfg) {
		t.Fatal("the skill was released, yet the folders count as guarded")
	}

	batch, err := store.BeginJudgeBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = batch.Rollback() }()
	started := time.Now()
	guarded := api.skillFoldersAreGuarded(context.Background(), cfg)
	elapsed := time.Since(started)
	if !guarded {
		t.Error("the store did not answer, yet the folders do not count as guarded (fail closed)")
	}
	if elapsed > 4*skillGuardReadWait {
		t.Errorf("the guard question waited %v on the held connection, want about %v", elapsed, skillGuardReadWait)
	}
}
