package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2628: a configured skill root the watcher cannot create when it starts
// (its parent is made later, for example an admin-only folder) is watched
// once it exists: a skill already in it and one copied in later both get an
// install verdict instead of the root being skipped for good.
func TestWatcherWatchesASkillRootThatCouldNotBeCreatedOnceItExists(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	for _, name := range []string{"early", "later"} {
		cfg.AssetPolicy.Skill.Allowed = append(cfg.AssetPolicy.Skill.Allowed, config.AssetPolicyRule{Name: name, Reason: "pre-approved"})
	}
	// A file where the parent folder should be makes MkdirAll fail on
	// every OS, as the admin-only parent does for the service account.
	parent := filepath.Join(filepath.Dir(skillDir), "approved")
	if err := os.WriteFile(parent, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(parent, "X")
	admitted := make(chan string, 8)
	w := New(cfg, []string{skillDir, missing}, nil, store, logger, nil, func(r AdmissionResult) { admitted <- r.Event.Name })
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	defer func() { cancel(); <-errCh }()
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-errCh:
		errCh <- err // the deferred stop reads it again
		t.Fatalf("watcher stopped with only a missing root: %v", err)
	default:
	}

	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(missing, "early"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missing, "early", "SKILL.md"), []byte("# early\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait := func(name string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case got := <-admitted:
				if got == name {
					return
				}
			case <-deadline:
				t.Fatalf("skill %s in the late root got no admission", name)
			}
		}
	}
	wait("early")
	later := filepath.Join(missing, "later")
	if err := os.Mkdir(later, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(later, "SKILL.md"), []byte("# later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("later")
}
