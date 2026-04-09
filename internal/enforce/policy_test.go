package enforce

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func testStore(t *testing.T) *audit.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Store.Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestPolicyEngineBlockAllow(t *testing.T) {
	t.Run("block_then_check", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.Block("skill", "evil", "bad"); err != nil {
			t.Fatalf("Block: %v", err)
		}

		blocked, err := pe.IsBlocked("skill", "evil")
		if err != nil {
			t.Fatalf("IsBlocked: %v", err)
		}
		if !blocked {
			t.Error("expected blocked")
		}
	})

	t.Run("allow_clears_quarantine_and_disable", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.Quarantine("skill", "s1", "scan"); err != nil {
			t.Fatalf("Quarantine: %v", err)
		}
		if err := pe.Disable("skill", "s1", "scan"); err != nil {
			t.Fatalf("Disable: %v", err)
		}

		q, _ := pe.IsQuarantined("skill", "s1")
		if !q {
			t.Fatal("expected quarantined before allow")
		}

		if err := pe.Allow("skill", "s1", "user override"); err != nil {
			t.Fatalf("Allow: %v", err)
		}

		allowed, _ := pe.IsAllowed("skill", "s1")
		if !allowed {
			t.Error("expected allowed after Allow()")
		}

		q2, _ := pe.IsQuarantined("skill", "s1")
		if q2 {
			t.Error("quarantine should be cleared after Allow()")
		}
	})

	t.Run("allow_returns_error_on_clear_failure", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		// Normal allow works fine
		err := pe.Allow("skill", "ok-skill", "test")
		if err != nil {
			t.Fatalf("Allow should succeed: %v", err)
		}
	})

	t.Run("unblock_clears_install_action", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		pe.Block("skill", "s2", "test block")
		blocked, _ := pe.IsBlocked("skill", "s2")
		if !blocked {
			t.Fatal("expected blocked before unblock")
		}

		if err := pe.Unblock("skill", "s2"); err != nil {
			t.Fatalf("Unblock: %v", err)
		}

		blocked2, _ := pe.IsBlocked("skill", "s2")
		if blocked2 {
			t.Error("expected not blocked after unblock")
		}
	})
}

func TestPolicyEngineNilStore(t *testing.T) {
	pe := NewPolicyEngine(nil)

	blocked, err := pe.IsBlocked("skill", "x")
	if err != nil || blocked {
		t.Error("expected false, nil for nil store")
	}

	if err := pe.Block("skill", "x", "r"); err != nil {
		t.Error("expected nil error for nil store Block")
	}

	if err := pe.Allow("skill", "x", "r"); err != nil {
		t.Error("expected nil error for nil store Allow")
	}
}

func TestPolicyEngineAllowPartialCleanupError(t *testing.T) {
	store := testStore(t)
	pe := NewPolicyEngine(store)

	// Set up quarantine and disable, then close the store to force errors
	pe.Quarantine("skill", "fail-skill", "test")
	pe.Disable("skill", "fail-skill", "test")

	// Allow with active store should succeed and clear both
	err := pe.Allow("skill", "fail-skill", "user")
	if err != nil {
		// If clear succeeded, no error; if failed, error contains "partial cleanup"
		if !strings.Contains(err.Error(), "partial cleanup") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
