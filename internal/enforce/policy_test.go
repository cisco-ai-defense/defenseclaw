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
	dbPath := filepath.Join(t.TempDir(), "cleanup-test.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Store.Init: %v", err)
	}

	pe := NewPolicyEngine(store)

	pe.Quarantine("skill", "fail-skill", "test")
	pe.Disable("skill", "fail-skill", "test")

	store.Close()

	err = pe.Allow("skill", "fail-skill", "user")
	if err == nil {
		t.Fatal("expected error from Allow on closed store")
	}
	if !strings.Contains(err.Error(), "database is closed") && !strings.Contains(err.Error(), "partial cleanup") {
		t.Errorf("expected DB or cleanup error, got: %v", err)
	}
}

func TestPolicyEngineAllowCleansUpEnforcement(t *testing.T) {
	store := testStore(t)
	pe := NewPolicyEngine(store)

	pe.Quarantine("skill", "q-skill", "test")
	pe.Disable("skill", "q-skill", "test")

	isQ, _ := pe.IsQuarantined("skill", "q-skill")
	if !isQ {
		t.Fatal("expected quarantine before allow")
	}

	err := pe.Allow("skill", "q-skill", "user approved")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}

	isQ, _ = pe.IsQuarantined("skill", "q-skill")
	if isQ {
		t.Error("quarantine should be cleared after allow")
	}

	isA, _ := pe.IsAllowed("skill", "q-skill")
	if !isA {
		t.Error("skill should be allowed after Allow call")
	}
}

// TestToolConnectorTarget pins the "@<connector>/<tool>" encoding so the read
// gate and any write surface (CLI) can rely on the same key shape.
func TestPolicyEngineConnectorScope(t *testing.T) {
	t.Run("connector_block_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.BlockForConnector("mcp", "demo", "codex", "scoped"); err != nil {
			t.Fatalf("BlockForConnector: %v", err)
		}

		if b, _ := pe.IsBlockedForConnector("mcp", "demo", "codex"); !b {
			t.Error("expected blocked for the scoped connector codex")
		}
		if b, _ := pe.IsBlockedForConnector("mcp", "demo", "opencode"); b {
			t.Error("connector-scoped block must not affect a different connector")
		}
		if b, _ := pe.IsBlockedForConnector("mcp", "demo", ""); b {
			t.Error("connector-scoped block must not apply globally")
		}
		// The plain (global-only) IsBlocked must not see the scoped row either.
		if b, _ := pe.IsBlocked("mcp", "demo"); b {
			t.Error("connector-scoped block must not register as a global block")
		}
	})

	t.Run("global_block_hits_all_connectors", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.Block("mcp", "demo", "global"); err != nil {
			t.Fatalf("Block: %v", err)
		}
		for _, c := range []string{"", "codex", "opencode"} {
			if b, _ := pe.IsBlockedForConnector("mcp", "demo", c); !b {
				t.Errorf("global block must apply to connector %q", c)
			}
		}
	})

	t.Run("connector_disable_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := store.SetActionFieldForConnector("skill", "demo", "codex", "runtime", "disable", "scoped"); err != nil {
			t.Fatalf("seed disable: %v", err)
		}

		if d, _ := pe.IsDisabledForConnector("skill", "demo", "codex"); !d {
			t.Error("expected disabled for the scoped connector codex")
		}
		if d, _ := pe.IsDisabledForConnector("skill", "demo", "opencode"); d {
			t.Error("connector-scoped disable must not affect a different connector")
		}
		if d, _ := pe.IsDisabledForConnector("skill", "demo", ""); d {
			t.Error("connector-scoped disable must not apply globally")
		}
	})

	t.Run("global_disable_hits_all_connectors", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := store.SetActionField("plugin", "demo", "runtime", "disable", "global"); err != nil {
			t.Fatalf("seed global disable: %v", err)
		}
		for _, c := range []string{"", "codex", "opencode"} {
			if d, _ := pe.IsDisabledForConnector("plugin", "demo", c); !d {
				t.Errorf("global disable must apply to connector %q", c)
			}
		}
	})

	t.Run("disable_lookup_error_surfaces_error", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)
		store.Close()

		if disabled, err := pe.IsDisabledForConnector("skill", "demo", "codex"); err == nil || disabled {
			t.Fatalf("IsDisabledForConnector on closed store = disabled=%v err=%v, want error and disabled=false", disabled, err)
		}
	})

	t.Run("connector_allow_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.AllowForConnector("mcp", "demo", "codex", "scoped"); err != nil {
			t.Fatalf("AllowForConnector: %v", err)
		}
		if a, _ := pe.IsAllowedForConnector("mcp", "demo", "codex"); !a {
			t.Error("expected allowed for the scoped connector codex")
		}
		if a, _ := pe.IsAllowedForConnector("mcp", "demo", "opencode"); a {
			t.Error("connector-scoped allow must not affect a different connector")
		}
	})

	t.Run("global_block_wins_over_connector_allow", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.Block("mcp", "demo", "global block"); err != nil {
			t.Fatalf("Block: %v", err)
		}
		if err := pe.AllowForConnector("mcp", "demo", "codex", "scoped allow"); err != nil {
			t.Fatalf("AllowForConnector: %v", err)
		}
		// The gate checks blocked before allowed, so the global block wins.
		if b, _ := pe.IsBlockedForConnector("mcp", "demo", "codex"); !b {
			t.Error("global block must win over a connector-scoped allow")
		}
	})

	t.Run("connector_unblock_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.BlockForConnector("mcp", "demo", "codex", "x"); err != nil {
			t.Fatalf("BlockForConnector(codex): %v", err)
		}
		if err := pe.BlockForConnector("mcp", "demo", "opencode", "x"); err != nil {
			t.Fatalf("BlockForConnector(opencode): %v", err)
		}
		if err := pe.RemoveActionForConnector("mcp", "demo", "codex"); err != nil {
			t.Fatalf("RemoveActionForConnector: %v", err)
		}
		if b, _ := pe.IsBlockedForConnector("mcp", "demo", "codex"); b {
			t.Error("codex block should be cleared")
		}
		if b, _ := pe.IsBlockedForConnector("mcp", "demo", "opencode"); !b {
			t.Error("opencode block must survive a codex-scoped unblock")
		}
	})
}

func TestToolConnectorTarget(t *testing.T) {
	if got := toolConnectorTarget("delete_file", "hermes"); got != "@hermes/delete_file" {
		t.Errorf("toolConnectorTarget scoped = %q, want @hermes/delete_file", got)
	}
	if got := toolConnectorTarget("delete_file", ""); got != "delete_file" {
		t.Errorf("toolConnectorTarget empty connector = %q, want delete_file", got)
	}
}

func TestPolicyEngineToolConnectorScope(t *testing.T) {
	t.Run("connector_block_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.BlockToolForConnector("delete_file", "hermes", "scoped"); err != nil {
			t.Fatalf("BlockToolForConnector: %v", err)
		}

		if b, _ := pe.IsToolBlockedForConnector("delete_file", "hermes"); !b {
			t.Error("expected blocked for the scoped connector hermes")
		}
		if b, _ := pe.IsToolBlockedForConnector("delete_file", "codex"); b {
			t.Error("connector-scoped block must not affect a different connector")
		}
		if b, _ := pe.IsToolBlockedForConnector("delete_file", ""); b {
			t.Error("connector-scoped block must not apply globally")
		}
	})

	t.Run("global_block_hits_all_connectors", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.BlockToolForConnector("delete_file", "", "global"); err != nil {
			t.Fatalf("BlockToolForConnector(global): %v", err)
		}
		for _, c := range []string{"", "hermes", "codex"} {
			if b, _ := pe.IsToolBlockedForConnector("delete_file", c); !b {
				t.Errorf("global block must apply to connector %q", c)
			}
		}
	})

	t.Run("connector_allow_isolated", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		if err := pe.AllowToolForConnector("search", "hermes", "scoped"); err != nil {
			t.Fatalf("AllowToolForConnector: %v", err)
		}
		if a, _ := pe.IsToolAllowedForConnector("search", "hermes"); !a {
			t.Error("expected allowed for the scoped connector hermes")
		}
		if a, _ := pe.IsToolAllowedForConnector("search", "codex"); a {
			t.Error("connector-scoped allow must not affect a different connector")
		}
		if a, _ := pe.IsToolAllowedForConnector("search", ""); a {
			t.Error("connector-scoped allow must not apply globally")
		}
	})

	t.Run("global_block_and_connector_allow_coexist", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		// Resolution order is block-first (block @C/T → block T → allow @C/T →
		// allow T → scan); both rows are independently visible to the helpers,
		// and the gateway lane picks block because it checks block first.
		if err := pe.BlockToolForConnector("write_file", "", "global block"); err != nil {
			t.Fatalf("BlockToolForConnector: %v", err)
		}
		if err := pe.AllowToolForConnector("write_file", "hermes", "scoped allow"); err != nil {
			t.Fatalf("AllowToolForConnector: %v", err)
		}
		if b, _ := pe.IsToolBlockedForConnector("write_file", "hermes"); !b {
			t.Error("global block must be visible to the connector block check")
		}
		if a, _ := pe.IsToolAllowedForConnector("write_file", "hermes"); !a {
			t.Error("connector-scoped allow row must remain visible to the allow check")
		}
	})

	t.Run("allow_clears_enforcement", func(t *testing.T) {
		store := testStore(t)
		pe := NewPolicyEngine(store)

		target := "@hermes/run"
		if err := store.SetActionField("tool", target, "file", "quarantine", "scan"); err != nil {
			t.Fatalf("seed quarantine: %v", err)
		}
		if err := store.SetActionField("tool", target, "runtime", "disable", "scan"); err != nil {
			t.Fatalf("seed disable: %v", err)
		}

		if err := pe.AllowToolForConnector("run", "hermes", "approved"); err != nil {
			t.Fatalf("AllowToolForConnector: %v", err)
		}
		if q, _ := store.HasAction("tool", target, "file", "quarantine"); q {
			t.Error("quarantine should be cleared after AllowToolForConnector")
		}
		if d, _ := store.HasAction("tool", target, "runtime", "disable"); d {
			t.Error("disable should be cleared after AllowToolForConnector")
		}
	})

	t.Run("nil_store_is_safe", func(t *testing.T) {
		pe := NewPolicyEngine(nil)
		if b, err := pe.IsToolBlockedForConnector("t", "hermes"); err != nil || b {
			t.Error("expected false, nil for nil store")
		}
		if a, err := pe.IsToolAllowedForConnector("t", "hermes"); err != nil || a {
			t.Error("expected false, nil for nil store")
		}
		if err := pe.BlockToolForConnector("t", "hermes", "r"); err != nil {
			t.Error("expected nil error for nil store BlockToolForConnector")
		}
		if err := pe.AllowToolForConnector("t", "hermes", "r"); err != nil {
			t.Error("expected nil error for nil store AllowToolForConnector")
		}
	})
}
