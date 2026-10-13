package enforce

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// TestPolicyEngineOperatorListsComeFromConfig pins config_version 9: operator
// block/allow answers come from asset_policy, a connector-scoped rule decides
// before an unscoped one, and a journal install block is not policy.
func TestPolicyEngineOperatorListsComeFromConfig(t *testing.T) {
	store := testStore(t)
	cfg := config.DefaultConfig()
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "demo"}}
	cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "demo", Connector: "codex"}}
	cfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "shell", Connector: "codex"}}
	cfg.AssetPolicy.Tool.Allowed = []config.AssetPolicyToolRule{{Name: "shell"}}
	pe := NewPolicyEngine(store).WithConfig(func() *config.Config { return cfg })

	if b, _ := pe.IsBlockedForConnector("mcp", "demo", "opencode"); !b {
		t.Error("global deny must block opencode")
	}
	if b, _ := pe.IsBlockedForConnector("mcp", "demo", "codex"); b {
		t.Error("codex-scoped allow must override the global deny")
	}
	if a, _ := pe.IsAllowedForConnector("mcp", "demo", "codex"); !a {
		t.Error("codex-scoped allow must allow codex")
	}
	if b, _ := pe.IsToolBlockedForConnector("shell", "codex"); !b {
		t.Error("codex-scoped tool deny must block codex")
	}
	if b, _ := pe.IsToolBlockedForConnector("shell", "claudecode"); b {
		t.Error("codex-scoped tool deny must not block claudecode")
	}
	if a, _ := pe.IsToolAllowedForConnector("shell", "claudecode"); !a {
		t.Error("global tool allow must allow claudecode")
	}

	if err := pe.Block("skill", "auto", "auto-block: watch detected HIGH findings"); err != nil {
		t.Fatal(err)
	}
	if b, _ := pe.IsBlockedForConnector("skill", "auto", ""); b {
		t.Error("a journal install block must not be read as an operator block")
	}
	if b, _ := pe.JournalInstallBlocked("skill", "auto", ""); !b {
		t.Error("JournalInstallBlocked must see the watcher's block")
	}
}

// TestPolicyEngineSecureClientKeepsActionRows: Secure Client hosts keep
// reading operator rows from the actions table, byte for byte as before.
func TestPolicyEngineSecureClientKeepsActionRows(t *testing.T) {
	store := testStore(t)
	cfg := config.DefaultConfig()
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	pe := NewPolicyEngine(store).WithConfig(func() *config.Config { return cfg })
	if err := store.SetActionField("tool", "@codex/shell", "install", "block", "operator"); err != nil {
		t.Fatal(err)
	}
	if b, _ := pe.IsToolBlockedForConnector("shell", "codex"); !b {
		t.Error("Secure Client must read the scoped tool row")
	}
}

func TestPolicyEngineJournalDisable(t *testing.T) {
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

}

// GAP-0992: a command-pinned rule must resolve the connector's MCP server
// before the runtime tool-call reader decides whether to block it.
func TestMCPRuntimeBlockReadsCommandPins(t *testing.T) {
	cfg := config.DefaultConfig()
	path := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(path, []byte(`{"mcp":{"servers":{"demo":{"command":"npx","args":["-y","approved"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = path
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{
		Name: "demo", Command: "npx", ArgsPrefix: []string{"-y", "approved"},
	}}
	pe := NewPolicyEngine(nil).WithConfig(func() *config.Config { return cfg })
	blocked, err := pe.IsMCPBlockedForConnector("demo", "openclaw")
	if err != nil || !blocked {
		t.Fatalf("command-pinned runtime deny = %v, %v; want blocked", blocked, err)
	}
}
