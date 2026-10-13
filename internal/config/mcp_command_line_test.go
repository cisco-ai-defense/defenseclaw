package config

import "testing"

func TestCodexWholeTableOverrideMergesExistingServer(t *testing.T) {
	base := []MCPServerEntry{{Name: "approved", URL: "https://approved.example/mcp"}}
	entries, touched, exclusive, err := applyCodexMCPOverrides(base, []string{
		`mcp_servers={added={url="https://added.example/mcp"}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exclusive || touched["approved"] {
		t.Fatalf("whole-table override hid the configured server: exclusive=%v touched=%v", exclusive, touched)
	}
	approved, found := lookupMCPToolServer("codex", entries, "approved")
	if !found || approved.URL != base[0].URL {
		t.Fatalf("configured server after override = %+v, found=%v", approved, found)
	}
	if added, found := lookupMCPToolServer("codex", entries, "added"); !found || added.URL != "https://added.example/mcp" {
		t.Fatalf("added server = %+v, found=%v", added, found)
	}
}
