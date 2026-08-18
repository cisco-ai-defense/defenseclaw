package cli

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestDiscoverRequiredEndpoints_WithChannels(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"channels": map[string]interface{}{
			"slack":    map[string]interface{}{},
			"telegram": map[string]interface{}{},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	// slack has 2 endpoints, telegram has 1
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(eps), eps)
	}

	hosts := map[string]bool{}
	for _, ep := range eps {
		hosts[ep.Host] = true
	}
	for _, want := range []string{"**.slack.com", "hooks.slack.com", "**.telegram.org"} {
		if !hosts[want] {
			t.Errorf("missing expected host %q", want)
		}
	}
}

func TestDiscoverRequiredEndpoints_WithProviders(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"openai": map[string]interface{}{
					"baseUrl": "https://api.openai.com/v1",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(eps), eps)
	}
	if eps[0].Host != "api.openai.com" {
		t.Errorf("expected host api.openai.com, got %q", eps[0].Host)
	}
	if eps[0].Port != 443 {
		t.Errorf("expected port 443, got %d", eps[0].Port)
	}
}

func TestDiscoverRequiredEndpoints_SkipsLiteLLM(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"litellm": map[string]interface{}{
					"baseUrl": "http://127.0.0.1:4000",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for litellm, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_SkipsLocalhost(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"local": map[string]interface{}{
					"baseUrl": "http://localhost:8080/api",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for localhost, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_MissingFile(t *testing.T) {
	eps := discoverRequiredEndpoints("/nonexistent/path/openclaw.json")

	if eps != nil {
		t.Fatalf("expected nil for missing file, got %+v", eps)
	}
}

func TestDiscoverRequiredEndpoints_EmptyJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, map[string]interface{}{})

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for empty JSON, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_Mixed(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"channels": map[string]interface{}{
			"discord": map[string]interface{}{},
		},
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"anthropic": map[string]interface{}{
					"baseUrl": "https://api.anthropic.com/v1",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	// discord has 2 endpoints + 1 provider endpoint = 3
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(eps), eps)
	}

	sources := map[string]bool{}
	for _, ep := range eps {
		sources[ep.Source] = true
	}
	if !sources["channel:discord"] {
		t.Error("missing channel:discord source")
	}
	if !sources["provider:anthropic"] {
		t.Error("missing provider:anthropic source")
	}
}

func writeJSON(t *testing.T, dir string, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

const policyPathTestModule = `package defenseclaw

import rego.v1

admission := {
	"verdict": "allowed",
	"reason": data.marker,
	"file_action": "allow",
	"install_action": "allow",
	"runtime_action": "allow",
}

firewall := {
	"action": "allow",
	"rule_name": data.marker,
}
`

func TestResolvePolicyPathsLayoutsAndManagedDefaults(t *testing.T) {
	t.Run("canonical preferred", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.rootDir != root || paths.regoDir != canonical || paths.dataPath != filepath.Join(canonical, "data.json") {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("legacy flat", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != root || paths.dataPath != filepath.Join(root, "data.json") {
			t.Fatalf("resolved paths = %#v", paths)
		}
	})

	t.Run("canonical data-only evidence", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), false)
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.regoDir != canonical {
			t.Fatalf("regoDir = %q, want %q", paths.regoDir, canonical)
		}
		if err := policyValidateCmd.RunE(policyValidateCmd, nil); err == nil || !strings.Contains(err.Error(), "no .rego files") {
			t.Fatalf("validate error = %v", err)
		}
	})

	t.Run("configured data directory", func(t *testing.T) {
		dataDir := t.TempDir()
		root := filepath.Join(dataDir, "policies")
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "configured"), true)
		setPolicyPathTestConfig(t, &config.Config{DataDir: dataDir})
		paths, err := resolvePolicyPaths()
		if err != nil || paths.rootDir != root {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})

	t.Run("default managed home", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		root := filepath.Join(home, "policies")
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "default"), true)
		setPolicyPathTestConfig(t, nil)
		paths, err := resolvePolicyPaths()
		if err != nil || paths.rootDir != root {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})
}

func TestResolvePolicyPathsSecurityBoundaries(t *testing.T) {
	t.Run("working directory ignored", func(t *testing.T) {
		trustedRoot := filepath.Join(t.TempDir(), "missing-policies")
		untrusted := t.TempDir()
		writePolicyPathTestLayout(t, filepath.Join(untrusted, "policies", "rego"), policyPathTestData(t, "untrusted"), true)
		previous, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(untrusted); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chdir(previous) })
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: trustedRoot})
		paths, err := resolvePolicyPaths()
		if err != nil {
			t.Fatal(err)
		}
		if paths.dataPath != filepath.Join(trustedRoot, "rego", "data.json") {
			t.Fatalf("dataPath = %q", paths.dataPath)
		}
		if err := policyShowCmd.RunE(policyShowCmd, nil); err == nil || !strings.Contains(err.Error(), "data.json") {
			t.Fatalf("show error = %v", err)
		}
	})

	for _, test := range []struct {
		name string
		root string
		want string
	}{
		{name: "relative", root: filepath.Join("relative", "policies"), want: "absolute"},
		{name: "parent segment", root: t.TempDir() + string(filepath.Separator) + "scope" + string(filepath.Separator) + ".." + string(filepath.Separator) + "policies", want: "parent segment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setPolicyPathTestConfig(t, &config.Config{PolicyDir: test.root})
			_, err := resolvePolicyPaths()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	t.Run("sibling prefix containment", func(t *testing.T) {
		root := t.TempDir()
		if !policyPathContained(root, filepath.Join(root, "rego", "data.json")) {
			t.Fatal("contained path rejected")
		}
		if policyPathContained(root, root+"-sibling"+string(filepath.Separator)+"data.json") {
			t.Fatal("sibling prefix accepted")
		}
	})

	t.Run("deeper generation", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, filepath.Join(canonical, "rego"), policyPathTestData(t, "deeper"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if _, err := resolvePolicyPaths(); err == nil || !strings.Contains(err.Error(), "unsupported nested") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("redirected supplemental data", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		target := filepath.Join(t.TempDir(), "data-sandbox.json")
		if err := os.WriteFile(target, []byte(`{"outside":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(canonical, "data-sandbox.json")); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if _, err := resolvePolicyPaths(); err == nil || !strings.Contains(err.Error(), "supplemental") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestResolvePolicyPathsIgnoresUnusedFlatResidue(t *testing.T) {
	t.Run("nonregular custom module", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		if err := os.Mkdir(filepath.Join(root, "custom.rego"), 0o700); err != nil {
			t.Fatal(err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if paths, err := resolvePolicyPaths(); err != nil || paths.regoDir != canonical {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})

	t.Run("legacy data alias", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		writePolicyPathTestLayout(t, canonical, policyPathTestData(t, "canonical"), true)
		if err := os.Symlink(filepath.Join(canonical, "data.json"), filepath.Join(root, "data.json")); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		if paths, err := resolvePolicyPaths(); err != nil || paths.regoDir != canonical {
			t.Fatalf("paths = %#v, error = %v", paths, err)
		}
	})
}

func TestPolicyCommandsUseSelectedAndEffectiveData(t *testing.T) {
	t.Run("canonical", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, filepath.Join(root, "rego"), policyPathTestData(t, "canonical"), true)
		writePolicyPathTestLayout(t, root, []byte("{"), false)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})

	t.Run("legacy", func(t *testing.T) {
		root := t.TempDir()
		writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		requirePolicyPathCommandsSucceed(t)
	})

	t.Run("supplemental", func(t *testing.T) {
		root := t.TempDir()
		canonical := filepath.Join(root, "rego")
		base, err := json.Marshal(map[string]interface{}{
			"marker": "base", "config": map[string]interface{}{}, "actions": map[string]interface{}{}, "severity_ranking": map[string]interface{}{},
		})
		if err != nil {
			t.Fatal(err)
		}
		writePolicyPathTestLayout(t, canonical, base, true)
		supplemental, err := json.Marshal(map[string]interface{}{
			"marker": "supplemental",
			"firewall": map[string]interface{}{
				"default_action": "allow", "blocked_destinations": []string{}, "allowed_domains": []string{"supplemental.example.invalid"}, "allowed_ports": []int{443},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(canonical, "data-sandbox.json"), supplemental, 0o600); err != nil {
			t.Fatal(err)
		}
		setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
		setPolicyPathTestFlags(t)
		if err := policyValidateCmd.RunE(policyValidateCmd, nil); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name string
			cmd  *cobra.Command
			want string
		}{
			{name: "show", cmd: policyShowCmd, want: `"marker": "supplemental"`},
			{name: "evaluate", cmd: policyEvaluateCmd, want: `"reason": "supplemental"`},
			{name: "firewall", cmd: policyEvaluateFirewallCmd, want: `"rule_name": "supplemental"`},
			{name: "domains", cmd: policyDomainsCmd, want: "supplemental.example.invalid"},
		} {
			t.Run(test.name, func(t *testing.T) {
				output, err := capturePolicyPathTestOutput(t, func() error { return test.cmd.RunE(test.cmd, nil) })
				if err != nil || !strings.Contains(output, test.want) {
					t.Fatalf("output = %q, error = %v, want %q", output, err, test.want)
				}
			})
		}
	})
}

func TestPolicyCommandsFailClosedOnCanonicalData(t *testing.T) {
	for _, test := range []struct {
		name         string
		base         []byte
		supplemental []byte
	}{
		{name: "missing", base: nil},
		{name: "malformed", base: []byte("{")},
		{name: "null", base: []byte("null")},
		{name: "malformed supplemental", base: policyPathTestData(t, "canonical"), supplemental: []byte("{")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			canonical := filepath.Join(root, "rego")
			writePolicyPathTestLayout(t, canonical, test.base, true)
			writePolicyPathTestLayout(t, root, policyPathTestData(t, "legacy"), true)
			if test.supplemental != nil {
				if err := os.WriteFile(filepath.Join(canonical, "data-sandbox.json"), test.supplemental, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			setPolicyPathTestConfig(t, &config.Config{PolicyDir: root})
			setPolicyPathTestFlags(t)
			for _, command := range policyPathTestCommands() {
				t.Run(command.name, func(t *testing.T) {
					if err := command.cmd.RunE(command.cmd, nil); err == nil {
						t.Fatalf("%s accepted %s canonical data", command.name, test.name)
					}
				})
			}
		})
	}
}

func TestPolicyReloadRemainsPathIndependent(t *testing.T) {
	const token = "reload-fixture-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/policy/reload" || r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-DefenseClaw-Token") != token {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	setPolicyPathTestConfig(t, &config.Config{
		PolicyDir: filepath.Join("relative", "untrusted"),
		Gateway:   config.GatewayConfig{APIBind: host, APIPort: port, Token: token},
	})
	if err := policyReloadCmd.RunE(policyReloadCmd, nil); err != nil {
		t.Fatalf("reload resolved local policy paths: %v", err)
	}
}

func policyPathTestCommands() []struct {
	name string
	cmd  *cobra.Command
} {
	return []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "validate", cmd: policyValidateCmd},
		{name: "show", cmd: policyShowCmd},
		{name: "evaluate", cmd: policyEvaluateCmd},
		{name: "evaluate-firewall", cmd: policyEvaluateFirewallCmd},
		{name: "domains", cmd: policyDomainsCmd},
	}
}

func setPolicyPathTestConfig(t *testing.T, value *config.Config) {
	t.Helper()
	previous := cfg
	cfg = value
	t.Cleanup(func() { cfg = previous })
}

func setPolicyPathTestFlags(t *testing.T) {
	t.Helper()
	setPolicyPathTestFlag(t, policyEvaluateCmd, "target-name", "fixture")
	setPolicyPathTestFlag(t, policyEvaluateFirewallCmd, "destination", "example.invalid")
}

func setPolicyPathTestFlag(t *testing.T, command *cobra.Command, name, value string) {
	t.Helper()
	flag := command.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("missing flag %s", name)
	}
	previousValue := flag.Value.String()
	previousChanged := flag.Changed
	if err := command.Flags().Set(name, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Flags().Set(name, previousValue)
		flag.Changed = previousChanged
	})
}

func requirePolicyPathCommandsSucceed(t *testing.T) {
	t.Helper()
	for _, command := range policyPathTestCommands() {
		if _, err := capturePolicyPathTestOutput(t, func() error { return command.cmd.RunE(command.cmd, nil) }); err != nil {
			t.Fatalf("%s failed: %v", command.name, err)
		}
	}
}

func policyPathTestData(t *testing.T, marker string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]interface{}{
		"marker": marker, "config": map[string]interface{}{}, "actions": map[string]interface{}{}, "severity_ranking": map[string]interface{}{},
		"firewall": map[string]interface{}{
			"default_action": "allow", "blocked_destinations": []string{}, "allowed_domains": []string{marker + ".example.invalid"}, "allowed_ports": []int{443},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writePolicyPathTestLayout(t *testing.T, dir string, data []byte, withModule bool) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if withModule {
		if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policyPathTestModule), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if data != nil {
		if err := os.WriteFile(filepath.Join(dir, "data.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func capturePolicyPathTestOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	runErr := run()
	os.Stdout = previous
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(raw), runErr
}
