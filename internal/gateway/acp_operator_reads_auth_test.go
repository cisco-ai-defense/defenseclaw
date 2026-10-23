package gateway

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The operator read-only ACP routes (/v1/acp/catalog, /v1/acp/profiles) are
// management reads and must authenticate with the gateway token, exactly as
// docs/reference/gateway-api.mdx states ("everything but GET /health
// authenticates with the gateway token"; only the two POST /api/v1/acp/*
// routes use their own scheme). The ACP bearer branch of tokenAuth used to
// match the whole "/v1/acp/" prefix, so on loopback an ACP scoped credential
// authenticated these reads while the configured gateway token was refused
// 401 before its comparison ever ran. These tests pin the restored contract
// from both sides: the scoped token must not open the operator reads, and
// the gateway token must.
func newACPOperatorReadsTestServer(t *testing.T) (*APIServer, http.HandlerFunc, string, string) {
	t.Helper()
	const acpToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const gatewayToken = "test-gateway-token-operator-reads"
	dataDir := writePrivateACPToken(t, acpToken)
	cfg := acpGatewayTestConfig(dataDir, "")
	cfg.Gateway.Token = gatewayToken
	api := &APIServer{scannerCfg: cfg}
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/acp/profiles":
			api.handleACPProfiles(w, r)
		case "/v1/acp/catalog":
			api.handleACPCatalog(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return api, dispatch, acpToken, gatewayToken
}

func serveACPOperatorRead(api *APIServer, dispatch http.Handler, method, path, bearer, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	api.tokenAuth(api.apiCSRFProtect(dispatch)).ServeHTTP(rec, req)
	return rec
}

func TestACPScopedTokenDoesNotAuthenticateOperatorReads(t *testing.T) {
	api, dispatch, acpToken, gatewayToken := newACPOperatorReadsTestServer(t)
	const loopback = "127.0.0.1:45678"
	const remote = "192.0.2.50:45678"

	for _, path := range []string{"/v1/acp/profiles", "/v1/acp/catalog"} {
		if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, path, acpToken, loopback); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with the ACP scoped token from loopback: status = %d, want 401", path, rec.Code)
		}
		// Off-loopback the ACP branch never applies; a token that is not
		// the gateway token must still be refused.
		if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, path, acpToken, remote); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with the ACP scoped token from a remote address: status = %d, want 401", path, rec.Code)
		}
		if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, path, "0000", loopback); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with a garbage token: status = %d, want 401", path, rec.Code)
		}
	}

	// The guard's own routes keep their signed-request scheme: a plain
	// bearer - even the correct ACP token - never reaches the evaluator.
	if rec := serveACPOperatorRead(api, dispatch, http.MethodPost, "/api/v1/acp/evaluate", acpToken, loopback); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/acp/evaluate with a plain bearer: status = %d, want 401", rec.Code)
	}

	// The scoped token must not gain authority over unrelated management
	// routes either; this handler stands in for one.
	management := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if rec := serveACPOperatorRead(api, management, http.MethodGet, "/status", acpToken, loopback); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /status with the ACP scoped token: status = %d, want 401", rec.Code)
	}
	_ = gatewayToken
}

func TestACPOperatorReadsAuthenticateWithGatewayToken(t *testing.T) {
	api, dispatch, acpToken, gatewayToken := newACPOperatorReadsTestServer(t)
	const loopback = "127.0.0.1:45678"
	const remote = "192.0.2.50:45678"

	rec := serveACPOperatorRead(api, dispatch, http.MethodGet, "/v1/acp/profiles", gatewayToken, loopback)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/acp/profiles with the gateway token from loopback: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"enabled":true`, `"default_profile":"locked"`, `"profiles"`, `"denied_methods"`} {
		if !strings.Contains(body, want) {
			t.Errorf("profiles body missing %s: %s", want, body)
		}
	}
	if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, "/v1/acp/catalog", gatewayToken, loopback); rec.Code != http.StatusOK {
		t.Errorf("GET /v1/acp/catalog with the gateway token from loopback: status = %d, want 200", rec.Code)
	}
	// The management client calls from off-loopback too; the gateway token
	// is the credential there, so it must keep working.
	if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, "/v1/acp/profiles", gatewayToken, remote); rec.Code != http.StatusOK {
		t.Errorf("GET /v1/acp/profiles with the gateway token from a remote address: status = %d, want 200", rec.Code)
	}
	_ = acpToken
}

// The config the profiles handler returns is the running ACP posture, so a
// second profile must appear in the read - the fleet-scope object the
// operator inspects and the earlier overreach disclosed.
func TestACPOperatorProfilesReadCoversEveryProfile(t *testing.T) {
	api, dispatch, _, gatewayToken := newACPOperatorReadsTestServer(t)
	api.scannerCfg.ACP.Profiles = map[string]config.ACPProfile{
		"locked":        {Mode: "action", AllowedClients: []string{"zed"}, AllowedAgents: []string{"kiro"}, DeniedMethods: []string{"session/prompt"}},
		"finance-tower": {Mode: "action", AllowedClients: []string{"vscode"}, AllowedAgents: []string{"finance-agent"}, DeniedMethods: []string{"terminal/exec"}},
	}
	rec := serveACPOperatorRead(api, dispatch, http.MethodGet, "/v1/acp/profiles", gatewayToken, "127.0.0.1:45678")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, want := range []string{"locked", "finance-tower"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("profiles body missing profile %q: %s", want, rec.Body.String())
		}
	}
}

// On a managed gateway each enrolled user holds a credential bound to one
// client/agent pair and profile. It must not read the profile inventory,
// which names every other binding's posture, or the catalog; only the
// administrator's gateway token does.
func TestACPManagedEnrollmentCredentialDoesNotReadOperatorRoutes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed credential records require an installer-protected service tree on Windows")
	}
	dataDir := t.TempDir()
	credential, err := acp.EnsureEnterpriseCredential(dataDir, "uid:501", "zed", "kiro", "locked")
	if err != nil {
		t.Fatal(err)
	}
	const gatewayToken = "test-gateway-token-managed-operator-reads"
	cfg := acpGatewayTestConfig(dataDir, "managed_enterprise")
	cfg.Gateway.Token = gatewayToken
	cfg.ACP.Profiles["finance-tower"] = config.ACPProfile{
		Mode: "action", AllowedClients: []string{"vscode"}, AllowedAgents: []string{"finance-agent"},
	}
	api := &APIServer{scannerCfg: cfg}
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/acp/profiles":
			api.handleACPProfiles(w, r)
		case "/v1/acp/catalog":
			api.handleACPCatalog(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	for _, path := range []string{"/v1/acp/profiles", "/v1/acp/catalog"} {
		rec := serveACPOperatorRead(api, dispatch, http.MethodGet, path, credential.Token, "127.0.0.1:45678")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with an enrollment credential: status = %d, want 401", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "finance-tower") {
			t.Errorf("GET %s with an enrollment credential disclosed another binding: %s", path, rec.Body.String())
		}
		if rec := serveACPOperatorRead(api, dispatch, http.MethodGet, path, gatewayToken, "127.0.0.1:45678"); rec.Code != http.StatusOK {
			t.Errorf("GET %s with the gateway token: status = %d, want 200", path, rec.Code)
		}
	}
}
