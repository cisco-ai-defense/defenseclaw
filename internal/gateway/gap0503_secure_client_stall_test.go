package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestGAP0503SecureClientStalledFinalizeRetainsAudit(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	signer := &heldWriterSigner{entered: make(chan struct{}), release: make(chan struct{})}
	fixture := newSidecarRuntimeFixtureWithSigner(t, true, signer)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{Profile: managed.ProfileSecureClient}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	if !cfg.SecureClientIntegration() {
		t.Fatal("Secure Client profile not active")
	}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	api.SetCiscoInspector(&stubAIDInspector{verdict: &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"}})
	bindHookLifecycleV8(t, api, fixture.runtime)
	var once sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(signer.release) }) }
	defer release()
	holderDone := make(chan struct{})
	previous := hookStagePanicHook
	hookStagePanicHook = func(_ context.Context, stage string) {
		if stage != "finalize_audit" {
			return
		}
		once.Do(func() {
			signer.armed.Store(true)
			go func() {
				defer close(holderDone)
				api.emitClaudeCodeHookLLMEvent(context.Background(),
					claudePreToolUseForOperationTest("gap0503-holder", "gap0503-holder"), nil, nil)
			}()
			select {
			case <-signer.entered:
			case <-time.After(5 * time.Second):
				t.Error("holder did not acquire SQLite connection")
			}
			time.AfterFunc(12*time.Second, release)
		})
	}
	t.Cleanup(func() { hookStagePanicHook = previous })
	body, err := json.Marshal(claudePreToolUseForOperationTest("gap0503-sc", "gap0503-sc").Payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body))
	response := httptest.NewRecorder()
	started := time.Now()
	api.handleAgentHook("claudecode").ServeHTTP(response, request)
	elapsed := time.Since(started)
	release()
	select {
	case <-holderDone:
	case <-time.After(5 * time.Second):
		t.Error("holder did not drain")
	}
	rows, err := fixture.store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	var audited int
	for _, row := range rows {
		if row.Action == string(audit.ActionConnectorHook) {
			audited++
		}
	}
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"allow"`)) {
		t.Fatalf("Secure Client answer changed: status=%d body=%q", response.Code, response.Body.String())
	}
	if audited != 1 {
		t.Fatalf("Secure Client audit rows after a temporary store hold: got %d, want 1 (elapsed %s)", audited, elapsed)
	}
}
