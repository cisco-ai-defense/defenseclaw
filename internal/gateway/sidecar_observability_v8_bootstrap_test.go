// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/version"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestSidecarObservabilityV8BootstrapErrorReportsOnlySafeRedactionSubcode(t *testing.T) {
	t.Parallel()
	err := newSidecarObservabilityV8BootstrapError(
		sidecarObservabilityV8BootstrapRedaction,
		&observabilityredaction.KeyStoreError{Code: observabilityredaction.KeyStoreErrorUnsafePermissions},
	)
	if got, want := err.Error(), "sidecar observability v8 bootstrap failed: redaction_unavailable:unsafe_key_permissions"; got != want {
		t.Fatalf("safe redaction error = %q, want %q", got, want)
	}
	const secret = "operator-secret-path-and-material"
	err = newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRedaction, errors.New(secret))
	if got := err.Error(); strings.Contains(got, secret) || got != "sidecar observability v8 bootstrap failed: redaction_unavailable" {
		t.Fatalf("unsafe cause escaped bootstrap boundary: %q", got)
	}
}

type sidecarV8BootstrapFixture struct {
	sidecar    *Sidecar
	store      *audit.Store
	logger     *audit.Logger
	dataDir    string
	configPath string
	raw        []byte
}

func newSidecarV8BootstrapFixture(t *testing.T, configVersion int, storePath string) sidecarV8BootstrapFixture {
	t.Helper()
	dataDir := t.TempDir()
	// Some self-hosted Linux runners create testing.TempDir children under a
	// permissive process umask. The production audit store correctly rejects an
	// immediately group-writable database directory, so make the shared success
	// fixture's custody contract explicit; dedicated audit-path tests cover the
	// rejection case.
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if storePath == "" {
		storePath = filepath.Join(dataDir, config.DefaultAuditDBName)
	}
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	logger := audit.NewLogger(store)
	configPath := filepath.Join(dataDir, "config.yaml")
	cfg := &config.Config{
		ConfigVersion: configVersion, ConfigFilePath: configPath,
		DataDir: dataDir, AuditDB: storePath,
		JudgeBodiesDB: filepath.Join(dataDir, config.DefaultJudgeBodiesDBName),
		Environment:   "test",
	}
	sidecar := &Sidecar{cfg: cfg, store: store, logger: logger, health: NewSidecarHealth()}
	sidecar.publishConfig(cfg)
	previousVersion := version.Current().BinaryVersion
	version.SetBinaryVersion("8.0.0-bootstrap-test")
	previousRunID := gatewaylog.ProcessRunID()
	previousInstanceID := gatewaylog.SidecarInstanceID()
	gatewaylog.SetProcessRunID("bootstrap-run-001")
	gatewaylog.SetSidecarInstanceID("bootstrap-instance-001")
	t.Cleanup(func() {
		_ = sidecar.closeOwnedObservabilityV8Runtime()
		logger.Close()
		_ = store.Close()
		version.SetBinaryVersion(previousVersion)
		gatewaylog.SetProcessRunID(previousRunID)
		gatewaylog.SetSidecarInstanceID(previousInstanceID)
	})
	raw := []byte(fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability: {}\n", dataDir))
	return sidecarV8BootstrapFixture{
		sidecar: sidecar, store: store, logger: logger,
		dataDir: dataDir, configPath: configPath, raw: raw,
	}
}

func TestSidecarBootstrapObservabilityV8BindsOneValidatedOwnedRuntime(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	proxy := &GuardrailProxy{}
	fixture.sidecar.setGuardrailProxy(proxy)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner, ok := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if !ok || owner == nil || owner.runtime == nil || owner.runtime.Active() == nil ||
		owner.runtime.Active().Generation() != 1 {
		t.Fatalf("owned runtime=%T %#v", fixture.sidecar.observabilityV8, owner)
	}
	if proxy.observabilityV8TraceRuntime() != owner {
		t.Fatal("validated runtime was not bound to the existing proxy")
	}
	health := fixture.sidecar.health.Snapshot().Telemetry
	rows, healthOK := health.Details["destinations"].([]map[string]interface{})
	if health.State != StateRunning || !healthOK || len(rows) != 1 ||
		rows[0]["name"] != config.ObservabilityV8LocalDestinationName ||
		rows[0]["kind"] != string(config.ObservabilityV8DestinationLocalSQLite) ||
		rows[0]["state"] != string(delivery.HealthHealthy) || rows[0]["queue"] != nil {
		t.Fatalf("bootstrap health=%+v", health)
	}
	if rebound, secondErr := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	); rebound || sidecarV8BootstrapCode(secondErr) != sidecarObservabilityV8BootstrapBinding {
		t.Fatalf("duplicate bootstrap bound=%t error=%v", rebound, secondErr)
	}
	if err := fixture.sidecar.beginObservabilityV8Run(); err != nil {
		t.Fatalf("validated bound v8 run gate: %v", err)
	}
}

func TestSidecarBootstrapOwnedRuntimeBindsLocalOnlyAPIConsumer(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)

	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	owner, ok := fixture.sidecar.observabilityV8Emitter().(*sidecarOwnedObservabilityV8Runtime)
	if !ok || owner == nil {
		t.Fatalf("owned runtime=%T", fixture.sidecar.observabilityV8Emitter())
	}
	if got := api.observabilityV8LocalOnlyRuntime(); got != owner {
		t.Fatalf("local-only API runtime=%T, want production owner %p", got, owner)
	}
}

func lifecycleTraceBootstrapRaw(dataDir string, retentionDays int, endpoint string) []byte {
	return []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  local:\n    retention_days: %d\n  destinations:\n    - name: lifecycle-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      send:\n        signals: [traces]\n        buckets: ['*']\n",
		dataDir,
		retentionDays,
		endpoint,
	))
}

func bootstrapOwnedLifecycleTraceRuntime(
	t *testing.T,
	fixture sidecarV8BootstrapFixture,
) (*sidecarOwnedObservabilityV8Runtime, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, lifecycleTraceBootstrapRaw(fixture.dataDir, 90, server.URL),
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap lifecycle runtime bound=%t error=%v", bound, err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner, ok := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if !ok || owner == nil {
		t.Fatalf("owned lifecycle runtime=%T", fixture.sidecar.observabilityV8)
	}
	return owner, server.URL
}

func TestSidecarOwnedLifecycleRuntimeForwardsEveryRootOperation(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	owner, endpoint := bootstrapOwnedLifecycleTraceRuntime(t, fixture)

	_, agent, err := owner.StartAgentTrace(t.Context(), observability.SpanAgentInvokeInput{
		Kind: "INTERNAL", DefenseClawAgentType: "root",
	})
	if err != nil || agent == nil || agent.Generation() != 1 {
		t.Fatalf("forward root agent=%v error=%v", agent, err)
	}
	agent.Abort()

	_, model, err := owner.StartModelTrace(t.Context(), observability.SpanModelChatInput{
		Kind: "CLIENT", GenAIRequestModel: "reported-model",
	})
	if err != nil || model == nil || model.Generation() != 1 {
		t.Fatalf("forward root model=%v error=%v", model, err)
	}
	model.Abort()

	_, tool, err := owner.StartToolTrace(t.Context(), observability.SpanToolExecuteInput{
		Kind: "INTERNAL", GenAIToolName: "reported-tool",
	})
	if err != nil || tool == nil || tool.Generation() != 1 {
		t.Fatalf("forward root tool=%v error=%v", tool, err)
	}
	tool.Abort()

	_, approval, err := owner.StartApprovalTrace(t.Context(), observability.SpanApprovalResolveInput{
		Kind: "INTERNAL", DefenseClawApprovalID: observability.Present("approval-001"),
	})
	if err != nil || approval == nil || approval.Generation() != 1 {
		t.Fatalf("forward root approval=%v error=%v", approval, err)
	}
	approval.Abort()

	reload, reloadErr := fixture.sidecar.ReloadObservabilityRuntime(
		t.Context(), fixture.configPath, lifecycleTraceBootstrapRaw(fixture.dataDir, 30, endpoint),
	)
	if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied ||
		owner.runtime.Active() == nil || owner.runtime.Active().Generation() != 2 {
		t.Fatalf("reload after forwarded aborts=%s error=%v", reload.Status(), reloadErr)
	}
}

func TestSidecarDetachesLifecycleConsumersBeforeOwnedRuntimeCloseWaitsForLease(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	owner, _ := bootstrapOwnedLifecycleTraceRuntime(t, fixture)
	api := &APIServer{}
	router := &EventRouter{}
	proxy := &GuardrailProxy{}
	fixture.sidecar.setAPIServer(api)
	fixture.sidecar.setEventRouter(router)
	fixture.sidecar.setGuardrailProxy(proxy)
	if api.observabilityV8LifecycleRuntime() != owner ||
		router.observabilityV8LifecycleRuntime() != owner ||
		proxy.observabilityV8TraceRuntime() != owner {
		t.Fatal("owned lifecycle runtime was not bound before close")
	}

	_, agent, err := owner.StartAgentTrace(t.Context(), observability.SpanAgentInvokeInput{
		Kind: "INTERNAL", DefenseClawAgentType: "root",
	})
	if err != nil || agent == nil {
		t.Fatalf("start close-blocking agent=%v error=%v", agent, err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- fixture.sidecar.closeOwnedObservabilityV8Runtime() }()

	deadline := time.Now().Add(5 * time.Second)
	for fixture.sidecar.observabilityV8LifecycleRuntime() != nil ||
		api.observabilityV8RuntimeEmitter() != nil ||
		api.observabilityV8CanaryRuntime() != nil ||
		api.observabilityV8LocalOnlyRuntime() != nil ||
		api.observabilityV8LifecycleRuntime() != nil ||
		router.observabilityV8LifecycleRuntime() != nil ||
		proxy.observabilityV8TraceRuntime() != nil {
		if time.Now().After(deadline) {
			agent.Abort()
			t.Fatal("lifecycle consumers were not detached before close wait")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case closeErr := <-closeDone:
		agent.Abort()
		t.Fatalf("owned runtime close returned before active lease release: %v", closeErr)
	default:
	}

	agent.Abort()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned runtime close did not finish after lease release")
	}
	if fixture.sidecar.observabilityV8Emitter() != nil {
		t.Fatal("owned emitter remained published after close")
	}
}

func TestSidecarConcurrentConsumerConstructionCannotRepublishClosingRuntime(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	owner, _ := bootstrapOwnedLifecycleTraceRuntime(t, fixture)
	_, agent, err := owner.StartAgentTrace(t.Context(), observability.SpanAgentInvokeInput{
		Kind: "INTERNAL", DefenseClawAgentType: "root",
	})
	if err != nil || agent == nil {
		t.Fatalf("start close-blocking agent=%v error=%v", agent, err)
	}

	api := &APIServer{}
	router := &EventRouter{}
	proxy := &GuardrailProxy{}
	start := make(chan struct{})
	closeDone := make(chan error, 1)
	constructionDone := make(chan struct{}, 1)
	go func() {
		<-start
		closeDone <- fixture.sidecar.closeOwnedObservabilityV8Runtime()
	}()
	go func() {
		<-start
		fixture.sidecar.setAPIServer(api)
		fixture.sidecar.setEventRouter(router)
		fixture.sidecar.setGuardrailProxy(proxy)
		constructionDone <- struct{}{}
	}()
	close(start)
	<-constructionDone

	deadline := time.Now().Add(5 * time.Second)
	for fixture.sidecar.observabilityV8LifecycleRuntime() != nil ||
		api.observabilityV8RuntimeEmitter() != nil ||
		api.observabilityV8CanaryRuntime() != nil ||
		api.observabilityV8LocalOnlyRuntime() != nil ||
		api.observabilityV8LifecycleRuntime() != nil ||
		router.observabilityV8LifecycleRuntime() != nil ||
		proxy.observabilityV8TraceRuntime() != nil {
		if time.Now().After(deadline) {
			agent.Abort()
			t.Fatal("consumer construction republished the closing runtime")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case closeErr := <-closeDone:
		agent.Abort()
		t.Fatalf("owned runtime close returned before active lease release: %v", closeErr)
	default:
	}

	agent.Abort()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned runtime close did not finish after concurrent construction")
	}
}

func TestSidecarBootstrapLocalObservabilityCanaryReachesAgent360Projection(t *testing.T) {
	requests := make(chan *collectortracepb.ExportTraceServiceRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/traces" {
			http.NotFound(writer, request)
			return
		}
		body, _ := io.ReadAll(request.Body)
		decoded := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			http.Error(writer, "invalid protobuf", http.StatusBadRequest)
			return
		}
		requests <- decoded
		response, _ := proto.Marshal(&collectortracepb.ExportTraceServiceResponse{})
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(response)
	}))
	defer server.Close()

	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  destinations:\n    - name: %s\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 2\n        scheduled_delay_ms: 10\n      send:\n        signals: [traces]\n        buckets: ['*']\n",
		fixture.dataDir,
		localobservability.DestinationName,
		server.URL,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	canary := fixture.sidecar.observabilityV8CanaryEmitter()
	if canary == nil {
		t.Fatal("owned runtime did not expose canary emitter")
	}
	result, err := canary.EmitTraceCanary(t.Context(), localobservability.DestinationName)
	if err != nil || !result.Acknowledged || result.Generation != 1 ||
		result.Destination != localobservability.DestinationName || result.TraceID == "" {
		t.Fatalf("canary result=%+v error=%v", result, err)
	}

	var request *collectortracepb.ExportTraceServiceRequest
	select {
	case request = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("local-observability receiver did not get canary trace")
	}
	spans := gatewayTraceRequestSpans(request)
	if len(spans) != 2 {
		t.Fatalf("captured canary spans = %d, want 2", len(spans))
	}
	var root, child *tracepb.Span
	for _, span := range spans {
		switch gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") {
		case observability.TelemetryFamilyAgentInvoke:
			root = span
		case observability.TelemetryFamilyModelChat:
			child = span
		}
	}
	if root == nil || child == nil || root.Name != "invoke_agent diagnostic" || child.Name != "chat gpt-4o-mini" ||
		fmt.Sprintf("%x", root.TraceId) != result.TraceID ||
		!bytes.Equal(root.TraceId, child.TraceId) || !bytes.Equal(root.SpanId, child.ParentSpanId) {
		t.Fatalf("canonical root/child pair root=%+v child=%+v result=%+v", root, child, result)
	}
	if gatewayProtoAttribute(root.Attributes, "defenseclaw.agent.type") != "diagnostic" ||
		gatewayProtoAttribute(root.Attributes, "gen_ai.agent.type") != "diagnostic" {
		t.Fatalf("Agent360 compatibility aliases = %q/%q",
			gatewayProtoAttribute(root.Attributes, "defenseclaw.agent.type"),
			gatewayProtoAttribute(root.Attributes, "gen_ai.agent.type"))
	}
}

func TestSidecarBootstrapControlPlaneActionPersistsAndRoutesExactlyOnce(t *testing.T) {
	requests := make(chan []byte, 8)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requests <- append([]byte(nil), body...)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  destinations:\n    - name: control-plane-http\n      kind: http_jsonl\n      endpoint: %q\n      network_safety:\n        allow_private_networks: true\n      batch:\n        scheduled_delay_ms: 1\n",
		fixture.dataDir,
		server.URL,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	if err := fixture.logger.LogActionCtx(
		audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
			RunID: "control-plane-run", RequestID: "control-plane-request",
		}),
		string(audit.ActionConfigUpdate),
		"config.yaml",
		"generation applied",
	); err != nil {
		t.Fatalf("LogActionCtx: %v", err)
	}

	rows, err := fixture.store.ListEvents(100)
	if err != nil {
		t.Fatalf("list local audit rows: %v", err)
	}
	var row audit.Event
	matches := 0
	for _, candidate := range rows {
		if candidate.RequestID == "control-plane-request" {
			row = candidate
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("local control-plane occurrence rows=%d, want exactly 1", matches)
	}
	if row.Action != string(audit.ActionConfigUpdate) {
		t.Fatalf("local compatibility action=%q", row.Action)
	}
	reader, err := sql.Open("sqlite", fixture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var bucket, eventName, projectedRecord string
	var mandatory int
	if err := reader.QueryRowContext(
		t.Context(),
		`SELECT bucket, event_name, mandatory, projected_record_json FROM audit_events WHERE id = ?`,
		row.ID,
	).Scan(&bucket, &eventName, &mandatory, &projectedRecord); err != nil {
		t.Fatalf("read local canonical control-plane row: %v", err)
	}
	if bucket != string(observability.BucketComplianceActivity) ||
		eventName != observability.TelemetryEventConfigChangeApplied ||
		mandatory != 1 || projectedRecord == "" {
		t.Fatalf("local canonical control-plane fields=%q/%q/%d/%t",
			bucket, eventName, mandatory, projectedRecord != "")
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	remoteMatches := 0
	for remoteMatches == 0 {
		select {
		case requestBody := <-requests:
			for _, line := range bytes.Split(bytes.TrimSpace(requestBody), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				var projected map[string]any
				if err := json.Unmarshal(line, &projected); err != nil {
					t.Fatalf("decode HTTP JSONL projection: %v", err)
				}
				if projected["record_id"] != row.ID {
					continue
				}
				remoteMatches++
				if projected["bucket"] != string(observability.BucketComplianceActivity) ||
					projected["event_name"] != observability.TelemetryEventConfigChangeApplied ||
					projected["action"] != string(audit.ActionConfigUpdate) {
					t.Fatalf("remote canonical control-plane projection=%#v", projected)
				}
				projection, ok := projected["projection"].(map[string]any)
				if !ok || projection["redaction_profile"] != "none" {
					t.Fatalf("default remote projection metadata=%#v", projection)
				}
			}
		case <-deadline.C:
			t.Fatal("HTTP JSONL destination did not receive the control-plane record")
		}
	}
	select {
	case requestBody := <-requests:
		for _, line := range bytes.Split(bytes.TrimSpace(requestBody), []byte{'\n'}) {
			var projected map[string]any
			if json.Unmarshal(line, &projected) == nil && projected["record_id"] == row.ID {
				remoteMatches++
			}
		}
	case <-time.After(50 * time.Millisecond):
	}
	if remoteMatches != 1 {
		t.Fatalf("remote control-plane deliveries=%d, want exactly 1", remoteMatches)
	}
}

func TestSidecarBootstrapObservabilityV8RejectsV7WithoutMutation(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 7, "")
	v7 := []byte("config_version: 7\notel:\n  enabled: false\n")
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, v7)
	if err == nil || bound {
		t.Fatalf("v7 bootstrap bound=%t error=%v", bound, err)
	}
	if fixture.sidecar.observabilityV8Emitter() != nil {
		t.Fatal("rejected v7 bootstrap changed runtime state")
	}
	if runErr := fixture.sidecar.beginObservabilityV8Run(); runErr == nil {
		t.Fatal("v7 sidecar passed the run gate")
	}
}

func TestNewSidecarRejectsV7BeforeInitialization(t *testing.T) {
	if sidecar, err := NewSidecar(&config.Config{ConfigVersion: 7}, nil, nil, nil); err == nil || sidecar != nil {
		t.Fatalf("v7 constructor = sidecar:%v error:%v", sidecar, err)
	}
}

func TestSidecarBootstrapObservabilityV8FailsClosedBeforeServing(t *testing.T) {
	dataDir := t.TempDir()
	wrongStore := filepath.Join(dataDir, "wrong.db")
	fixture := newSidecarV8BootstrapFixture(t, 8, wrongStore)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw)
	if bound || sidecarV8BootstrapCode(err) != sidecarObservabilityV8BootstrapStore {
		t.Fatalf("mismatched store bound=%t error=%v", bound, err)
	}
	if fixture.sidecar.observabilityV8Emitter() != nil {
		t.Fatal("failed bootstrap left a partial runtime bound")
	}
	runErr := fixture.sidecar.beginObservabilityV8Run()
	var gate *sidecarObservabilityError
	if !errors.As(runErr, &gate) || gate.Code() != sidecarObservabilityInvalidBinding {
		t.Fatalf("unbound v8 run gate error=%v", runErr)
	}
}

func TestSidecarOwnedObservabilityV8ReloadsGenerationAndShutsDownBeforeStore(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	reloadRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  local:\n    retention_days: 30\n",
		fixture.dataDir,
	))
	result, reloadErr := fixture.sidecar.ReloadObservabilityRuntime(
		t.Context(), fixture.configPath, reloadRaw,
	)
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied ||
		owner.runtime.Active() == nil || owner.runtime.Active().Generation() != 2 ||
		owner.runtime.Active().RetentionDays() != 30 {
		t.Fatalf("reload=%s error=%v graph=%+v", result.Status(), reloadErr, owner.runtime.Active())
	}
	if !fixture.store.Ready() {
		t.Fatal("runtime reload closed the caller-owned SQLite store")
	}
	if err := fixture.sidecar.closeOwnedObservabilityV8Runtime(); err != nil {
		t.Fatal(err)
	}
	owner.lifecycleMu.RLock()
	closed := owner.closed
	owner.lifecycleMu.RUnlock()
	if !closed || fixture.sidecar.observabilityV8Emitter() != nil || !fixture.store.Ready() {
		t.Fatalf("shutdown closed=%t emitter=%v store-ready=%t", closed, fixture.sidecar.observabilityV8Emitter(), fixture.store.Ready())
	}
	if err := fixture.sidecar.closeOwnedObservabilityV8Runtime(); err != nil {
		t.Fatalf("idempotent shutdown: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := fixture.sidecar.ReloadObservabilityRuntime(ctx, fixture.configPath, reloadRaw); err == nil {
		t.Fatal("closed runtime accepted reload")
	}
}

func TestSidecarConfigManagerReloadsFileChangedAfterBootstrap(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: test\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	activeDigest := fixture.sidecar.observabilityV8ActivePlanDigest()
	if activeDigest == "" {
		t.Fatal("bootstrapped runtime has no active plan digest")
	}

	// This source is installed by the test hook immediately after fsnotify is
	// registered and before startup reconciliation. The serving gate must not
	// report ready until this buffered registration-window mutation is active.
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: test\nguardrail:\n  mode: action\nobservability:\n  local:\n    retention_days: 30\n",
		fixture.dataDir,
	))
	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		activeDigest,
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	var hookErr error
	mgr.afterWatchAdded = func() { hookErr = os.WriteFile(fixture.configPath, nextRaw, 0o600) }
	runCtx, cancel := context.WithCancel(t.Context())
	ready := make(chan error, 1)
	runDone := make(chan error, 1)
	go func() { runDone <- mgr.runWithStartupReconcile(runCtx, ready) }()
	if err := <-ready; err != nil {
		cancel()
		t.Fatal(err)
	}
	if hookErr != nil {
		cancel()
		t.Fatal(hookErr)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if owner.runtime.Active().Generation() != 2 || owner.runtime.Active().RetentionDays() != 30 {
		t.Fatalf("active graph generation/retention = %d/%d",
			owner.runtime.Active().Generation(), owner.runtime.Active().RetentionDays())
	}
	if got := fixture.sidecar.currentConfig().Guardrail.Mode; got != "action" {
		t.Fatalf("sidecar config guardrail mode = %q", got)
	}
	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("config manager shutdown error = %v", err)
	}
}

func TestSidecarConfigManagerV8RuntimeFailureRollsBackGraphAndConfig(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	failingRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\nguardrail:\n  mode: action\nobservability:\n  destinations:\n    - name: occupied\n      kind: prometheus\n      listen: %q\n      path: /metrics\n",
		fixture.dataDir,
		listener.Addr().String(),
	))
	if err := os.WriteFile(fixture.configPath, failingRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.Reload(t.Context(), "test")
	if err == nil {
		t.Fatal("occupied Prometheus listener reload unexpectedly succeeded")
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if owner.runtime.Active().Generation() != 1 || fixture.sidecar.currentConfig().Guardrail.Mode != "observe" ||
		mgr.Current().Guardrail.Mode != "observe" || mgr.gen.Load() != 0 {
		t.Fatalf("rollback graph/sidecar/manager/gen = %d/%q/%q/%d",
			owner.runtime.Active().Generation(), fixture.sidecar.currentConfig().Guardrail.Mode,
			mgr.Current().Guardrail.Mode, mgr.gen.Load())
	}
}

func TestSidecarConfigManagerV8SamePrometheusBindingRequiresRestartBeforeReplacement(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\nobservability:\n  local:\n    retention_days: 90\n  destinations:\n    - name: metrics\n      kind: prometheus\n      listen: %q\n      path: /metrics\n",
		fixture.dataDir, listen,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	assertMetricsListenerBound := func() {
		t.Helper()
		connection, dialErr := net.DialTimeout("tcp", listen, 2*time.Second)
		if dialErr != nil {
			t.Fatalf("dial active Prometheus listener: %v", dialErr)
		}
		if closeErr := connection.Close(); closeErr != nil {
			t.Fatalf("close Prometheus listener probe: %v", closeErr)
		}
	}
	assertMetricsListenerBound()

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	initialDigest := mgr.v8PlanDigest
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	oldGraph := owner.runtime.Active()
	candidateRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\nobservability:\n  local:\n    retention_days: 30\n  destinations:\n    - name: metrics\n      kind: prometheus\n      listen: %q\n      path: /metrics\n",
		fixture.dataDir, listen,
	))
	if err := os.WriteFile(fixture.configPath, candidateRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	reloadErr := mgr.Reload(t.Context(), "test")
	if sidecarV8BootstrapCode(reloadErr) != sidecarObservabilityV8BootstrapReload {
		t.Fatalf("same Prometheus binding reload error = %v", reloadErr)
	}
	if owner.runtime.Active() != oldGraph || oldGraph.Generation() != 1 ||
		mgr.v8PlanDigest != initialDigest || mgr.gen.Load() != 0 {
		t.Fatalf(
			"same-binding reload mutated graph/digest/gen = %p/%p %q/%q/%d",
			owner.runtime.Active(), oldGraph, mgr.v8PlanDigest, initialDigest, mgr.gen.Load(),
		)
	}
	assertMetricsListenerBound()
}

func TestSidecarConfigManagerV8RestartModeDoesNotHotApplyPlan(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\ngateway:\n  config_reload:\n    mode: restart\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	helperCalled := false
	previousHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error {
		helperCalled = true
		return nil
	}
	t.Cleanup(func() { launchConfigRestartHelper = previousHelper })
	runCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.sidecar.setRunCancel(cancel)

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\ngateway:\n  config_reload:\n    mode: restart\nobservability:\n  local:\n    retention_days: 30\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if !helperCalled || owner.runtime.Active().Generation() != 1 ||
		fixture.sidecar.currentConfig().Environment != "original" {
		t.Fatalf("restart helper/generation/environment = %t/%d/%q",
			helperCalled, owner.runtime.Active().Generation(), fixture.sidecar.currentConfig().Environment)
	}
	select {
	case <-runCtx.Done():
	default:
		t.Fatal("restart-mode v8 change did not request process restart")
	}
}

func TestSidecarConfigManagerV8RestartHelperFailureIsAtomic(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\ngateway:\n  config_reload:\n    mode: restart\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, initialRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	previousHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error { return errors.New("helper unavailable") }
	t.Cleanup(func() { launchConfigRestartHelper = previousHelper })

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\ngateway:\n  config_reload:\n    mode: restart\nobservability:\n  local:\n    retention_days: 30\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	reloadErr := mgr.Reload(t.Context(), "test")
	if reloadErr == nil || !strings.Contains(reloadErr.Error(), "helper unavailable") {
		t.Fatalf("restart helper failure = %v", reloadErr)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if owner.runtime.Active().Generation() != 1 ||
		fixture.sidecar.currentConfig().Environment != "original" ||
		mgr.Current().Environment != "original" || mgr.gen.Load() != 0 {
		t.Fatalf(
			"failed restart mutated generation/sidecar/manager/gen = %d/%q/%q/%d",
			owner.runtime.Active().Generation(), fixture.sidecar.currentConfig().Environment,
			mgr.Current().Environment, mgr.gen.Load(),
		)
	}
}

func TestSidecarConfigManagerV8ArmsRestartModeWithoutImmediateRestart(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, config.ObservabilityV8ConfigVersion, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: hot\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, initialRaw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	helperCalled := false
	previousHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error {
		helperCalled = true
		return nil
	}
	t.Cleanup(func() { launchConfigRestartHelper = previousHelper })

	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\ngateway:\n  config_reload:\n    mode: restart\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	if helperCalled {
		t.Fatal("restart helper launched while only arming restart mode")
	}
	if fixture.sidecar.currentConfig().Gateway.ConfigReload.Mode == "restart" {
		t.Fatal("live sidecar mode changed while arming restart mode")
	}
	if mgr.Current().Gateway.ConfigReload.Mode != "restart" || mgr.gen.Load() != 1 {
		t.Fatalf("manager mode/generation = %q/%d", mgr.Current().Gateway.ConfigReload.Mode, mgr.gen.Load())
	}
}

func TestSidecarConfigManagerV8NonObservabilityHotChangeDoesNotReloadGraph(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nnotifications:\n  enabled: false\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nnotifications:\n  enabled: true\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "test"); err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if owner.runtime.Active().Generation() != 1 || !fixture.sidecar.currentConfig().Notifications.Enabled {
		t.Fatalf("generation/notifications = %d/%t",
			owner.runtime.Active().Generation(), fixture.sidecar.currentConfig().Notifications.Enabled)
	}
}

func TestSidecarConfigManagerV8ResourceIdentityChangeRequiresRestart(t *testing.T) {
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	initialRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: original\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, initialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(fixture.configPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.sidecar.publishConfig(initial)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, initialRaw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	mgr := newConfigManagerWithSnapshot(
		fixture.configPath,
		initial,
		nil,
		nil,
		fixture.sidecar.observabilityV8ActivePlanDigest(),
		fixture.sidecar.applyConfigReloadSnapshot,
	)
	nextRaw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nenvironment: changed\nobservability: {}\n",
		fixture.dataDir,
	))
	if err := os.WriteFile(fixture.configPath, nextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	err = mgr.Reload(t.Context(), "test")
	if err == nil || !strings.Contains(err.Error(), "environment") {
		t.Fatalf("resource identity reload error = %v", err)
	}
	fixture.sidecar.observabilityV8Mu.Lock()
	owner := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	fixture.sidecar.observabilityV8Mu.Unlock()
	if owner.runtime.Active().Generation() != 1 ||
		fixture.sidecar.currentConfig().Environment != "original" ||
		mgr.Current().Environment != "original" {
		t.Fatalf("identity rollback generation/sidecar/manager = %d/%q/%q",
			owner.runtime.Active().Generation(), fixture.sidecar.currentConfig().Environment,
			mgr.Current().Environment)
	}
}

func TestSidecarRunEarlyFailureClosesOwnedObservabilityV8Runtime(t *testing.T) {
	t.Run("token synthesis", func(t *testing.T) {
		fixture := newSidecarV8BootstrapFixture(t, 8, "")
		bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
			t.Context(), fixture.configPath, fixture.raw,
		)
		if err != nil || !bound {
			t.Fatalf("bootstrap bound=%t error=%v", bound, err)
		}
		blockedDataDir := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(blockedDataDir, []byte("blocked"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
		t.Setenv("TEST_V8_EARLY_FAILURE_TOKEN", "")
		next := fixture.sidecar.currentConfig()
		next.DataDir = blockedDataDir
		next.Gateway.Token = ""
		next.Gateway.TokenEnv = "TEST_V8_EARLY_FAILURE_TOKEN"
		fixture.sidecar.publishConfig(next)

		err = fixture.sidecar.Run(t.Context())
		if err == nil || !strings.Contains(err.Error(), "gateway token synthesis") {
			t.Fatalf("Run token failure = %v", err)
		}
		assertSidecarOwnedV8ClosedAfterRunFailure(t, fixture)
	})

	t.Run("startup watcher reconcile", func(t *testing.T) {
		fixture := newSidecarV8BootstrapFixture(t, 8, "")
		bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
			t.Context(), fixture.configPath, fixture.raw,
		)
		if err != nil || !bound {
			t.Fatalf("bootstrap bound=%t error=%v", bound, err)
		}
		next := fixture.sidecar.currentConfig()
		next.Gateway.Token = "already-resolved-token"
		fixture.sidecar.publishConfig(next)
		invalid := []byte(fmt.Sprintf(
			"config_version: 8\ndata_dir: %q\nobservability:\n  destinationz: []\n",
			fixture.dataDir,
		))
		if err := os.WriteFile(fixture.configPath, invalid, 0o600); err != nil {
			t.Fatal(err)
		}

		err = fixture.sidecar.Run(t.Context())
		if err == nil || !strings.Contains(err.Error(), "reconcile observability v8 config") {
			t.Fatalf("Run reconcile failure = %v", err)
		}
		assertSidecarOwnedV8ClosedAfterRunFailure(t, fixture)
	})
}

func assertSidecarOwnedV8ClosedAfterRunFailure(t *testing.T, fixture sidecarV8BootstrapFixture) {
	t.Helper()
	if fixture.sidecar.observabilityV8Emitter() != nil || !fixture.store.Ready() {
		t.Fatalf("failed Run left owned runtime/store state = %T/%t",
			fixture.sidecar.observabilityV8Emitter(), fixture.store.Ready())
	}
}

func gatewayTraceRequestSpans(request *collectortracepb.ExportTraceServiceRequest) []*tracepb.Span {
	var spans []*tracepb.Span
	if request == nil {
		return spans
	}
	for _, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeSpans {
			if scope != nil {
				spans = append(spans, scope.Spans...)
			}
		}
	}
	return spans
}

func gatewayProtoAttribute(attributes []*commonpb.KeyValue, key string) string {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Key == key && attribute.Value != nil {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

func sidecarV8BootstrapCode(err error) sidecarObservabilityV8BootstrapErrorCode {
	var target *sidecarObservabilityV8BootstrapError
	if errors.As(err, &target) {
		return target.Code()
	}
	return ""
}
