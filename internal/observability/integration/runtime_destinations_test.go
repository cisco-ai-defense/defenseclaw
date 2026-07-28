// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	findingRecordID = "integration-security-finding"
	findingEmail    = "alice@example.test"
)

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.buffer.Bytes()...)
}

type integrationSecrets struct {
	mu     sync.Mutex
	values map[string]string
	calls  map[string]int
}

func (secrets *integrationSecrets) ResolveObservabilitySecret(name string) (string, bool) {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	secrets.calls[name]++
	value, ok := secrets.values[name]
	return value, ok
}

func (secrets *integrationSecrets) Calls(name string) int {
	secrets.mu.Lock()
	defer secrets.mu.Unlock()
	return secrets.calls[name]
}

type integrationCALoader struct {
	mu     sync.Mutex
	path   string
	bundle []byte
	calls  int
}

func (loader *integrationCALoader) LoadObservabilityCA(_ context.Context, path string) ([]byte, error) {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	loader.calls++
	if path != loader.path {
		return nil, fmt.Errorf("unexpected CA path")
	}
	return append([]byte(nil), loader.bundle...), nil
}

func (loader *integrationCALoader) Calls() int {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	return loader.calls
}

type integrationWarnings struct {
	mu       sync.Mutex
	warnings []push.Warning
}

func (warnings *integrationWarnings) ObservePushWarning(warning push.Warning) {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	warnings.warnings = append(warnings.warnings, warning)
}

func (warnings *integrationWarnings) Count(code push.WarningCode) int {
	warnings.mu.Lock()
	defer warnings.mu.Unlock()
	count := 0
	for _, warning := range warnings.warnings {
		if warning.Code == code {
			count++
		}
	}
	return count
}

type integrationDeliveryHealth struct {
	mu          sync.Mutex
	transitions []delivery.HealthTransition
}

func (health *integrationDeliveryHealth) Observe(transition delivery.HealthTransition) {
	health.mu.Lock()
	defer health.mu.Unlock()
	health.transitions = append(health.transitions, transition)
}

type discardReporter struct{}

func (*discardReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error { return nil }
func (*discardReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type capturedRequest struct {
	path        string
	headers     http.Header
	body        []byte
	sqliteCount int
}

type capturedGRPCLogRequest struct {
	request     *collectorlogpb.ExportLogsServiceRequest
	headers     metadata.MD
	sqliteCount int
}

type integrationGRPCLogServer struct {
	collectorlogpb.UnimplementedLogsServiceServer
	requests   chan capturedGRPCLogRequest
	localCount func() int
}

func (server *integrationGRPCLogServer) Export(ctx context.Context, request *collectorlogpb.ExportLogsServiceRequest) (*collectorlogpb.ExportLogsServiceResponse, error) {
	headers, _ := metadata.FromIncomingContext(ctx)
	server.requests <- capturedGRPCLogRequest{
		request: proto.Clone(request).(*collectorlogpb.ExportLogsServiceRequest),
		headers: headers, sqliteCount: server.localCount(),
	}
	return &collectorlogpb.ExportLogsServiceResponse{}, nil
}

func TestRuntimeRealDestinationBoundaryExactlyOnceAndReloadRemoval(t *testing.T) {
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	jsonlPath := filepath.Join(directory, "security.jsonl")
	caPath := filepath.Join(directory, "collector-ca.pem")

	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetMaxOpenConns(1)
	reader.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = reader.Close() })
	if err := reader.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	localCount := func() int {
		var count int
		if queryErr := reader.QueryRowContext(
			context.Background(), `SELECT COUNT(*) FROM audit_events WHERE id = ?`, findingRecordID,
		).Scan(&count); queryErr != nil {
			return -1
		}
		return count
	}
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcRequests := make(chan capturedGRPCLogRequest, 1)
	grpcServer := grpc.NewServer()
	collectorlogpb.RegisterLogsServiceServer(grpcServer, &integrationGRPCLogServer{
		requests: grpcRequests, localCount: localCount,
	})
	go grpcServer.Serve(grpcListener)
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = grpcListener.Close()
	})

	remoteRequests := make(chan capturedRequest, 4)
	remoteServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		remoteRequests <- capturedRequest{
			path: request.URL.Path, headers: request.Header.Clone(), body: body,
			sqliteCount: localCount(),
		}
		if request.URL.Path == "/splunk" {
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, `{"text":"Success","code":0}`)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(remoteServer.Close)

	slowStarted := make(chan capturedRequest, 1)
	slowDone := make(chan struct{})
	slowRelease := make(chan struct{})
	var slowReleaseOnce sync.Once
	releaseSlow := func() { slowReleaseOnce.Do(func() { close(slowRelease) }) }
	defer releaseSlow()
	var slowRequests atomic.Int64
	slowServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		slowRequests.Add(1)
		body, _ := io.ReadAll(request.Body)
		slowStarted <- capturedRequest{
			path: request.URL.Path, headers: request.Header.Clone(), body: body,
			sqliteCount: localCount(),
		}
		<-slowRelease
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "collector-secret-body-must-not-escape")
		close(slowDone)
	}))
	t.Cleanup(slowServer.Close)

	certificate := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: remoteServer.Certificate().Raw,
	})
	secrets := &integrationSecrets{
		values: map[string]string{
			"ARCHIVE_BEARER": "archive-secret", "ARCHIVE_TENANT": "tenant-a",
			"SPLUNK_TOKEN": "splunk-secret", "OTLP_AUTH": "Bearer otlp-secret",
			"TRACE_ONLY_AUTH": "Bearer must-not-resolve-in-log-factory",
			"GRPC_OTLP_AUTH":  "Bearer grpc-runtime-secret",
		},
		calls: map[string]int{},
	}
	caLoader := &integrationCALoader{path: caPath, bundle: certificate}
	warnings := &integrationWarnings{}
	console := &synchronizedBuffer{}
	factory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr,
		Stdout:        io.Discard, Stderr: console,
		Secrets: secrets, CALoader: caLoader,
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, Warnings: warnings,
	})
	if err != nil {
		t.Fatal(err)
	}

	initialSource := observabilitySource(
		storePath, judgePath,
		[]config.ObservabilityV8DestinationSource{
			logDestination("security-file", config.ObservabilityV8DestinationJSONL, "none", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Path = jsonlPath
			}),
			logDestination("security-console", config.ObservabilityV8DestinationConsole, "content", nil),
			logDestination("security-http", config.ObservabilityV8DestinationHTTPJSONL, "sensitive", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Endpoint = remoteServer.URL + "/archive"
				destination.BearerEnv = "ARCHIVE_BEARER"
				destination.Headers = map[string]config.ObservabilityV8HeaderValue{
					"X-Tenant": config.ObservabilityV8EnvironmentHeader("ARCHIVE_TENANT"),
				}
				destination.TLS.CACert = caPath
				destination.NetworkSafety.AllowPrivateNetworks = true
				destination.Batch.ScheduledDelayMS = 1
			}),
			logDestination("security-splunk", config.ObservabilityV8DestinationSplunkHEC, "strict", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Endpoint = remoteServer.URL + "/splunk"
				destination.TokenEnv = "SPLUNK_TOKEN"
				destination.Source = "defenseclaw"
				destination.SourceType = "defenseclaw:event"
				destination.SourceTypeOverrides = map[observability.ProducerKey]string{
					"scan-finding": "defenseclaw:finding",
				}
				destination.TLS.CACert = caPath
				destination.NetworkSafety.AllowPrivateNetworks = true
				destination.Batch.ScheduledDelayMS = 1
			}),
			logDestination("security-otlp", config.ObservabilityV8DestinationOTLP, "sensitive", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Protocol = "http/protobuf"
				destination.Endpoint = remoteServer.URL
				destination.Headers = map[string]config.ObservabilityV8HeaderValue{
					"Authorization": config.ObservabilityV8EnvironmentHeader("OTLP_AUTH"),
				}
				destination.LoggerName = "defenseclaw.integration"
				destination.TLS.CACert = caPath
				destination.NetworkSafety.AllowPrivateNetworks = true
				destination.Batch.ScheduledDelayMS = 1
			}),
			logDestination("security-otlp-grpc", config.ObservabilityV8DestinationOTLP, "content", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Protocol = "grpc"
				destination.Endpoint = grpcListener.Addr().String()
				destination.Headers = map[string]config.ObservabilityV8HeaderValue{
					"Authorization": config.ObservabilityV8EnvironmentHeader("GRPC_OTLP_AUTH"),
				}
				destination.LoggerName = "defenseclaw.integration.grpc"
				destination.TLS.Insecure = true
				destination.NetworkSafety.AllowPrivateNetworks = true
				destination.Batch.ScheduledDelayMS = 1
			}),
			{
				Name: "trace-only-otlp", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: remoteServer.URL,
				Send: &config.ObservabilityV8SendSource{
					Signals: []observability.Signal{observability.SignalTraces}, Buckets: []observability.Bucket{"*"},
				},
				Headers: map[string]config.ObservabilityV8HeaderValue{
					"Authorization": config.ObservabilityV8EnvironmentHeader("TRACE_ONLY_AUTH"),
				},
				TLS:           config.ObservabilityV8TLSSource{CACert: caPath},
				NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
			},
			logDestination("security-slow", config.ObservabilityV8DestinationHTTPJSONL, "legacy-v7", func(destination *config.ObservabilityV8DestinationSource) {
				destination.Endpoint = slowServer.URL + "/slow"
				destination.NetworkSafety.AllowPrivateNetworks = true
				destination.Batch.ScheduledDelayMS = 1
			}),
		},
	)
	initialSource.Resource.Attributes = map[string]string{
		"team.name": "integration-security",
	}
	plan, err := config.CompileObservabilityV8(initialSource)
	if err != nil {
		t.Fatal(err)
	}
	assertCompiledDefaults(t, plan)

	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	failureBuilder := mustRecordBuilder(t, "projection-failure")
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	deliveryHealth := &integrationDeliveryHealth{}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "integration-test", Environment: "test",
		ServiceInstanceID: "integration-service-instance", DefenseClawInstanceID: "integration-defenseclaw-instance",
	})
	expectedResource, err := providerFactory.ResourceContext(plan)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(
		context.Background(), runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: failureBuilder,
			Reporter: &discardReporter{}, RetentionController: retention,
			DestinationAdapterFactory: factory, DestinationObserver: deliveryHealth,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtimeClosed := false
	t.Cleanup(func() {
		if runtimeClosed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})

	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		"scan-finding",
		observability.ClassificationContext{RawSeverity: "HIGH"},
		observability.SourceScanner,
		"scanner",
		"scan-finding",
	)
	if err != nil {
		t.Fatal(err)
	}
	correlation := observability.Correlation{
		RunID: "run-integration", SessionID: "session-integration",
		TraceID:             "0123456789abcdef0123456789abcdef",
		FindingOccurrenceID: "finding-occurrence-integration",
	}
	emitBuilder := mustRecordBuilder(t, findingRecordID)
	started := time.Now()
	outcome, emitErr := runtime.Emit(context.Background(), metadata,
		func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			if admission != router.AdmissionOrdinary {
				return observability.Record{}, fmt.Errorf("unexpected admission")
			}
			return emitBuilder.BuildClassifiedLog(observability.ClassifiedLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: "scan-finding",
				ClassificationContext: observability.ClassificationContext{RawSeverity: "HIGH"},
				Source:                observability.SourceScanner, Connector: "scanner", Action: "scan-finding",
				Outcome: observability.OutcomeCompleted, Correlation: correlation,
				Provenance: observability.Provenance{
					Producer: "integration_test", BinaryVersion: "test",
					RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
					ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
				Body: map[string]any{
					"message": "finding detected for " + findingEmail,
					"actor":   "operator@example.test", "target": "sensitive-target",
				},
				FieldClasses: map[string]observability.FieldClass{
					"/message": observability.FieldClassContent,
					"/actor":   observability.FieldClassContent,
					"/target":  observability.FieldClassContent,
				},
			})
		},
	)
	if emitErr != nil || !outcome.LocalPersisted() || outcome.Admission() != router.AdmissionOrdinary {
		t.Fatalf("emit persisted=%t admission=%s error=%v", outcome.LocalPersisted(), outcome.Admission(), emitErr)
	}
	if time.Since(started) > time.Second {
		t.Fatal("producer waited for an optional destination")
	}
	if count := localCount(); count != 1 {
		t.Fatalf("SQLite count immediately after Emit=%d", count)
	}

	slow := receiveRequest(t, slowStarted)
	firstRemote := receiveRequest(t, remoteRequests)
	secondRemote := receiveRequest(t, remoteRequests)
	thirdRemote := receiveRequest(t, remoteRequests)
	grpcRemote := receiveRequest(t, grpcRequests)
	remoteByPath := map[string]capturedRequest{
		firstRemote.path: firstRemote, secondRemote.path: secondRemote, thirdRemote.path: thirdRemote,
	}
	for _, request := range []capturedRequest{slow, firstRemote, secondRemote, thirdRemote} {
		if request.sqliteCount != 1 {
			t.Fatalf("optional request %s observed SQLite count %d", request.path, request.sqliteCount)
		}
	}
	if grpcRemote.sqliteCount != 1 {
		t.Fatalf("optional gRPC request observed SQLite count %d", grpcRemote.sqliteCount)
	}
	if _, ok := remoteByPath["/archive"]; !ok {
		t.Fatal("HTTP JSONL request missing")
	}
	if _, ok := remoteByPath["/splunk"]; !ok {
		t.Fatal("Splunk request missing")
	}
	if _, ok := remoteByPath["/v1/logs"]; !ok {
		t.Fatal("OTLP log request missing")
	}

	waitFor(t, func() bool {
		file, readErr := os.ReadFile(jsonlPath)
		return readErr == nil && bytes.Count(file, []byte{'\n'}) == 1 &&
			bytes.Count(console.Bytes(), []byte{'\n'}) == 1
	})
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	consoleBytes := console.Bytes()
	archive := remoteByPath["/archive"]
	splunk := remoteByPath["/splunk"]
	otlpRequest := remoteByPath["/v1/logs"]
	if archive.headers.Get("Authorization") != "Bearer archive-secret" ||
		archive.headers.Get("X-Tenant") != "tenant-a" ||
		splunk.headers.Get("Authorization") != "Splunk splunk-secret" ||
		otlpRequest.headers.Get("Authorization") != "Bearer otlp-secret" {
		t.Fatal("resolved destination authorization/header mismatch")
	}

	sqliteProjection, sqliteProfile := readSQLiteProjection(t, reader)
	jsonlProjection := bytes.TrimSuffix(jsonlBytes, []byte{'\n'})
	consoleProjection := bytes.TrimSuffix(consoleBytes, []byte{'\n'})
	archiveProjection := bytes.TrimSuffix(archive.body, []byte{'\n'})
	slowProjection := bytes.TrimSuffix(slow.body, []byte{'\n'})
	splunkProjection, splunkEvent, splunkSourceType := readSplunkProjection(t, splunk.body)
	otlpProjection := readOTLPProjection(t, otlpRequest.body)
	grpcOTLPProjection := readOTLPLogRequest(t, grpcRemote.request, "defenseclaw.integration.grpc")
	var httpOTLPRequest collectorlogpb.ExportLogsServiceRequest
	if err := proto.Unmarshal(otlpRequest.body, &httpOTLPRequest); err != nil {
		t.Fatal(err)
	}
	assertExactOTLPLogResource(t, &httpOTLPRequest, expectedResource)
	assertExactOTLPLogResource(t, grpcRemote.request, expectedResource)
	projections := map[string][]byte{
		"sqlite": sqliteProjection, "jsonl": jsonlProjection,
		"console": consoleProjection, "http": archiveProjection,
		"splunk": splunkProjection, "otlp": otlpProjection,
		"otlp-grpc": grpcOTLPProjection, "slow": slowProjection,
	}
	for name, projection := range projections {
		assertProjectionIdentity(t, name, projection, correlation)
	}
	for name, wantProfile := range map[string]string{
		"sqlite": "none", "jsonl": "none", "console": "content",
		"http": "sensitive", "splunk": "strict", "otlp": "sensitive",
		"otlp-grpc": "content", "slow": "legacy-v7",
	} {
		if got := projectionProfile(t, projections[name]); got != wantProfile {
			t.Fatalf("%s projection profile=%s want=%s", name, got, wantProfile)
		}
	}
	if sqliteProfile != "none" || !bytes.Contains(sqliteProjection, []byte(findingEmail)) ||
		!bytes.Contains(jsonlProjection, []byte(findingEmail)) {
		t.Fatal("unredacted local/JSONL projection was not preserved")
	}
	for _, name := range []string{"console", "http", "splunk", "otlp", "otlp-grpc", "slow"} {
		if bytes.Contains(projections[name], []byte(findingEmail)) {
			t.Fatalf("%s projection leaked destination-redacted email", name)
		}
	}
	if bytes.Equal(jsonlProjection, consoleProjection) || bytes.Equal(consoleProjection, archiveProjection) ||
		bytes.Equal(archiveProjection, splunkProjection) {
		t.Fatal("destination-specific projections unexpectedly collapsed to one encoding")
	}
	var strictRecord map[string]any
	if err := json.Unmarshal(splunkProjection, &strictRecord); err != nil {
		t.Fatal(err)
	}
	if body, hasBody := strictRecord["body"]; hasBody {
		object, isObject := body.(map[string]any)
		if !isObject || len(object) != 0 {
			t.Fatalf("strict Splunk projection retained body=%+v", body)
		}
	}
	for _, absent := range []string{"details", "target"} {
		if _, exists := splunkEvent[absent]; exists {
			t.Fatalf("Splunk alias %s recovered a value removed by its projection", absent)
		}
	}
	strictProvenance, _ := strictRecord["provenance"].(map[string]any)
	if splunkEvent["id"] != findingRecordID || splunkEvent["run_id"] != correlation.RunID ||
		splunkEvent["action"] != strictRecord["action"] ||
		splunkEvent["actor"] != strictProvenance["producer"] || splunkSourceType != "defenseclaw:finding" {
		t.Fatalf("Splunk projection-derived aliases=%+v sourcetype=%s", splunkEvent, splunkSourceType)
	}
	if bytes.Contains(splunk.body, []byte(findingEmail)) || bytes.Contains(splunk.body, []byte("_splunk_hec_events")) {
		t.Fatal("Splunk full wrapper contains removed or opaque content")
	}
	if got := grpcRemote.headers.Get("authorization"); len(got) != 1 || got[0] != "Bearer grpc-runtime-secret" {
		t.Fatalf("gRPC OTLP authorization=%v", got)
	}

	releaseSlow()
	select {
	case <-slowDone:
	case <-time.After(5 * time.Second):
		t.Fatal("slow permanent-failure destination did not finish")
	}
	if slowRequests.Load() != 1 {
		t.Fatalf("slow destination attempts=%d, want exactly one permanent failure", slowRequests.Load())
	}
	if count := localCount(); count != 1 {
		t.Fatalf("optional failure changed SQLite count=%d", count)
	}
	if secrets.Calls("ARCHIVE_BEARER") != 1 || secrets.Calls("ARCHIVE_TENANT") != 1 ||
		secrets.Calls("SPLUNK_TOKEN") != 1 || secrets.Calls("OTLP_AUTH") != 1 ||
		secrets.Calls("GRPC_OTLP_AUTH") != 1 || caLoader.Calls() != 3 {
		t.Fatalf("secret/CA resolution counts bearer=%d tenant=%d splunk=%d otlp=%d grpc=%d CA=%d",
			secrets.Calls("ARCHIVE_BEARER"), secrets.Calls("ARCHIVE_TENANT"),
			secrets.Calls("SPLUNK_TOKEN"), secrets.Calls("OTLP_AUTH"),
			secrets.Calls("GRPC_OTLP_AUTH"), caLoader.Calls())
	}
	if secrets.Calls("TRACE_ONLY_AUTH") != 0 {
		t.Fatalf("trace-only destination entered log factory %d times", secrets.Calls("TRACE_ONLY_AUTH"))
	}
	if warnings.Count(push.WarningPrivateNetworksAllowed) != 5 {
		t.Fatalf("private destination warnings=%d", warnings.Count(push.WarningPrivateNetworksAllowed))
	}
	if warnings.Count(push.WarningTLSVerificationDisabled) != 1 || warnings.Count(push.WarningPlaintextCredentials) != 1 {
		t.Fatalf("OTLP insecure/plaintext warnings TLS=%d credentials=%d",
			warnings.Count(push.WarningTLSVerificationDisabled), warnings.Count(push.WarningPlaintextCredentials))
	}

	activeBeforeRejectedReload := runtime.Active()
	rejectedSource := observabilitySource(storePath, judgePath, []config.ObservabilityV8DestinationSource{
		logDestination("rejected-archive", config.ObservabilityV8DestinationHTTPJSONL, "none", func(destination *config.ObservabilityV8DestinationSource) {
			destination.Endpoint = "https://collector.example.test/events?credential=must-not-escape"
			destination.BearerEnv = "MISSING_SUPER_SECRET"
			destination.Batch.ScheduledDelayMS = 1
		}),
	})
	rejectedPlan, err := config.CompileObservabilityV8(rejectedSource)
	if err != nil {
		t.Fatal(err)
	}
	rejectedResult, rejectedErr := runtime.Reload(
		context.Background(), runtimegraph.ConfigFromPlan(rejectedPlan, false),
	)
	if rejectedErr == nil || rejectedResult.Status() != runtimegraph.ReloadRejected ||
		runtime.Active() != activeBeforeRejectedReload {
		t.Fatalf("rejected reload status=%s error=%v", rejectedResult.Status(), rejectedErr)
	}
	for _, forbidden := range []string{"MISSING_SUPER_SECRET", "must-not-escape", "collector.example.test"} {
		if strings.Contains(rejectedErr.Error(), forbidden) {
			t.Fatalf("reload error disclosed %q: %v", forbidden, rejectedErr)
		}
	}
	if secrets.Calls("MISSING_SUPER_SECRET") != 1 {
		t.Fatalf("rejected reload resolved missing secret %d times", secrets.Calls("MISSING_SUPER_SECRET"))
	}

	removalPlan, err := config.CompileObservabilityV8(observabilitySource(storePath, judgePath, nil))
	if err != nil {
		t.Fatal(err)
	}
	removedResult, removedErr := runtime.Reload(
		context.Background(), runtimegraph.ConfigFromPlan(removalPlan, false),
	)
	if removedErr != nil || removedResult.Status() != runtimegraph.ReloadApplied ||
		runtime.Active().Generation() <= activeBeforeRejectedReload.Generation() {
		t.Fatalf("removal reload status=%s error=%v", removedResult.Status(), removedErr)
	}
	if slowRequests.Load() != 1 || len(remoteRequests) != 0 ||
		bytes.Count(mustReadFile(t, jsonlPath), []byte{'\n'}) != 1 ||
		bytes.Count(console.Bytes(), []byte{'\n'}) != 1 {
		t.Fatal("reload/removal duplicated an optional destination path")
	}
	var totalRows int
	if err := reader.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events`).Scan(&totalRows); err != nil {
		t.Fatal(err)
	}
	if totalRows != 1 {
		t.Fatalf("audit rows=%d, duplicate legacy/local path detected", totalRows)
	}

	closeContext, cancelClose := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelClose()
	if err := runtime.Close(closeContext); err != nil {
		t.Fatal(err)
	}
	runtimeClosed = true
}

func observabilitySource(
	storePath string,
	judgePath string,
	destinationSources []config.ObservabilityV8DestinationSource,
) *config.ObservabilityV8Source {
	retentionDays := 0
	return &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: storePath, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
		},
		Destinations: destinationSources,
	}
}

func logDestination(
	name string,
	kind config.ObservabilityV8DestinationKind,
	profile string,
	mutate func(*config.ObservabilityV8DestinationSource),
) config.ObservabilityV8DestinationSource {
	destination := config.ObservabilityV8DestinationSource{
		Name: name, Kind: kind,
		Send: &config.ObservabilityV8SendSource{
			Signals:          []observability.Signal{observability.SignalLogs},
			Buckets:          []observability.Bucket{observability.BucketSecurityFinding},
			RedactionProfile: profile,
		},
	}
	if mutate != nil {
		mutate(&destination)
	}
	return destination
}

func assertCompiledDefaults(t *testing.T, plan *config.ObservabilityV8Plan) {
	t.Helper()
	for _, name := range []string{"security-file", "security-console", "security-http", "security-splunk", "security-otlp", "security-otlp-grpc", "security-slow"} {
		destination, ok := plan.RuntimeDestination(name)
		if !ok || destination.Transport.Batch == nil {
			t.Fatalf("destination %s has no compiled batch", name)
		}
		batch := destination.Transport.Batch
		if batch.MaxQueueSize != 2_048 || batch.MaxQueueBytes != 67_108_864 {
			t.Fatalf("destination %s queue defaults=%+v", name, batch)
		}
		if destination.Kind == config.ObservabilityV8DestinationJSONL ||
			destination.Kind == config.ObservabilityV8DestinationConsole {
			if batch.MaxExportBatchSize != 0 || batch.MaxExportBatchBytes != 0 || batch.ScheduledDelayMS != 0 {
				t.Fatalf("queue-only destination %s batch=%+v", name, batch)
			}
			continue
		}
		if batch.MaxExportBatchSize != 512 || batch.MaxExportBatchBytes != 8_388_608 || batch.ScheduledDelayMS != 1 {
			t.Fatalf("push destination %s compiled defaults=%+v", name, batch)
		}
	}
	jsonl, _ := plan.RuntimeDestination("security-file")
	if jsonl.Transport.Rotation == nil || jsonl.Transport.Rotation.MaxSizeMB != 50 ||
		jsonl.Transport.Rotation.MaxBackups != 5 || jsonl.Transport.Rotation.MaxAgeDays != 30 ||
		!jsonl.Transport.Rotation.Compress {
		t.Fatalf("JSONL rotation defaults=%+v", jsonl.Transport.Rotation)
	}
}

func mustRecordBuilder(t *testing.T, recordID string) *observability.RecordBuilder {
	t.Helper()
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 3, 18, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func receiveRequest[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(10 * time.Second):
		var zero T
		t.Fatal("timed out waiting for destination request")
		return zero
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func readSQLiteProjection(t *testing.T, reader *sql.DB) ([]byte, string) {
	t.Helper()
	var projection []byte
	var profile string
	if err := reader.QueryRowContext(context.Background(), `
		SELECT projected_record_json, redaction_profile
		FROM audit_events WHERE id = ?`, findingRecordID,
	).Scan(&projection, &profile); err != nil {
		t.Fatal(err)
	}
	return projection, profile
}

func readSplunkProjection(t *testing.T, body []byte) ([]byte, map[string]any, string) {
	t.Helper()
	line := bytes.TrimSuffix(body, []byte{'\n'})
	var envelope struct {
		SourceType string                     `json:"sourcetype"`
		Event      map[string]json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil {
		t.Fatal(err)
	}
	record := append([]byte(nil), envelope.Event["record"]...)
	aliases := make(map[string]any, len(envelope.Event))
	for key, encoded := range envelope.Event {
		if key == "record" {
			continue
		}
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		aliases[key] = value
	}
	return record, aliases, envelope.SourceType
}

func readOTLPProjection(t *testing.T, body []byte) []byte {
	t.Helper()
	var request collectorlogpb.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	return readOTLPLogRequest(t, &request, "defenseclaw.integration")
}

func readOTLPLogRequest(t *testing.T, request *collectorlogpb.ExportLogsServiceRequest, scope string) []byte {
	t.Helper()
	if request == nil {
		t.Fatal("nil OTLP log request")
	}
	if len(request.ResourceLogs) != 1 || len(request.ResourceLogs[0].ScopeLogs) != 1 ||
		len(request.ResourceLogs[0].ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("unexpected OTLP log shape: %+v", request.ResourceLogs)
	}
	if got := request.ResourceLogs[0].ScopeLogs[0].Scope.Name; got != scope {
		t.Fatalf("OTLP scope = %q", got)
	}
	return []byte(request.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Body.GetStringValue())
}

func assertExactOTLPLogResource(
	t *testing.T,
	request *collectorlogpb.ExportLogsServiceRequest,
	expected telemetry.V8ResourceContext,
) {
	t.Helper()
	if request == nil || len(request.ResourceLogs) != 1 || request.ResourceLogs[0] == nil ||
		request.ResourceLogs[0].Resource == nil {
		t.Fatalf("missing OTLP log resource: %+v", request)
	}
	resourceLogs := request.ResourceLogs[0]
	if resourceLogs.SchemaUrl != expected.SchemaURL() ||
		resourceLogs.Resource.DroppedAttributesCount != expected.ResourceDroppedAttributesCount() {
		t.Fatalf("OTLP resource schema/dropped mismatch: schema=%q dropped=%d want=%d", resourceLogs.SchemaUrl, resourceLogs.Resource.DroppedAttributesCount, expected.ResourceDroppedAttributesCount())
	}
	got := make(map[string]string, len(resourceLogs.Resource.Attributes))
	for _, attribute := range resourceLogs.Resource.Attributes {
		if attribute == nil || attribute.Value == nil {
			t.Fatal("OTLP resource contains nil attribute")
		}
		got[attribute.Key] = attribute.Value.GetStringValue()
	}
	want := expected.Values()
	if len(got) != len(want) {
		t.Fatalf("OTLP resource attribute count=%d want=%d got=%+v want=%+v", len(got), len(want), got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("OTLP resource %q=%q want=%q", key, got[key], value)
		}
	}
	if got["team.name"] != "integration-security" ||
		got["deployment.environment"] != got["deployment.environment.name"] {
		t.Fatalf("OTLP resource lost custom/compatibility attributes: %+v", got)
	}
}

func assertProjectionIdentity(
	t *testing.T,
	name string,
	encoded []byte,
	wantCorrelation observability.Correlation,
) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatalf("%s projection: %v", name, err)
	}
	if record["record_id"] != findingRecordID || record["bucket"] != "security.finding" ||
		record["event_name"] != "legacy.audit.scan.finding" || record["action"] != "scan-finding" {
		t.Fatalf("%s identity=%+v", name, record)
	}
	correlation, ok := record["correlation"].(map[string]any)
	if !ok || correlation["run_id"] != wantCorrelation.RunID ||
		correlation["session_id"] != wantCorrelation.SessionID ||
		correlation["trace_id"] != wantCorrelation.TraceID ||
		correlation["finding_occurrence_id"] != wantCorrelation.FindingOccurrenceID {
		t.Fatalf("%s correlation=%+v", name, correlation)
	}
}

func projectionProfile(t *testing.T, encoded []byte) string {
	t.Helper()
	var record struct {
		Projection struct {
			Profile string `json:"redaction_profile"`
		} `json:"projection"`
	}
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	return record.Projection.Profile
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
