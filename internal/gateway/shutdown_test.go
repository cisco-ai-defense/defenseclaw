// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGatewayShutdownRequiresMasterAuthCSRFAndRuntimeIdentity(t *testing.T) {
	dataDir := t.TempDir()
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}}
	api.scannerCfg.Gateway.Token = "shutdown-test-token"
	var requests atomic.Int32
	api.SetShutdownRequester(func() { requests.Add(1) })

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/shutdown", api.handleShutdown)
	handler := maxBodyMiddleware(mux, 1<<20)
	handler = api.apiCSRFProtect(handler)
	handler = api.tokenAuth(handler)

	body := fmt.Sprintf(`{"pid":%d,"data_dir":%q}`, os.Getpid(), dataDir)
	request := func(token, clientHeader, contentType, payload string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/admin/shutdown", strings.NewReader(payload))
		req.RemoteAddr = "127.0.0.1:32100"
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if clientHeader != "" {
			req.Header.Set("X-DefenseClaw-Client", clientHeader)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	if got := request("", "daemon-stop", "application/json", body).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := request("shutdown-test-token", "", "application/json", body).Code; got != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want %d", got, http.StatusForbidden)
	}
	if got := request("shutdown-test-token", "daemon-stop", "text/plain", body).Code; got != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong content type status = %d, want %d", got, http.StatusUnsupportedMediaType)
	}
	wrongPID := fmt.Sprintf(`{"pid":%d,"data_dir":%q}`, os.Getpid()+1, dataDir)
	if got := request("shutdown-test-token", "daemon-stop", "application/json", wrongPID).Code; got != http.StatusConflict {
		t.Fatalf("wrong PID status = %d, want %d", got, http.StatusConflict)
	}
	wrongHome := fmt.Sprintf(`{"pid":%d,"data_dir":%q}`, os.Getpid(), t.TempDir())
	if got := request("shutdown-test-token", "daemon-stop", "application/json", wrongHome).Code; got != http.StatusConflict {
		t.Fatalf("wrong data home status = %d, want %d", got, http.StatusConflict)
	}
	if got := request("shutdown-test-token", "daemon-stop", "application/json", body+` {}`).Code; got != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, want %d", got, http.StatusBadRequest)
	}

	accepted := request("shutdown-test-token", "daemon-stop", "application/json", body)
	if accepted.Code != http.StatusAccepted || !strings.Contains(accepted.Body.String(), `"accepted"`) {
		t.Fatalf("accepted response = %d %s", accepted.Code, accepted.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for requests.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("shutdown callback count = %d, want 1", got)
	}
	repeated := request("shutdown-test-token", "daemon-stop", "application/json", body)
	if repeated.Code != http.StatusAccepted || !strings.Contains(repeated.Body.String(), `"already_requested"`) {
		t.Fatalf("repeat response = %d %s", repeated.Code, repeated.Body.String())
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("repeat invoked callback; count = %d", got)
	}
}

func TestGatewayShutdownRejectsNonLoopbackEvenAfterAuthentication(t *testing.T) {
	dataDir := t.TempDir()
	api := &APIServer{scannerCfg: &config.Config{DataDir: dataDir}, shutdownRequester: func() {}}
	body := []byte(fmt.Sprintf(`{"pid":%d,"data_dir":%q}`, os.Getpid(), dataDir))
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/admin/shutdown", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.20:42100"
	recorder := httptest.NewRecorder()
	api.handleShutdown(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("remote shutdown status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestSameRuntimeDataDirNormalizesPath(t *testing.T) {
	dataDir := t.TempDir()
	if !sameRuntimeDataDir(filepath.Join(dataDir, "."), dataDir) {
		t.Fatal("equivalent data paths did not match")
	}
	if sameRuntimeDataDir("", dataDir) || sameRuntimeDataDir(dataDir, t.TempDir()) {
		t.Fatal("empty or different data paths matched")
	}
}
