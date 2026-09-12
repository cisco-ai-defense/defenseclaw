// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/google/uuid"
)

func (a *APIServer) handleACPCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.writeJSON(w, http.StatusOK, acp.BuiltinCatalog())
}

func (a *APIServer) handleACPProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "configuration unavailable"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": cfg.ACP.Enabled, "mode": effectiveACPMode(cfg.ACP, ""),
		"default_profile": cfg.ACP.DefaultProfile, "profiles": cfg.ACP.Profiles,
	})
}

func (a *APIServer) handleACPEvaluate(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, acp.MaxTurnEvaluationBytes+(64<<10))
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req acp.Evaluation
	if err := decoder.Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ACP evaluation body"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ACP evaluation body"})
		return
	}
	maxPayload := acp.MaxFrameBytes
	if req.Aggregate {
		maxPayload = acp.MaxTurnEvaluationBytes
	}
	if len(req.Payload) == 0 || len(req.Payload) > maxPayload {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP payload is empty or too large"})
		return
	}
	if req.Aggregate {
		if req.Direction != acp.AgentToClient || req.Surface != acp.SurfaceOutput || req.Method != "session/update" ||
			acp.ValidateTurnEvaluationPayload(req.Payload) != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP completed-turn metadata does not match payload"})
			return
		}
	} else {
		msg, err := acp.ParseMessage(req.Payload)
		if err != nil || msg.Method != req.Method || acp.Classify(msg, req.Direction) != req.Surface {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ACP envelope metadata does not match payload"})
			return
		}
	}
	agent, err := acp.LookupAgent(req.AgentID)
	if err != nil || strings.TrimSpace(agent.ConnectorID) == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown or unbound ACP agent"})
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil || !cfg.ACP.Enabled {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ACP guard is not enabled"})
		return
	}
	profileName, profile, ok := resolveACPProfile(cfg.ACP, req.Profile)
	if !ok {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP profile is not configured"})
		return
	}
	clientBinding, clientOK := cfg.ACP.Clients[req.ClientID]
	agentBinding, agentOK := cfg.ACP.Agents[req.AgentID]
	if !clientOK || !clientBinding.Enabled || clientBinding.Profile != profileName ||
		!agentOK || !agentBinding.Enabled || agentBinding.Profile != profileName {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP client or agent binding is disabled or pinned to another profile"})
		return
	}
	if !acpBindingAllowed(profile.AllowedClients, req.ClientID) || !acpBindingAllowed(profile.AllowedAgents, req.AgentID) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP client or agent is outside the selected profile"})
		return
	}
	if managed.IsManagedEnterprise(cfg.DeploymentMode) {
		credential, ok := acpEnterpriseCredentialFromContext(r.Context())
		if !ok || credential.ClientID != req.ClientID || credential.AgentID != req.AgentID || credential.Profile != profileName {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "ACP enterprise credential is outside its enrolled binding"})
			return
		}
	}
	mode := effectiveACPMode(cfg.ACP, profileName)
	if string(req.Mode) != mode {
		a.writeJSON(w, http.StatusConflict, map[string]string{
			"error": "ACP runtime mode does not match central policy; re-run managed setup",
		})
		return
	}
	if slices.Contains(profile.DeniedMethods, req.Method) {
		verdict := acp.Verdict{Action: "block", RawAction: "block", Severity: "HIGH", Reason: "method denied by ACP profile"}
		if mode != string(acp.ModeAction) {
			verdict.Action, verdict.WouldBlock = "allow", true
		}
		a.recordACPEvaluationV8(r.Context(), req, verdict, agent.ConnectorID, profileName, time.Since(started))
		a.writeJSON(w, http.StatusOK, verdict)
		return
	}

	direction := string(req.Surface)
	if req.Surface == acp.SurfaceOutput {
		direction = "completion"
	}
	if req.Surface == acp.SurfacePrompt {
		direction = "prompt"
	}
	ctx, cancel := context.WithTimeout(r.Context(), inspectScanTimeout)
	defer cancel()
	verdict := a.inspectMessageContent(ctx, &ToolInspectRequest{
		Tool: "message", Content: string(req.Payload), Direction: direction,
		Connector: agent.ConnectorID, contentScope: ruleContentScopeUntrusted,
	})
	if verdict == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ACP inspection unavailable"})
		return
	}
	verdict.applyMode(mode)
	result := acp.Verdict{
		Action: verdict.Action, RawAction: verdict.RawAction, Severity: verdict.Severity,
		Reason: verdict.Reason, WouldBlock: verdict.WouldBlock,
	}
	a.recordACPEvaluationV8(r.Context(), req, result, agent.ConnectorID, profileName, time.Since(started))
	a.writeJSON(w, http.StatusOK, result)
}

func (a *APIServer) recordACPEvaluationV8(
	ctx context.Context, req acp.Evaluation, verdict acp.Verdict, connector, profile string, elapsed time.Duration,
) {
	action := strings.ToLower(strings.TrimSpace(verdict.Action))
	if action == "confirm" {
		action = "block"
	}
	if action != "allow" && action != "alert" && action != "block" {
		action = "allow"
	}
	direction := "prompt"
	if req.Direction == acp.AgentToClient {
		direction = "completion"
	}
	severity := strings.ToUpper(strings.TrimSpace(verdict.Severity))
	if severity == "" {
		severity = "NONE"
	}
	facts, err := newAPIGuardrailEventV8Facts(ctx, connector, guardrailEventRequest{
		EvaluationID: uuid.NewString(), Direction: direction, Action: action,
		RawAction: verdict.RawAction, WouldBlock: verdict.WouldBlock, Severity: severity,
		Reason: verdict.Reason, ElapsedMs: float64(elapsed) / float64(time.Millisecond),
	})
	if err != nil {
		return
	}
	facts.acp = &acpEvaluationV8Context{
		client: req.ClientID, agent: req.AgentID, method: req.Method,
		direction: string(req.Direction), surface: string(req.Surface), profile: profile,
	}
	_ = a.emitGuardrailEventV8(ctx, facts)
}

func effectiveACPMode(cfg config.ACPConfig, profileName string) string {
	if profileName != "" {
		if profile, ok := cfg.Profiles[profileName]; ok && (profile.Mode == "observe" || profile.Mode == "action") {
			return profile.Mode
		}
	}
	if cfg.Mode == "action" {
		return "action"
	}
	return "observe"
}

func resolveACPProfile(cfg config.ACPConfig, requested string) (string, config.ACPProfile, bool) {
	name := strings.TrimSpace(requested)
	if name == "" {
		name = strings.TrimSpace(cfg.DefaultProfile)
	}
	if name == "" {
		name = "default"
	}
	profile, ok := cfg.Profiles[name]
	return name, profile, ok
}

func acpBindingAllowed(allow []string, value string) bool {
	return len(allow) == 0 || slices.Contains(allow, value)
}

func isACPAPIPath(path string) bool {
	return path == "/api/v1/acp/evaluate" || strings.HasPrefix(path, "/v1/acp/")
}

type acpEnterpriseCredentialContextKey struct{}

func withACPEnterpriseCredential(ctx context.Context, credential acp.EnterpriseCredential) context.Context {
	return context.WithValue(ctx, acpEnterpriseCredentialContextKey{}, credential)
}

func acpEnterpriseCredentialFromContext(ctx context.Context) (acp.EnterpriseCredential, bool) {
	credential, ok := ctx.Value(acpEnterpriseCredentialContextKey{}).(acp.EnterpriseCredential)
	return credential, ok
}

// authenticateACPToken applies different custody models without widening the
// bearer onto any non-ACP route. Unmanaged mode uses the single local sidecar;
// managed enterprise mode requires one administrator-owned, per-principal and
// per-binding credential record and carries its scope into evaluation.
func (a *APIServer) authenticateACPToken(r *http.Request, candidate string) (*http.Request, bool) {
	if a == nil || a.scannerCfg == nil || r == nil {
		return r, false
	}
	if !managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		return r, a.acpAPITokenMatches(candidate)
	}
	credential, ok := acp.MatchEnterpriseCredential(a.scannerCfg.DataDir, candidate)
	if !ok {
		return r, false
	}
	return r.WithContext(withACPEnterpriseCredential(r.Context(), credential)), true
}

func (a *APIServer) authenticateACPSignedRequest(r *http.Request) (*http.Request, string, string, bool) {
	if a == nil || a.scannerCfg == nil || r == nil || r.Method != http.MethodPost || r.URL.Path != "/api/v1/acp/evaluate" {
		return r, "", "", false
	}
	keyID := strings.TrimSpace(r.Header.Get(acp.AuthKeyIDHeader))
	nonce := strings.TrimSpace(r.Header.Get(acp.AuthNonceHeader))
	candidateMAC := strings.TrimSpace(r.Header.Get(acp.AuthRequestMACHeader))
	if len(keyID) != 64 || len(nonce) != 64 || len(candidateMAC) != 64 {
		return r, "", "", false
	}
	var token string
	if managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		credential, secret, ok := acp.MatchEnterpriseCredentialKeyID(a.scannerCfg.DataDir, keyID)
		if !ok {
			return r, "", "", false
		}
		token = secret
		r = r.WithContext(withACPEnterpriseCredential(r.Context(), credential))
	} else {
		var ok bool
		token, ok = a.loadACPAPIToken()
		if !ok || !constantTimeStringMatch(acp.HTTPAuthKeyID(token), keyID) {
			return r, "", "", false
		}
	}
	limited := io.LimitReader(r.Body, acp.MaxTurnEvaluationBytes+(64<<10)+1)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) > acp.MaxTurnEvaluationBytes+(64<<10) {
		return r, "", "", false
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !acp.VerifyHTTPRequestMAC(token, keyID, nonce, r.Method, r.URL.Path, body, candidateMAC) {
		return r, "", "", false
	}
	r.Header.Set(acp.AuthKeyIDHeader, keyID)
	r.Header.Set(acp.AuthNonceHeader, nonce)
	return r, token, nonce, true
}

type acpSignedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *acpSignedResponse) Header() http.Header { return w.header }

func (w *acpSignedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *acpSignedResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.body.Len()+len(body) > 64<<10 {
		return 0, errors.New("ACP signed response exceeds its size bound")
	}
	return w.body.Write(body)
}

func serveACPSignedResponse(w http.ResponseWriter, r *http.Request, next http.Handler, token, nonce string) {
	capture := &acpSignedResponse{header: w.Header().Clone()}
	next.ServeHTTP(capture, r)
	if capture.status == 0 {
		capture.status = http.StatusOK
	}
	keyID := r.Header.Get(acp.AuthKeyIDHeader)
	capture.header.Set(acp.AuthResponseMACHeader, acp.HTTPResponseMAC(token, keyID, nonce, capture.status, capture.body.Bytes()))
	for name := range w.Header() {
		w.Header().Del(name)
	}
	for name, values := range capture.header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(capture.status)
	_, _ = w.Write(capture.body.Bytes())
}

// acpAPITokenMatches authenticates the guard with a credential that has no
// authority outside ACP routes. The token stays in a mode-0600 sidecar rather
// than IDE JSON or config.yaml.
func (a *APIServer) acpAPITokenMatches(candidate string) bool {
	if a == nil || a.scannerCfg == nil || candidate == "" {
		return false
	}
	expected, ok := a.loadACPAPIToken()
	return ok && constantTimeStringMatch(expected, candidate)
}

func (a *APIServer) loadACPAPIToken() (string, bool) {
	if a == nil || a.scannerCfg == nil {
		return "", false
	}
	path := filepath.Join(a.scannerCfg.DataDir, "acp", ".token")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return "", false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", false
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return "", false
	}
	body, err := safefile.ReadRegularFileBounded(path, 16<<10)
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(string(body))
	return token, token != ""
}

func (a *APIServer) acpScopedTokenReady() bool {
	if a == nil || a.scannerCfg == nil {
		return false
	}
	key := a.scannerCfg.DeploymentMode + "\x00" + a.scannerCfg.DataDir
	now := time.Now()
	a.acpReadinessMu.Lock()
	defer a.acpReadinessMu.Unlock()
	if key == a.acpReadinessKey && now.Sub(a.acpReadinessCheckedAt) < 500*time.Millisecond {
		return a.acpReadinessValue
	}
	ready := a.acpScopedTokenReadyUncached()
	a.acpReadinessKey = key
	a.acpReadinessCheckedAt = now
	a.acpReadinessValue = ready
	return ready
}

func (a *APIServer) acpScopedTokenReadyUncached() bool {
	if managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) {
		return acp.EnterpriseCredentialsReady(a.scannerCfg.DataDir)
	}
	path := filepath.Join(a.scannerCfg.DataDir, "acp", ".token")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return false
	}
	permissionsSafe := runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
	return permissionsSafe && safefile.ValidatePrivateFile(path) == nil
}
