// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

var connectorOpenClawInstallPolicyCmd = &cobra.Command{
	Use:   "install-policy",
	Short: "Answer an OpenClaw install policy request with DefenseClaw admission (OpenClaw runs it)",
	Long: `OpenClaw runs this command as its security.installPolicy before it installs
or updates a skill or plugin (setup registers it when
connectors.openclaw.install_policy resolves to on). It reads one OpenClaw
request (protocolVersion 1) on stdin, asks the DefenseClaw gateway to scan
the staged files and apply skill or plugin admission, and writes one answer
on stdout: allow, or block with the reason and the findings. It always
exits 0 with an answer, so OpenClaw shows the DefenseClaw reason.

When the gateway does not answer, the strict policy and managed installs
block the install; the default and permissive policies allow it. A
missing credential, a listener that does not prove it is this account
gateway, or an error answer blocks in every policy.`,
	Args: cobra.NoArgs,
	// The answer must be the only stdout and must come within the OpenClaw
	// timeout, so the command loads only the config, never the audit store.
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	PersistentPostRun: func(*cobra.Command, []string) {},
	Annotations:       map[string]string{auditOptionalAnnotation: "true", configOptionalAnnotation: "true"},
	SilenceUsage:      true,
	SilenceErrors:     true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ep := resolveOpenClawInstallPolicyEndpoint(os.Getenv)
		parent := cmd.Context()
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, ep.deadline)
		defer cancel()
		answer := decideOpenClawInstall(ctx, cmd.InOrStdin(), ep)
		if answer.Note != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "defenseclaw install-policy: %s\n", answer.Note)
		}
		return writeOpenClawInstallPolicyAnswer(cmd.OutOrStdout(), answer)
	},
}

func init() {
	connectorOpenClawCmd.AddCommand(connectorOpenClawInstallPolicyCmd)
}

const (
	// openClawInstallPolicyMaxInput is the request size OpenClaw sends at
	// most (DEFAULT_MAX_REQUEST_BYTES, 256 KiB); more is refused.
	openClawInstallPolicyMaxInput = 256 << 10
	// openClawInstallPolicyDefaultTimeout is the OpenClaw exec timeout
	// when exec.timeoutMs is not set.
	openClawInstallPolicyDefaultTimeout = 10 * time.Second
	openClawInstallPolicyMaxFindings    = 100
	openClawInstallPolicyMaxText        = 1000
)

type openClawInstallPolicyRequest struct {
	ProtocolVersion *int   `json:"protocolVersion"`
	TargetType      string `json:"targetType"`
	TargetName      string `json:"targetName"`
	SourcePath      string `json:"sourcePath"`
	SourcePathKind  string `json:"sourcePathKind"`
}

type openClawInstallPolicyFinding struct {
	RuleID   string `json:"ruleId"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
}

type openClawInstallPolicyAnswer struct {
	ProtocolVersion int                            `json:"protocolVersion"`
	Decision        string                         `json:"decision"`
	Reason          string                         `json:"reason,omitempty"`
	Findings        []openClawInstallPolicyFinding `json:"findings,omitempty"`
	// Note goes to stderr only (an allowed install during an outage).
	Note string `json:"-"`
}

func allowOpenClawInstall(findings []openClawInstallPolicyFinding) openClawInstallPolicyAnswer {
	return openClawInstallPolicyAnswer{ProtocolVersion: 1, Decision: "allow", Findings: findings}
}

func blockOpenClawInstall(reason string, findings []openClawInstallPolicyFinding) openClawInstallPolicyAnswer {
	reason = clipOpenClawInstallText(strings.TrimSpace(reason))
	if reason == "" {
		reason = "DefenseClaw blocked the install"
	}
	return openClawInstallPolicyAnswer{ProtocolVersion: 1, Decision: "block", Reason: reason, Findings: findings}
}

func clipOpenClawInstallText(s string) string {
	if len(s) <= openClawInstallPolicyMaxText {
		return s
	}
	return strings.ToValidUTF8(s[:openClawInstallPolicyMaxText-3], "") + "..."
}

func writeOpenClawInstallPolicyAnswer(w io.Writer, answer openClawInstallPolicyAnswer) error {
	out, err := json.Marshal(answer)
	if err != nil {
		out = []byte(`{"protocolVersion":1,"decision":"block","reason":"DefenseClaw could not write its answer"}`)
	}
	_, err = w.Write(append(out, byte(10)))
	return err
}

// openClawInstallPolicyEndpoint is how the command reaches the gateway.
type openClawInstallPolicyEndpoint struct {
	addr        string // loopback host:port of the gateway API
	token       string // the openclaw connector-scoped plugin credential
	failsClosed bool   // the answer when the gateway does not answer
	deadline    time.Duration
	// problem, when set, blocks every request: DefenseClaw cannot decide.
	problem string
}

// resolveOpenClawInstallPolicyEndpoint reads the endpoint from config.yaml
// or, in the separate-user layout (the OpenClaw account cannot read
// config.yaml), from the environment setup wrote into exec.env. Tests
// replace it.
var resolveOpenClawInstallPolicyEndpoint = func(getenv func(string) string) openClawInstallPolicyEndpoint {
	ep := openClawInstallPolicyEndpoint{failsClosed: true, deadline: openClawInstallPolicyDeadline(getenv(connector.OpenClawInstallPolicyTimeoutEnv))}
	if tokenFile := strings.TrimSpace(getenv(connector.OpenClawInstallPolicyTokenFileEnv)); tokenFile != "" {
		ep.addr = strings.TrimSpace(getenv(connector.OpenClawInstallPolicyAPIEnv))
		ep.failsClosed = strings.TrimSpace(getenv(connector.OpenClawInstallPolicyOutageEnv)) != "open"
		token, err := readOpenClawInstallPolicyToken(tokenFile)
		if err != nil {
			ep.problem = fmt.Sprintf("DefenseClaw could not read its OpenClaw credential %s (%v)", tokenFile, err)
		}
		ep.token = token
		return ep
	}
	if err := loadGatewayCommandConfigOnly(); err != nil || cfg == nil {
		ep.problem = fmt.Sprintf("DefenseClaw could not load config.yaml (%v); run defenseclaw doctor", err)
		return ep
	}
	ep.failsClosed = cfg.OpenClawInstallPolicyFailsClosed() ||
		strings.TrimSpace(getenv(connector.OpenClawInstallPolicyOutageEnv)) == "closed"
	host := gatewayClientHost(cfg)
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		// Connect to the address the gateway binds, as the plugin does.
		host = "127.0.0.1"
	}
	ep.addr = net.JoinHostPort(host, strconv.Itoa(cfg.Gateway.APIPort))
	if hookexec.InstallLockHeld(cfg.DataDir) {
		ep.problem = "DefenseClaw is being installed or upgraded; retry the install when it finishes"
		return ep
	}
	token, err := connector.LoadHookAPIToken(cfg.DataDir, "openclaw")
	if err != nil || strings.TrimSpace(token) == "" {
		ep.problem = "DefenseClaw has no OpenClaw plugin credential; run defenseclaw setup openclaw"
	}
	ep.token = strings.TrimSpace(token)
	return ep
}

// openClawInstallPolicyDeadline keeps the whole command inside the OpenClaw
// timeout: the timeout less a quarter, at most 5 s less.
func openClawInstallPolicyDeadline(raw string) time.Duration {
	timeout := openClawInstallPolicyDefaultTimeout
	if ms, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && ms >= 1000 && ms <= 3600000 {
		timeout = time.Duration(ms) * time.Millisecond
	}
	margin := timeout / 4
	if margin > 5*time.Second {
		margin = 5 * time.Second
	}
	return timeout - margin
}

func readOpenClawInstallPolicyToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("empty")
	}
	return token, nil
}

// readOpenClawInstallPolicyRequest reads one protocolVersion 1 request.
func readOpenClawInstallPolicyRequest(in io.Reader) (openClawInstallPolicyRequest, error) {
	var req openClawInstallPolicyRequest
	data, err := io.ReadAll(io.LimitReader(in, openClawInstallPolicyMaxInput+1))
	if err != nil {
		return req, err
	}
	if len(data) > openClawInstallPolicyMaxInput {
		return req, fmt.Errorf("the request is larger than %d bytes", openClawInstallPolicyMaxInput)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("the request is not a JSON object (%v)", err)
	}
	if dec.More() {
		return req, errors.New("the request holds more than one JSON value")
	}
	if req.ProtocolVersion == nil || *req.ProtocolVersion != 1 {
		return req, errors.New("the request protocolVersion is not 1")
	}
	return req, nil
}

// decideOpenClawInstall answers one OpenClaw install policy request.
func decideOpenClawInstall(ctx context.Context, in io.Reader, ep openClawInstallPolicyEndpoint) openClawInstallPolicyAnswer {
	req, err := readOpenClawInstallPolicyRequest(in)
	if err != nil {
		return blockOpenClawInstall("DefenseClaw could not read the OpenClaw install request: "+err.Error(), nil)
	}
	var route string
	switch req.TargetType {
	case "skill":
		route = "/v1/skill/scan"
	case "plugin":
		route = "/v1/plugin/scan"
	default:
		return blockOpenClawInstall(fmt.Sprintf("DefenseClaw has no admission for target type %q", req.TargetType), nil)
	}
	if req.SourcePathKind == "file" {
		// The npm metadata check before the download: no code to scan yet.
		// OpenClaw asks again with the staged package folder.
		return allowOpenClawInstall(nil)
	}
	if !filepath.IsAbs(req.SourcePath) {
		return blockOpenClawInstall("the OpenClaw install request names no absolute sourcePath", nil)
	}
	if ep.problem != "" {
		return blockOpenClawInstall(ep.problem, nil)
	}
	body, _ := json.Marshal(map[string]string{"target": req.SourcePath, "name": req.TargetName})
	status, raw, outage, err := openClawInstallPolicyCall(ctx, ep, route, body)
	if outage {
		if ep.failsClosed {
			return blockOpenClawInstall(fmt.Sprintf("the DefenseClaw gateway at %s did not answer (%v); this policy blocks installs until it runs (defenseclaw-gateway status)", ep.addr, err), nil)
		}
		answer := allowOpenClawInstall(nil)
		answer.Note = fmt.Sprintf("WARNING the DefenseClaw gateway at %s did not answer (%v); %s %s was installed without admission", ep.addr, err, req.TargetType, req.TargetName)
		return answer
	}
	if err != nil {
		return blockOpenClawInstall(err.Error(), nil)
	}
	return openClawInstallAnswerFromScan(req, status, raw)
}

// openClawInstallAnswerFromScan maps the gateway scan answer and its
// admission result (gatewayScanResponse) to an OpenClaw answer.
func openClawInstallAnswerFromScan(req openClawInstallPolicyRequest, status int, raw []byte) openClawInstallPolicyAnswer {
	var parsed gatewayScanResponse
	parseErr := json.Unmarshal(raw, &parsed)
	if status != http.StatusOK {
		message := strings.TrimSpace(parsed.Error)
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			message = "the gateway refused the OpenClaw plugin credential; run defenseclaw setup openclaw"
		} else if message == "" {
			message = fmt.Sprintf("HTTP %d", status)
		}
		return blockOpenClawInstall(fmt.Sprintf("DefenseClaw could not scan %s %s: %s", req.TargetType, req.TargetName, message), nil)
	}
	if parseErr != nil || parsed.Admission == nil || strings.TrimSpace(parsed.Admission.Verdict) == "" {
		return blockOpenClawInstall(fmt.Sprintf("DefenseClaw returned no admission decision for %s %s", req.TargetType, req.TargetName), nil)
	}
	var findings []openClawInstallPolicyFinding
	for _, f := range parsed.Result.Findings {
		if len(findings) == openClawInstallPolicyMaxFindings {
			break
		}
		message := strings.TrimSpace(f.Title)
		if message == "" {
			continue
		}
		ruleID := firstNonEmptyString(strings.TrimSpace(f.RuleID), strings.TrimSpace(f.Scanner), "defenseclaw")
		findings = append(findings, openClawInstallPolicyFinding{
			RuleID:   clipOpenClawInstallText(ruleID),
			Message:  clipOpenClawInstallText(message),
			Severity: openClawInstallSeverity(f.Severity),
			File:     clipOpenClawInstallText(strings.TrimSpace(f.Location)),
		})
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Admission.Verdict)) {
	case "blocked", "rejected":
		reason := strings.TrimSpace(parsed.Admission.Reason)
		if reason == "" {
			reason = "DefenseClaw admission blocked it"
		}
		return blockOpenClawInstall(fmt.Sprintf("DefenseClaw blocked %s %s: %s", req.TargetType, req.TargetName, reason), findings)
	}
	// clean, allowed and warning are admitted. OSS answers only allow or
	// block: a warn answer blocks gateway-backed and automatic installs.
	return allowOpenClawInstall(findings)
}

func openClawInstallSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "critical"
	case "MEDIUM", "LOW":
		return "warn"
	}
	return "info"
}

// errOpenClawInstallNotProven is a listener that did not prove it holds
// the plugin credential: nothing was sent, and it is not an outage.
var errOpenClawInstallNotProven = errors.New("the listener did not prove it is the DefenseClaw gateway of this account; the install request was not sent")

// openClawInstallPolicyCall proves the gateway listener on one loopback
// connection (GET /api/v1/hook-listener-proof, as the OpenClaw plugin does)
// and sends the scan on that same connection. outage reports a gateway
// that did not answer: the connection was refused or the deadline passed.
func openClawInstallPolicyCall(ctx context.Context, ep openClawInstallPolicyEndpoint, route string, body []byte) (status int, raw []byte, outage bool, err error) {
	host, _, splitErr := net.SplitHostPort(ep.addr)
	if ip := net.ParseIP(strings.Trim(host, "[]")); splitErr != nil || ip == nil || !ip.IsLoopback() {
		return 0, nil, false, fmt.Errorf("the DefenseClaw gateway address %q is not a loopback address; the install request was not sent", ep.addr)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", ep.addr)
	if err != nil {
		return 0, nil, true, err
	}
	used := false
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errOpenClawInstallNotProven
			}
			used = true
			return conn, nil
		},
		DisableCompression: true,
		MaxConnsPerHost:    1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	base := "http://" + ep.addr
	outageOf := func(err error) bool { return ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) }

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, nil, false, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	want, err := connector.UserScopedListenerProof(ep.token, "openclaw", nonce)
	if err != nil {
		return 0, nil, false, fmt.Errorf("the OpenClaw plugin credential is not usable (%v); run defenseclaw setup openclaw", err)
	}
	proofReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+connector.UserScopedListenerProofPath, nil)
	proofReq.Header.Set("X-DefenseClaw-Connector", "openclaw")
	proofReq.Header.Set(connector.UserScopedListenerKeyIDHeader, connector.UserScopedCredentialKeyID(ep.token))
	proofReq.Header.Set(connector.UserScopedListenerNonceHeader, nonce)
	proofResp, err := client.Do(proofReq)
	if err != nil {
		return 0, nil, outageOf(err), err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(proofResp.Body, 4096))
	proofResp.Body.Close()
	got, _ := hex.DecodeString(strings.TrimSpace(proofResp.Header.Get(connector.UserScopedListenerProofHeader)))
	wantBytes, _ := hex.DecodeString(want)
	if proofResp.StatusCode != http.StatusNoContent || len(got) == 0 || !hmac.Equal(got, wantBytes) {
		return 0, nil, false, errOpenClawInstallNotProven
	}

	scanReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+route, bytes.NewReader(body))
	scanReq.Header.Set("Content-Type", "application/json")
	scanReq.Header.Set("Authorization", "Bearer "+ep.token)
	scanReq.Header.Set("X-DefenseClaw-Token", ep.token)
	scanReq.Header.Set("X-DefenseClaw-Connector", "openclaw")
	scanReq.Header.Set("X-DefenseClaw-Client", "openclaw-install-policy")
	resp, err := client.Do(scanReq)
	if err != nil {
		if outageOf(err) {
			return 0, nil, true, err
		}
		return 0, nil, false, fmt.Errorf("the DefenseClaw gateway dropped the scan (%v)", err)
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, outageOf(err), err
	}
	return resp.StatusCode, raw, false, nil
}
