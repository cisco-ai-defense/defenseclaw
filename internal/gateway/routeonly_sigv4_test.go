// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// isolateAWSEnv keeps the developer or CI AWS setup out of a test.
func isolateAWSEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	return dir
}

const sigv4ARNPath = "/model/arn%3Aaws%3Abedrock%3Aus-west-2%3A111122223333%3Ainference-profile%2Fus.anthropic.claude-sonnet-4-5-v1%3A0/invoke-with-response-stream"

func signForTest(t *testing.T, s *bedrockSigner, rawURL string, body []byte, inbound http.Header) sigv4Wire {
	t.Helper()
	s.now = func() time.Time { return time.Date(2026, 11, 12, 23, 0, 0, 0, time.UTC) }
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range inbound {
		req.Header[k] = vs
	}
	if err := s.sign(context.Background(), req, body); err != nil {
		t.Fatal(err)
	}
	return sigv4Wire{method: req.Method, escapedPath: req.URL.EscapedPath(), rawQuery: req.URL.RawQuery, host: req.Host, header: req.Header, body: body}
}

func TestBedrockSigV4StaticCredentialsARNPathVerifies(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("DC_SIGV4_AK", "AKIDSTATIC")
	t.Setenv("DC_SIGV4_SK", "static-secret")
	t.Setenv("DC_SIGV4_ST", "static-session")
	b := &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthIAMCredentials, AccessKeyEnv: "DC_SIGV4_AK", SecretKeyEnv: "DC_SIGV4_SK", SessionTokenEnv: "DC_SIGV4_ST"}
	var cache bedrockSigners
	s, err := cache.get(&config.Config{}, b, "https://bedrock-runtime.us-west-2.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"hi"}]}`)
	inbound := http.Header{"Authorization": {"Bearer stale"}, "X-Amz-Security-Token": {"agent"}, "X-Amz-Date": {"19990101T000000Z"}, "Content-Type": {"application/json"}}
	w := signForTest(t, s, "https://bedrock-runtime.us-west-2.amazonaws.com"+sigv4ARNPath, body, inbound)
	if w.escapedPath != sigv4ARNPath {
		t.Fatalf("wire path %q lost the escaped ARN segment", w.escapedPath)
	}
	scope, err := verifySigV4(w, "static-secret")
	if err != nil {
		t.Fatal(err)
	}
	if scope[1] != "us-west-2" || scope[2] != "bedrock" {
		t.Fatalf("scope = %v, want us-west-2/bedrock", scope)
	}
	auth := w.header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIDSTATIC/") || !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,") {
		t.Fatalf("authorization = %q", auth)
	}
	if w.header.Get("X-Amz-Security-Token") != "static-session" || strings.HasPrefix(w.header.Get("X-Amz-Date"), "1999") {
		t.Fatal("inbound x-amz headers were not replaced")
	}
	w.body = []byte(`{"tampered":true}`)
	w.header.Set("X-Amz-Content-Sha256", sigv4Hex(w.body))
	if _, err := verifySigV4(w, "static-secret"); err == nil {
		t.Fatal("a changed body still verified")
	}
	if again, _ := cache.get(&config.Config{}, b, "https://bedrock-runtime.us-west-2.amazonaws.com"); again != s {
		t.Fatal("the signer (and its credential cache) was not reused")
	}
}

func TestBedrockSigV4ProfileAndDefaultChain(t *testing.T) {
	dir := isolateAWSEnv(t)
	creds := "[dc-route]\naws_access_key_id = AKIDPROFILE\naws_secret_access_key = profile-secret\n"
	if err := os.WriteFile(filepath.Join(dir, "credentials"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	var cache bedrockSigners
	b := &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthProfile, Profile: "dc-route", Region: "eu-central-1"}
	s, err := cache.get(&config.Config{}, b, "https://bedrock-runtime.eu-central-1.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	w := signForTest(t, s, "https://bedrock-runtime.eu-central-1.amazonaws.com/model/m/invoke", []byte("{}"), nil)
	if scope, err := verifySigV4(w, "profile-secret"); err != nil || scope[1] != "eu-central-1" {
		t.Fatalf("profile signature: scope %v, %v", scope, err)
	}
	if _, err := cache.get(&config.Config{}, &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthProfile, Profile: "missing", Region: "us-east-1"}, "https://bedrock-runtime.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("a missing profile built a signer")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDCHAIN")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "chain-secret")
	s, err = cache.get(&config.Config{}, &config.RoutingBedrockAuthConfig{Auth: config.RoutingBedrockAuthInstanceRole}, "https://bedrock-runtime.us-east-2.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	w = signForTest(t, s, "https://bedrock-runtime.us-east-2.amazonaws.com/model/m/converse", []byte("{}"), nil)
	if _, err := verifySigV4(w, "chain-secret"); err != nil {
		t.Fatalf("default chain signature: %v", err)
	}
}

func TestBedrockSigV4RegionFromHost(t *testing.T) {
	for raw, want := range map[string]string{
		"https://bedrock-runtime.us-east-1.amazonaws.com":                         "us-east-1",
		"https://bedrock-runtime-fips.us-gov-west-1.amazonaws.com/":               "us-gov-west-1",
		"https://vpce-0abc.bedrock-runtime.eu-west-3.vpce.amazonaws.com":          "eu-west-3",
		"https://bedrock-runtime.cn-north-1.amazonaws.com.cn":                     "cn-north-1",
		"https://bedrock-runtime.us-east-1.amazonaws.com.evil.example":            "",
		"http://127.0.0.1:4100":                                                   "",
		"https://bedrock-runtime.ap-southeast-2.amazonaws.com:443/model/x/invoke": "ap-southeast-2",
	} {
		if got := bedrockRegionFromURL(raw); got != want {
			t.Errorf("%s: region %q, want %q", raw, got, want)
		}
	}
	if _, err := bedrockSigningRegion(&config.RoutingBedrockAuthConfig{Region: "us-west-2"}, "https://bedrock-runtime.us-east-1.amazonaws.com"); err == nil {
		t.Error("a region that disagrees with the host was accepted")
	}
	if _, err := bedrockSigningRegion(&config.RoutingBedrockAuthConfig{}, "https://gw.corp.example"); err == nil {
		t.Error("no region at all was accepted")
	}
	if !bedrockGatewaySigning(&config.RoutingBedrockAuthConfig{Auth: "profile"}) || bedrockGatewaySigning(&config.RoutingBedrockAuthConfig{Auth: "passthrough"}) || bedrockGatewaySigning(nil) {
		t.Error("gateway signing modes")
	}
}
