// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Gateway Bedrock signing for route-only (S1 DESIGN 7.3, 15.6, 16.8): the
// agent runs with CLAUDE_CODE_SKIP_BEDROCK_AUTH=1, so its request carries no
// AWS credential; the gateway signs every upstream attempt (original, routed
// and the retry) with SigV4 over the exact body and the escaped path it
// sends, after the model id swap. An inbound agent signature is never
// forwarded: the agent SDK signed Host 127.0.0.1.

const (
	bedrockSigningService = "bedrock"
	// Static credentials (env names, protected credential refs) are re-read
	// at most this often, so a rotated credential file is picked up.
	bedrockStaticCredentialTTL = 5 * time.Minute
	bedrockSignerCacheMax      = 64
)

// errBedrockSigning marks a failure to sign (no credential, bad profile);
// the request was never written.
var errBedrockSigning = errors.New("gateway Bedrock signing failed")

// errBedrockSignTooLarge: a body over the 64 MiB buffer cap streams and
// cannot be hashed first, so it cannot be signed (Bedrock has no unsigned
// payload mode). A full buffer budget is answered overloaded instead.
var errBedrockSignTooLarge = fmt.Errorf("%w: the request body is too large to sign", errBedrockSigning)

// routeOnlySendError answers a failed upstream send in the provider form.
func routeOnlySendError(w http.ResponseWriter, err error, msg string) {
	switch {
	case errors.Is(err, errBedrockSignTooLarge):
		routeOnlyError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "the request is too large for gateway Bedrock signing")
	case errors.Is(err, errBedrockSigning):
		bedrockSignLogf("send", "[routing] route-only: %v\n", err)
		routeOnlyError(w, http.StatusBadGateway, "api_error", "gateway Bedrock signing failed (no usable AWS credential); run defenseclaw doctor")
	default:
		routeOnlyError(w, http.StatusBadGateway, "api_error", msg)
	}
}

// routeOnlyLogLimiter lets one stderr line per key through each interval, so
// a signing outage does not write a line per request (REVIEW-code-slice7
// P3-7).
type routeOnlyLogLimiter struct {
	mu    sync.Mutex
	every time.Duration
	now   func() time.Time
	last  map[string]time.Time
}

func (l *routeOnlyLogLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.every {
		return false
	}
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	l.last[key] = now
	return true
}

var bedrockSignLog = &routeOnlyLogLimiter{every: time.Minute, now: time.Now}

// bedrockSignLogf writes a signing failure line at most once a minute per key.
func bedrockSignLogf(key, format string, args ...any) {
	if bedrockSignLog.allow(key) {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// bedrockSignableOp is the escaped native path of the only Bedrock calls the
// gateway signs with its own identity: Converse and InvokeModel (streaming
// or not) on one model id segment (an ARN keeps its %2F). StartAsyncInvoke,
// CountTokens, ApplyGuardrail and the model list are not model calls the
// routing gate judges, so they are never signed (REVIEW-code-slice7 P2-1).
var bedrockSignableOp = regexp.MustCompile(`^/model/[^/]+/(?:converse|converse-stream|invoke|invoke-with-response-stream)$`)

// bedrockSignableRequest reports a request the gateway may sign.
func bedrockSignableRequest(method, native string) bool {
	return method == http.MethodPost && bedrockSignableOp.MatchString(native)
}

// bedrockSignableURL reports an upstream the gateway sends its AWS
// credential to: HTTPS to an AWS Bedrock runtime host only (P3-9). Tests
// widen it to their loopback servers.
var bedrockSignableURL = func(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, "https") && bedrockRegionFromURL(raw) != ""
}

// Credentials are refreshed a little before they expire, so a call is never
// signed with one that lapses on the way (P3-5).
const bedrockCredentialExpiryWindow = time.Minute

func bedrockCacheOptions(o *aws.CredentialsCacheOptions) {
	o.ExpiryWindow = bedrockCredentialExpiryWindow
	o.ExpiryWindowJitterFrac = 0.5
}

func bedrockCredentialsCache(p aws.CredentialsProvider) *aws.CredentialsCache {
	return aws.NewCredentialsCache(p, bedrockCacheOptions)
}

// stripAmzQuery drops X-Amz-* query keys (a presigned URL form): next to
// the gateway Authorization header AWS refuses the call for two auth forms
// (P3-8). Other keys are kept as sent.
func stripAmzQuery(raw string) string {
	if raw == "" {
		return raw
	}
	vals, err := url.ParseQuery(raw)
	drop := err != nil
	for k := range vals {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			delete(vals, k)
			drop = true
		}
	}
	if !drop {
		return raw
	}
	return vals.Encode()
}

// bedrockGatewaySigning reports whether the bedrock block asks the gateway
// to sign (profile, instance_role, iam_credentials); passthrough and an
// absent block keep the agent credential.
func bedrockGatewaySigning(b *config.RoutingBedrockAuthConfig) bool {
	if b == nil {
		return false
	}
	switch b.Auth {
	case config.RoutingBedrockAuthProfile, config.RoutingBedrockAuthInstanceRole, config.RoutingBedrockAuthIAMCredentials:
		return true
	}
	return false
}

// bedrockRuntimeHostPattern matches bedrock-runtime.<region>.amazonaws.com,
// its FIPS form, VPC endpoint names and the China partition.
var bedrockRuntimeHostPattern = regexp.MustCompile(`(?:^|\.)bedrock-runtime(?:-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.(?:vpce\.)?amazonaws\.com(?:\.cn)?$`)

// bedrockRegionFromURL is the region named by a Bedrock runtime host ("" for
// other hosts, such as a corporate gateway).
func bedrockRegionFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	m := bedrockRuntimeHostPattern.FindStringSubmatch(strings.ToLower(u.Hostname()))
	if m == nil {
		return ""
	}
	return m[1]
}

// bedrockSigningRegion picks the signing region: the host region when the
// host names one (a block region that disagrees is refused, the signature
// would never verify), else the block region.
func bedrockSigningRegion(b *config.RoutingBedrockAuthConfig, baseURL string) (string, error) {
	host := bedrockRegionFromURL(baseURL)
	block := ""
	if b != nil {
		block = strings.TrimSpace(b.Region)
	}
	switch {
	case host != "" && block != "" && !strings.EqualFold(host, block):
		return "", fmt.Errorf("bedrock.region %s does not match the upstream host region %s", block, host)
	case host != "":
		return host, nil
	case block != "":
		return block, nil
	}
	return "", errors.New("bedrock.region is not set and the upstream host names no region")
}

// bedrockSigner signs Bedrock requests for one credential source and region.
type bedrockSigner struct {
	creds  aws.CredentialsProvider
	region string
	signer *v4.Signer
	now    func() time.Time
}

// newBedrockSigner builds a signer from a bedrock block. Managed hosts read
// only protected credential refs (the *_env names are refused there by
// validation and ignored here) and do not use a shared-config profile.
func newBedrockSigner(cfg *config.Config, b *config.RoutingBedrockAuthConfig, region string) (*bedrockSigner, error) {
	if !bedrockGatewaySigning(b) {
		return nil, errors.New("bedrock.auth is not a gateway signing mode")
	}
	managedHost := cfg != nil && cfg.StandaloneEnterprise()
	var provider aws.CredentialsProvider
	switch b.Auth {
	case config.RoutingBedrockAuthProfile:
		if managedHost {
			return nil, errors.New("bedrock.auth profile is not used on a managed host: use instance_role or the *_credential names")
		}
		profile := strings.TrimSpace(b.Profile)
		if profile == "" {
			profile = "default"
		}
		ac, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithSharedConfigProfile(profile), awsconfig.WithRegion(region), awsconfig.WithCredentialsCacheOptions(bedrockCacheOptions))
		if err != nil {
			return nil, fmt.Errorf("AWS profile %s: %w", profile, err)
		}
		provider = ac.Credentials
	case config.RoutingBedrockAuthInstanceRole:
		// The SDK default chain: on EC2 the instance role through IMDSv2,
		// on ECS or EKS the task or pod role.
		ac, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region), awsconfig.WithCredentialsCacheOptions(bedrockCacheOptions))
		if err != nil {
			return nil, fmt.Errorf("AWS default credential chain: %w", err)
		}
		provider = ac.Credentials
	case config.RoutingBedrockAuthIAMCredentials:
		provider = bedrockCredentialsCache(bedrockStaticCredentials(cfg, b, managedHost))
	}
	if provider == nil {
		return nil, errors.New("no AWS credential provider")
	}
	if _, cached := provider.(*aws.CredentialsCache); !cached {
		provider = bedrockCredentialsCache(provider)
	}
	return &bedrockSigner{creds: provider, region: region, signer: v4.NewSigner(), now: time.Now}, nil
}

// bedrockStaticCredentials reads the key names at every refresh (never the
// values into config or logs).
func bedrockStaticCredentials(cfg *config.Config, b *config.RoutingBedrockAuthConfig, managedHost bool) aws.CredentialsProviderFunc {
	read := func(envName, credName string) string {
		if managedHost {
			return cfg.RoutingCredential(credName)
		}
		if envName = strings.TrimSpace(envName); envName == "" {
			return ""
		}
		return strings.TrimSpace(os.Getenv(envName))
	}
	return func(context.Context) (aws.Credentials, error) {
		c := aws.Credentials{
			AccessKeyID:     read(b.AccessKeyEnv, b.AccessKeyCredential),
			SecretAccessKey: read(b.SecretKeyEnv, b.SecretKeyCredential),
			SessionToken:    read(b.SessionTokenEnv, b.SessionTokenCredential),
			Source:          "defenseclaw-routing",
			CanExpire:       true,
			Expires:         time.Now().Add(bedrockStaticCredentialTTL),
		}
		if c.AccessKeyID == "" || c.SecretAccessKey == "" {
			if managedHost {
				return aws.Credentials{}, errors.New("the access_key_credential or secret_key_credential protected credential is empty or unreadable")
			}
			return aws.Credentials{}, errors.New("the access_key_env or secret_key_env variable is not set in the gateway environment")
		}
		return c, nil
	}
}

// stripInboundAWSAuth removes every agent-side credential and AWS signing
// header before the gateway signs.
func stripInboundAWSAuth(h http.Header) {
	for k := range h {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Authorization" || ck == "X-Api-Key" || strings.HasPrefix(ck, "X-Amz-") {
			delete(h, k)
		}
	}
}

// sign signs req for the exact payload it carries. Only host, x-amz-date,
// x-amz-content-sha256 and x-amz-security-token are signed, so header
// changes on the way (user agent, accept encoding) never break it. The
// canonical URI is the escaped path req sends (ARN model ids keep %2F as
// one segment; the signer escapes it again, as AWS SDKs do for Bedrock).
func (s *bedrockSigner) sign(ctx context.Context, req *http.Request, payload []byte) error {
	stripInboundAWSAuth(req.Header)
	req.URL.RawQuery = stripAmzQuery(req.URL.RawQuery)
	sum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(sum[:])
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errBedrockSigning, err)
	}
	u := *req.URL
	shadow := &http.Request{Method: req.Method, URL: &u, Host: req.Host, Header: http.Header{}}
	shadow.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := s.signer.SignHTTP(ctx, creds, shadow, payloadHash, bedrockSigningService, s.region, s.now()); err != nil {
		return fmt.Errorf("%w: %v", errBedrockSigning, err)
	}
	for _, k := range []string{"Authorization", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Amz-Security-Token"} {
		if v := shadow.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}
	if shadow.Host != "" {
		req.Host = shadow.Host
	}
	return nil
}

// bedrockSignerKey identifies a signer by its credential source (names
// only, never values) and region.
type bedrockSignerKey struct {
	auth, profile, region                      string
	accessEnv, secretEnv, tokenEnv             string
	accessCred, secretCred, tokenCred, cfgPath string
	managed                                    bool
}

// bedrockSigners caches signers, so the SDK credential cache (profile,
// IMDSv2 role, SSO) survives across requests and config reloads.
type bedrockSigners struct {
	mu sync.Mutex
	m  map[bedrockSignerKey]*bedrockSigner
}

// get returns the signer for block b signing toward baseURL.
func (c *bedrockSigners) get(cfg *config.Config, b *config.RoutingBedrockAuthConfig, baseURL string) (*bedrockSigner, error) {
	if !bedrockSignableURL(baseURL) {
		return nil, errors.New("gateway Bedrock signing sends the AWS credential only to an https bedrock-runtime.<region>.amazonaws.com host")
	}
	region, err := bedrockSigningRegion(b, baseURL)
	if err != nil {
		return nil, err
	}
	key := bedrockSignerKey{
		auth: b.Auth, profile: strings.TrimSpace(b.Profile), region: region,
		accessEnv: b.AccessKeyEnv, secretEnv: b.SecretKeyEnv, tokenEnv: b.SessionTokenEnv,
		accessCred: b.AccessKeyCredential, secretCred: b.SecretKeyCredential, tokenCred: b.SessionTokenCredential,
	}
	if cfg != nil {
		key.managed, key.cfgPath = cfg.StandaloneEnterprise(), cfg.ConfigFilePath
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s := c.m[key]; s != nil {
		return s, nil
	}
	s, err := newBedrockSigner(cfg, b, region)
	if err != nil {
		return nil, err
	}
	if c.m == nil || len(c.m) >= bedrockSignerCacheMax {
		c.m = map[bedrockSignerKey]*bedrockSigner{}
	}
	c.m[key] = s
	return s, nil
}

// routeOnlyRenderSigners serves the render check, so a reload reuses the
// credential it fetched instead of asking IMDS, STS or SSO again.
var routeOnlyRenderSigners bedrockSigners

const bedrockRenderCheckTimeout = 2 * time.Second

// bedrockRenderReady fetches one credential (bounded) for block b toward
// baseURL: CLAUDE_CODE_SKIP_BEDROCK_AUTH is rendered only when the gateway
// can sign now, not merely when its config loads (REVIEW-code-slice7 P3-1).
func bedrockRenderReady(cfg *config.Config, b *config.RoutingBedrockAuthConfig, baseURL string) error {
	s, err := routeOnlyRenderSigners.get(cfg, b, baseURL)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), bedrockRenderCheckTimeout)
	defer cancel()
	if _, err := s.creds.Retrieve(ctx); err != nil {
		return fmt.Errorf("no AWS credential: %w", err)
	}
	return nil
}
