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

// errBedrockSignTooLarge: a body over the buffer cap or budget streams and
// cannot be hashed first, so it cannot be signed (Bedrock has no unsigned
// payload mode).
var errBedrockSignTooLarge = fmt.Errorf("%w: the request body is too large to sign", errBedrockSigning)

// routeOnlySendError answers a failed upstream send in the provider form.
func routeOnlySendError(w http.ResponseWriter, err error, msg string) {
	switch {
	case errors.Is(err, errBedrockSignTooLarge):
		routeOnlyError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "the request is too large for gateway Bedrock signing")
	case errors.Is(err, errBedrockSigning):
		fmt.Fprintf(os.Stderr, "[routing] route-only: %v\n", err)
		routeOnlyError(w, http.StatusBadGateway, "api_error", "gateway Bedrock signing failed (no usable AWS credential); run defenseclaw doctor")
	default:
		routeOnlyError(w, http.StatusBadGateway, "api_error", msg)
	}
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
		ac, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithSharedConfigProfile(profile), awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("AWS profile %s: %w", profile, err)
		}
		provider = ac.Credentials
	case config.RoutingBedrockAuthInstanceRole:
		// The SDK default chain: on EC2 the instance role through IMDSv2,
		// on ECS or EKS the task or pod role.
		ac, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("AWS default credential chain: %w", err)
		}
		provider = ac.Credentials
	case config.RoutingBedrockAuthIAMCredentials:
		provider = aws.NewCredentialsCache(bedrockStaticCredentials(cfg, b, managedHost))
	}
	if provider == nil {
		return nil, errors.New("no AWS credential provider")
	}
	if _, cached := provider.(*aws.CredentialsCache); !cached {
		provider = aws.NewCredentialsCache(provider)
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
