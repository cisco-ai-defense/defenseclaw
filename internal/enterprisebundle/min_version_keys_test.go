// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

const trustedConnectorBundleKeys = "  identity:\n    trusted_connectors:\n      - name: gas\n        account: svc-gas\n" +
	"        may_act_for:\n          groups: [agents-users]\n"

// Sign-time lint: a bundle that sets a key only 1.0.6 reads must carry
// min_product_version 1.0.6 or later.
func TestComposeRequiresProductFloorForTrustedConnectors(t *testing.T) {
	config := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n"+trustedConnectorBundleKeys, 1)
	for _, tc := range []struct {
		min    string
		refuse bool
	}{{"", true}, {"1.0.5", true}, {"1.0.6", false}, {"1.1.0", false}} {
		root, b := writeBundle(t, config)
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			MinProductVersion: tc.min, ProductVersion: "1.0.6", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		}
		_, _, err := enterprisebundle.Compose(context.Background(), in)
		if tc.refuse {
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "trusted_connectors") {
				t.Errorf("min %q: got %v, want config_invalid naming trusted_connectors", tc.min, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("min %q: %v", tc.min, err)
		}
	}
	for name, key := range map[string]string{
		"agent_gateway": "connectors:\n  agent_gateway:\n    enabled: true\n",
		"root_scope":    "guardrail:\n  chains:\n    root_scope: true\n",
	} {
		root, b := writeBundle(t, mergeTopLevel(bundleConfig(t), key))
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			ProductVersion: "1.0.6", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		}
		if _, _, err := enterprisebundle.Compose(context.Background(), in); !strings.Contains(errString(err), name) {
			t.Errorf("%s without a floor: got %v", name, err)
		}
	}
}

// mergeTopLevel adds a top-level block to config, or merges a guardrail
// block into the existing one.
func mergeTopLevel(config, block string) string {
	if strings.HasPrefix(block, "guardrail:\n") && strings.Contains(config, "\nguardrail:\n") {
		return strings.Replace(config, "\nguardrail:\n", "\n"+block, 1)
	}
	return config + block
}

// An older signed bundle that still lists a removed trusted connector is
// refused by the version floor once a newer bundle is confirmed.
func TestOlderBundleWithRemovedConnectorRefusedByFloor(t *testing.T) {
	older := &enterprisebundle.Manifest{BundleID: tamperBundleID, Version: 5}
	confirmed := enterprisebundle.Confirmed{Version: 6, BundleID: tamperBundleID, ManifestSHA256: strings.Repeat("a", 64)}
	if _, _, err := enterprisebundle.CheckFloor(older, strings.Repeat("b", 64), confirmed, 0); enterprisebundle.CodeOf(err) != enterprisebundle.CodeVersionNotNewer {
		t.Fatalf("an older bundle was not refused by the floor: %v", err)
	}
}

// Test tenant secrets: bytes 00..1f and 20..3f, base64url.
const (
	testJoinSecret     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	testJoinNextSecret = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
)

func joinDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// accountJoinBlock is an enterprise.account_join block for the test
// secrets, with the next generation when notAfter is set.
func accountJoinBlock(notAfter string) string {
	block := "  account_join:\n    mode: on\n    generation: 1\n    secret_sha256: " + joinDigest(testJoinSecret) + "\n"
	if notAfter != "" {
		block += "    next_generation: 2\n    next_secret_sha256: " + joinDigest(testJoinNextSecret) + "\n    next_not_after: \"" + notAfter + "\"\n"
	}
	return block
}

// accountJoinSecretValues are the --secret-file values of the test secrets.
func accountJoinSecretValues() map[string][]byte {
	return map[string][]byte{accountjoin.SecretName: []byte(testJoinSecret), accountjoin.NextSecretName: []byte(testJoinNextSecret)}
}

func accountJoinCompose(t *testing.T, block string, values map[string][]byte) (*enterprisebundle.Manifest, []byte, *enterprisebundle.Bundle, error) {
	t.Helper()
	config := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n"+block, 1)
	root, b := writeBundle(t, config)
	in := enterprisebundle.ComposeInput{
		Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
		Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
		MinProductVersion: "1.0.7", ProductVersion: "1.0.7", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		SecretValues: values,
	}
	m, raw, err := enterprisebundle.Compose(context.Background(), in)
	return m, raw, b, err
}

// rel-1-0-6:GAP-0276 (private #13 review, should-change 2): the tenant
// secrets are value-bound optional secret_refs. Sign needs their values,
// refuses values that are not the digests the config names or not tenant
// secrets, and never writes a value into the bundle.
func TestComposeBindsTheAccountJoinSecrets(t *testing.T) {
	notAfter := signedAt.Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, _, _, err := accountJoinCompose(t, accountJoinBlock(""), nil); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound || !strings.Contains(errString(err), accountjoin.SecretName) {
		t.Fatalf("no --secret-file: %v, want secret_ref_unbound naming %s", err, accountjoin.SecretName)
	}
	only := map[string][]byte{accountjoin.SecretName: []byte(testJoinSecret)}
	if _, _, _, err := accountJoinCompose(t, accountJoinBlock(notAfter), only); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefUnbound || !strings.Contains(errString(err), accountjoin.NextSecretName) {
		t.Fatalf("no next --secret-file: %v, want secret_ref_unbound naming %s", err, accountjoin.NextSecretName)
	}
	m, raw, b, err := accountJoinCompose(t, accountJoinBlock(notAfter), accountJoinSecretValues())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		accountjoin.SecretName:     enterprisebundle.CredentialValueSHA256("acme", accountjoin.SecretName, []byte(testJoinSecret)),
		accountjoin.NextSecretName: enterprisebundle.CredentialValueSHA256("acme", accountjoin.NextSecretName, []byte(testJoinNextSecret)),
	}
	for _, ref := range m.SecretRefs {
		if digest, ok := want[ref.Name()]; ok {
			if ref.Required || ref.ValueSHA256 != digest {
				t.Errorf("%s: %+v, want an optional reference bound to its value", ref.Name(), ref)
			}
			delete(want, ref.Name())
		}
	}
	if len(want) != 0 {
		t.Fatalf("secret_refs %+v lack %v", m.SecretRefs, want)
	}
	// The written bundle holds no form of either secret: the archive is
	// read back, and the manifest and every file are searched uncompressed.
	b.Manifest, b.Signature = raw, []byte(`{"s":1}`)
	var archive bytes.Buffer
	if err := enterprisebundle.WriteArchive(&archive, b); err != nil {
		t.Fatal(err)
	}
	back, err := enterprisebundle.ReadArchive(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{back.Manifest, back.Signature}
	for _, data := range back.Files {
		contents = append(contents, data)
	}
	written := bytes.Join(contents, []byte{0})
	if !bytes.Contains(written, []byte(joinDigest(testJoinSecret))) {
		t.Fatal("the search reads the wrong bytes: the config's secret_sha256 is not in them")
	}
	for _, secret := range []string{testJoinSecret, testJoinNextSecret} {
		decoded, err := base64.RawURLEncoding.DecodeString(secret)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range []string{secret, hex.EncodeToString(decoded), base64.StdEncoding.EncodeToString(decoded), base64.RawStdEncoding.EncodeToString(decoded), string(decoded)} {
			if bytes.Contains(written, []byte(form)) {
				t.Fatalf("the signed bundle holds a form of a tenant secret (%d bytes)", len(form))
			}
		}
	}
	// A value that is not the digest the config names, or not a tenant
	// secret, is refused without echoing it.
	for name, values := range map[string]map[string][]byte{
		"other current value": {accountjoin.SecretName: []byte(testJoinNextSecret), accountjoin.NextSecretName: []byte(testJoinNextSecret)},
		"other next value":    {accountjoin.SecretName: []byte(testJoinSecret), accountjoin.NextSecretName: []byte(testJoinSecret)},
		"not a tenant secret": {accountjoin.SecretName: []byte("short"), accountjoin.NextSecretName: []byte(testJoinNextSecret)},
	} {
		_, _, _, err := accountJoinCompose(t, accountJoinBlock(notAfter), values)
		if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid {
			t.Errorf("%s: %v, want config_invalid", name, err)
		}
		for _, value := range values {
			if strings.Contains(errString(err), string(value)) {
				t.Errorf("%s: the refusal echoes a value", name)
			}
		}
	}
}

// The device refuses a bundle whose config turns account_join on without
// binding its tenant secrets, and secret set refuses a value the confirmed
// bundle does not sign.
func TestAccountJoinSecretRefsOnTheDevice(t *testing.T) {
	m, _, b, err := accountJoinCompose(t, accountJoinBlock(""), map[string][]byte{accountjoin.SecretName: []byte(testJoinSecret)})
	if err != nil {
		t.Fatal(err)
	}
	if err := enterprisebundle.CheckSecretRefs(m, b); err != nil {
		t.Fatalf("bound bundle: %v", err)
	}
	unbound := *m
	unbound.SecretRefs = nil
	for _, ref := range m.SecretRefs {
		if ref.Name() != accountjoin.SecretName {
			unbound.SecretRefs = append(unbound.SecretRefs, ref)
		}
	}
	if err := enterprisebundle.CheckSecretRefs(&unbound, b); enterprisebundle.CodeOf(err) != enterprisebundle.CodeManifestInvalid {
		t.Fatalf("bundle without the account join reference: %v, want manifest_invalid", err)
	}
	if err := enterprisebundle.CheckCredentialChange(m, nil, accountjoin.SecretName, []byte(testJoinSecret)); err != nil {
		t.Fatalf("the signed value: %v", err)
	}
	if err := enterprisebundle.CheckCredentialChange(m, nil, accountjoin.SecretName, []byte(testJoinNextSecret)); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMismatch {
		t.Fatalf("another value: %v, want secret_ref_mismatch", err)
	}
}

func TestAccountJoinCredentials(t *testing.T) {
	for _, tc := range []struct {
		config string
		want   string
	}{
		{"config_version: 9\n", ""},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: off\n    generation: 1\n", ""},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n", accountjoin.SecretName},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: 2\n", accountjoin.SecretName + "," + accountjoin.NextSecretName},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: 0\n", accountjoin.SecretName},
		// A form the lookup cannot read as zero needs the next secret.
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: 0x2\n", accountjoin.SecretName + "," + accountjoin.NextSecretName},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: two\n", accountjoin.SecretName + "," + accountjoin.NextSecretName},
		{"config_version: 9\nenterprise:\n  account_join:\n    mode: on\n    generation: 1\n    next_generation: null\n", accountjoin.SecretName},
	} {
		names, err := enterprisebundle.AccountJoinCredentials([]byte(tc.config))
		if err != nil || strings.Join(names, ",") != tc.want {
			t.Errorf("%q: %v, %v; want %q", tc.config, names, err, tc.want)
		}
	}
}

// rel-1-0-6:GAP-0277: bundle sign refuses a next_not_after more than 30
// days after the signing time, which the device would refuse.
func TestComposeBoundsAccountJoinNextNotAfterBySigningTime(t *testing.T) {
	for _, tc := range []struct {
		days   int
		refuse bool
	}{{29, false}, {30, false}, {31, true}} {
		block := accountJoinBlock(signedAt.Add(time.Duration(tc.days) * 24 * time.Hour).UTC().Format(time.RFC3339))
		_, _, _, err := accountJoinCompose(t, block, accountJoinSecretValues())
		if tc.refuse {
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "next_not_after") {
				t.Errorf("%d days: got %v, want config_invalid naming next_not_after", tc.days, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d days: %v", tc.days, err)
		}
	}
}

// A bundle that sets enterprise.account_join needs min_product_version 1.0.7.
func TestComposeRequiresProductFloorForAccountJoin(t *testing.T) {
	config := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n"+accountJoinBlock(""), 1)
	for _, tc := range []struct {
		min    string
		refuse bool
	}{{"", true}, {"1.0.6", true}, {"1.0.7", false}} {
		root, b := writeBundle(t, config)
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			MinProductVersion: tc.min, ProductVersion: "1.0.7", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
			SecretValues: map[string][]byte{accountjoin.SecretName: []byte(testJoinSecret)},
		}
		_, _, err := enterprisebundle.Compose(context.Background(), in)
		if tc.refuse {
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "account_join") {
				t.Errorf("min %q: got %v, want config_invalid naming account_join", tc.min, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("min %q: %v", tc.min, err)
		}
	}
}

func TestComposeRequiresProductFloorForRoutingAdmin(t *testing.T) {
	config := bundleConfig(t) + "routing:\n  enabled: false\n  classifier: rules\n  models:\n    - name: fast\n      provider: openai\n      model: gpt-4.1-mini\n  admin:\n    allowed_aliases: [fast]\n"
	for _, tc := range []struct {
		min    string
		refuse bool
	}{{"", true}, {"1.0.9", true}, {"1.0.10", false}} {
		root, b := writeBundle(t, config)
		in := enterprisebundle.ComposeInput{
			Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
			Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
			MinProductVersion: tc.min, ProductVersion: "1.0.10", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
		}
		_, _, err := enterprisebundle.Compose(context.Background(), in)
		if tc.refuse {
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "routing.admin") {
				t.Errorf("min %q: got %v, want config_invalid naming routing.admin", tc.min, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("min %q: %v", tc.min, err)
		}
	}
}

func TestComposeRequiresProductFloorForTokenomics(t *testing.T) {
	for name, block := range map[string]string{
		"tokenomics": "observability:\n  tokenomics:\n    enabled: true\n    local_store:\n      enabled: true\n",
		"pricing":    "observability:\n  pricing:\n    version: \"2026-11-12.1\"\n    models:\n      - provider: openai\n        model: gpt-4.1-mini\n        input_per_mtok: 0.4\n        output_per_mtok: 1.6\n",
		// An explicit disable still writes the key a 1.0.9 device refuses.
		"tokenomics off": "observability:\n  tokenomics:\n    enabled: false\n",
	} {
		for _, tc := range []struct {
			min    string
			refuse bool
		}{{"", true}, {"1.0.6", true}, {"1.0.9", true}, {"1.0.10", false}, {"1.1.0", false}} {
			root, b := writeBundle(t, bundleConfig(t)+block)
			in := enterprisebundle.ComposeInput{
				Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
				Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
				MinProductVersion: tc.min, ProductVersion: "1.0.10", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
			}
			_, _, err := enterprisebundle.Compose(context.Background(), in)
			if tc.refuse {
				if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(errString(err), "observability.") || !strings.Contains(errString(err), "1.0.10") {
					t.Errorf("%s, min %q: got %v, want config_invalid naming the observability key and 1.0.10", name, tc.min, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s, min %q: %v", name, tc.min, err)
			}
		}
	}
}

// A bundle that sets only 1.0.9 observability keys needs no 1.0.10 floor.
func TestComposeNeedsNoTokenomicsFloorForEarlierObservability(t *testing.T) {
	root, b := writeBundle(t, bundleConfig(t)+"observability:\n  local:\n    enabled: true\n")
	in := enterprisebundle.ComposeInput{
		Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
		Platforms: []string{enterprisebundle.PlatformLinux}, CreatedAt: signedAt, CreatedBy: "operator:alice",
		ProductVersion: "1.0.9", HostPlatform: enterprisebundle.PlatformLinux, Digester: digester,
	}
	if _, _, err := enterprisebundle.Compose(context.Background(), in); err != nil && strings.Contains(errString(err), "tokenomics") {
		t.Fatalf("an observability block without tokenomics was refused for the tokenomics floor: %v", err)
	}
}
