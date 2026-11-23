// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
)

const (
	SkillManifestReceiptPath   = "/api/v1/inspect/defense_claw/skill-manifest-receipts"
	MaxSkillManifestParts      = 128
	maxManifestReceiptResponse = 32 << 10
)

var (
	ErrReceiptUnavailable = errors.New("skill manifest receipt unavailable")
	ErrReceiptUnsupported = errors.New("skill manifest receipt unsupported")
	ErrReceiptInvalid     = errors.New("skill manifest receipt invalid")
)

// ManifestPartReceipt describes durable metadata only, never manifest content.
type ManifestPartReceipt struct {
	Part   int    `json:"part"`
	SHA256 string `json:"sha256"`
}

type ManifestReceipt struct {
	Version      int                   `json:"version"`
	Nonce        string                `json:"nonce"`
	Scope        string                `json:"scope"`
	Revision     string                `json:"revision"`
	ManifestHash string                `json:"manifest_hash"`
	State        string                `json:"state"`
	PartsTotal   int                   `json:"parts_total"`
	Parts        []ManifestPartReceipt `json:"parts"`
	MissingParts []int                 `json:"missing_parts"`
}

// ManifestReceiptReader is queried only by enabled managed full scans.
type ManifestReceiptReader interface {
	ReadManifestReceipt(context.Context, string, int) (ManifestReceipt, error)
}

// ManifestReceiptClient shares the managed ingest origin and credential provider.
// Construction creates no worker, request or credential resolution.
type ManifestReceiptClient struct{ adapter *Adapter }

func NewManifestReceiptClient(ctx context.Context, ingestEndpoint string, resolver ProviderResolver, network push.NetworkOptions, warnings push.WarningObserver) (*ManifestReceiptClient, error) {
	endpoint, ok := validEndpoint(ingestEndpoint)
	if !ok || resolver == nil || ctx == nil {
		return nil, ErrReceiptUnavailable
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, ErrReceiptUnavailable
	}
	parsed.Path = SkillManifestReceiptPath
	target, client, err := prepareAuthenticatedTransport(ctx, "managed-skill-manifest-receipt", parsed.String(), network, warnings)
	if err != nil || client == nil {
		return nil, ErrReceiptUnavailable
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ManifestReceiptClient{adapter: &Adapter{endpoint: target, client: client, resolver: resolver, available: true, timeout: defaultTimeout}}, nil
}

func ValidManifestSHA256(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:" && validManagedContentHash(value[7:])
}

func (client *ManifestReceiptClient) ReadManifestReceipt(ctx context.Context, hash string, expectedParts int) (ManifestReceipt, error) {
	if client == nil || client.adapter == nil || ctx == nil || !ValidManifestSHA256(hash) || expectedParts < 0 || expectedParts > MaxSkillManifestParts {
		return ManifestReceipt{}, ErrReceiptInvalid
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return ManifestReceipt{}, ErrReceiptUnavailable
	}
	nonce := hex.EncodeToString(nonceBytes)
	requestBody, err := json.Marshal(struct {
		Version       int    `json:"version"`
		Nonce         string `json:"nonce"`
		ManifestHash  string `json:"manifest_hash"`
		ExpectedParts int    `json:"expected_parts,omitempty"`
	}{1, nonce, hash, expectedParts})
	if err != nil || len(requestBody) > 4<<10 {
		return ManifestReceipt{}, ErrReceiptInvalid
	}
	deadline, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	provider, err := resolveProvider(deadline, client.adapter.resolver)
	if err != nil || provider == nil {
		return ManifestReceipt{}, ErrReceiptUnavailable
	}
	token, err := providerToken(deadline, provider)
	if err != nil || !validToken(token) {
		return ManifestReceipt{}, ErrReceiptUnavailable
	}
	for attempt := 0; attempt < 2; attempt++ {
		receipt, status, err := client.postReceipt(deadline, requestBody, token, hash, nonce)
		if status != http.StatusUnauthorized || attempt != 0 {
			return receipt, err
		}
		fresh, outcome := client.adapter.remint(deadline, provider, token)
		if outcome != "" {
			return ManifestReceipt{}, ErrReceiptUnavailable
		}
		token = fresh
	}
	return ManifestReceipt{}, ErrReceiptUnavailable
}

func (client *ManifestReceiptClient) postReceipt(ctx context.Context, body []byte, token, hash, nonce string) (ManifestReceipt, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.adapter.endpoint, bytes.NewReader(body))
	if err != nil {
		return ManifestReceipt{}, 0, ErrReceiptUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.adapter.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ManifestReceipt{}, 0, ErrReceiptUnavailable
	}
	if response == nil || response.Body == nil {
		return ManifestReceipt{}, 0, ErrReceiptUnavailable
	}
	defer response.Body.Close()
	status := response.StatusCode
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
		return ManifestReceipt{}, status, ErrReceiptUnsupported
	}
	if status != http.StatusOK {
		return ManifestReceipt{}, status, ErrReceiptUnavailable
	}
	kind, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		return ManifestReceipt{}, status, ErrReceiptInvalid
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxManifestReceiptResponse+1))
	if err != nil || len(data) > maxManifestReceiptResponse {
		return ManifestReceipt{}, status, ErrReceiptInvalid
	}
	if _, err = observability.ParseValue(data); err != nil || !exactReceiptFields(data) {
		return ManifestReceipt{}, status, ErrReceiptInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt ManifestReceipt
	if err = decoder.Decode(&receipt); err != nil {
		return ManifestReceipt{}, status, ErrReceiptInvalid
	}
	if ValidateManifestReceipt(receipt, hash, nonce) != nil {
		return ManifestReceipt{}, status, ErrReceiptInvalid
	}
	return receipt, status, nil
}

// ValidateManifestReceipt rejects malformed snapshots before they enter state.
// The nonce binds a fresh authenticated response, not a cached/unioned index set.
func ValidateManifestReceipt(receipt ManifestReceipt, hash, nonce string) error {
	if receipt.Version != 1 || receipt.Nonce != nonce || len(nonce) != 32 || !validManagedContentHash(nonce+nonce) || receipt.ManifestHash != hash || !ValidManifestSHA256(hash) || !ValidManifestSHA256(receipt.Scope) || !ValidManifestSHA256(receipt.Revision) || receipt.Parts == nil || receipt.MissingParts == nil || len(receipt.Parts) > MaxSkillManifestParts || len(receipt.MissingParts) > MaxSkillManifestParts || receipt.PartsTotal < 0 || receipt.PartsTotal > MaxSkillManifestParts {
		return ErrReceiptInvalid
	}
	if receipt.State == "conflict" || receipt.State == "not_seen" {
		if receipt.PartsTotal != 0 || len(receipt.Parts) != 0 || len(receipt.MissingParts) != 0 {
			return ErrReceiptInvalid
		}
		return nil
	}
	if receipt.State != "complete" && receipt.State != "incomplete" || receipt.PartsTotal == 0 {
		return ErrReceiptInvalid
	}
	present := make(map[int]bool, len(receipt.Parts))
	last := 0
	for _, part := range receipt.Parts {
		if part.Part <= last || part.Part > receipt.PartsTotal || !ValidManifestSHA256(part.SHA256) {
			return ErrReceiptInvalid
		}
		present[part.Part] = true
		last = part.Part
	}
	missing := make([]int, 0, receipt.PartsTotal)
	for part := 1; part <= receipt.PartsTotal; part++ {
		if !present[part] {
			missing = append(missing, part)
		}
	}
	if len(missing) != len(receipt.MissingParts) {
		return ErrReceiptInvalid
	}
	for i, part := range missing {
		if receipt.MissingParts[i] != part {
			return ErrReceiptInvalid
		}
	}
	if receipt.State == "complete" && len(missing) != 0 || receipt.State == "incomplete" && len(missing) == 0 {
		return ErrReceiptInvalid
	}
	return nil
}

// encoding/json matches struct tags case-insensitively; the v1 wire grammar
// deliberately accepts only its exact named fields, including nested metadata.
func exactReceiptFields(data []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || len(object) != 9 {
		return false
	}
	for name := range object {
		switch name {
		case "version", "nonce", "scope", "revision", "manifest_hash", "state", "parts_total", "parts", "missing_parts":
		default:
			return false
		}
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(object["parts"], &parts) != nil {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 || part["part"] == nil || part["sha256"] == nil {
			return false
		}
	}
	return true
}
