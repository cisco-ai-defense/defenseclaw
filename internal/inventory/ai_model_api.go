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

package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// These limits are intentionally independent from the file crawler's
	// limits. Model APIs are controlled by another local process and must not
	// be able to turn a discovery pass into an unbounded allocation or a long
	// sequence of network waits.
	maxLocalModelAPIResponseBytes      int64 = 1 << 20 // 1 MiB after decompression
	maxLocalModelAPIItems                    = 256
	maxLocalModelAPIDecodedItems             = 1024
	maxLocalModelAPIEndpoints                = 24
	maxLocalModelIDBytes                     = 512
	maxLocalModelFormatBytes                 = 64
	maxLocalModelProviderBytes               = 96
	maxLocalModelFieldBytes                  = 128
	maxLocalModelModalityBytes               = 64
	maxLocalModelEvidenceMetadataBytes       = 1024
	maxLemonadeConfigBytes             int64 = 64 << 10

	localModelAPIRequestTimeout = 650 * time.Millisecond
	localModelAPITotalTimeout   = 3 * time.Second
)

var errLocalModelAPIResponseTooLarge = errors.New("local model metadata response exceeds size limit")

type localModelProviderKind uint8

const (
	localModelProviderOpenAI localModelProviderKind = iota
	localModelProviderOllama
	localModelProviderLemonade
)

type localModelEndpointKind uint8

const (
	localModelEndpointOpenAIModels localModelEndpointKind = iota
	localModelEndpointOllamaTags
	localModelEndpointOllamaPS
	localModelEndpointLemonadeHealth
)

type localModelAPIProbe struct {
	signature   AISignature
	providerKey string
	provider    localModelProviderKind
	kind        localModelEndpointKind
	endpoint    string
	origin      string
}

type localModelSourceMetadata struct {
	Checkpoint   string `json:"checkpoint"`
	OwnedBy      string `json:"owned_by"`
	Digest       string `json:"digest"`
	ModifiedAt   string `json:"modified_at"`
	RuntimeState string `json:"runtime_state"`
	SizeVRAM     int64  `json:"size_vram"`
}

type localModelObservation struct {
	model        LocalModelInfo
	pid          int
	lastActiveAt *time.Time
	source       localModelSourceMetadata
	cursorAfter  int
}

type localModelSignalCandidate struct {
	signal      AISignal
	cursorAfter int
}

type localModelAPIPageState struct {
	cursorKey   string
	priorCursor int
	nextCursor  int
	resumed     bool
}

// localModelAPIOutcome records coverage separately from observations. A
// provider can validly return an empty list (conclusive absence), while a
// timeout, auth failure, malformed response, or detector cap leaves prior
// inventory indeterminate. Keys include a hashed loopback origin so one local
// server cannot drive lifecycle decisions for another instance.
type localModelAPIOutcome struct {
	conclusive map[string]bool
	attempted  map[string]bool
	deferred   map[string]bool
}

// localEndpointsForSignature returns the catalog's endpoints plus Lemonade's
// documented liveness, model, and health endpoints. Lemonade can move off its default
// port via LEMONADE_PORT or config.json, so relying on the embedded catalog's
// 13305 URL alone would miss a supported configuration. Only loopback hosts
// are retained later by buildLocalModelAPIProbes.
func localEndpointsForSignature(sig AISignature) []string {
	endpoints := append([]string(nil), sig.LocalEndpoints...)
	if localModelProviderForSignature(sig) != localModelProviderLemonade {
		return endpoints
	}
	hasCatalogEndpoint := false
	for _, endpoint := range sig.LocalEndpoints {
		if strings.TrimSpace(endpoint) != "" {
			hasCatalogEndpoint = true
			break
		}
	}

	// A pack can point Lemonade at a test/custom port. Derive the companion
	// health/models route from every catalog origin before adding known config
	// locations.
	for _, endpoint := range append([]string(nil), endpoints...) {
		if u, err := url.Parse(strings.TrimSpace(endpoint)); err == nil && u.Scheme != "" && u.Host != "" {
			endpoints = appendLemonadeMetadataEndpoints(endpoints, u.Scheme, u.Hostname(), portFromURL(u))
		}
	}

	if !hasCatalogEndpoint {
		// The service default is localhost:13305. Use an explicit loopback
		// address so discovery never depends on local DNS or proxy settings.
		// Production's catalog already declares this endpoint; limiting the
		// fallback to signatures without endpoints keeps custom/test packs from
		// unexpectedly probing an unrelated developer service on 13305.
		endpoints = appendLemonadeMetadataEndpoints(endpoints, "http", "127.0.0.1", 13305)
	}

	envHost := strings.TrimSpace(os.Getenv("LEMONADE_HOST"))
	if envHost == "" {
		envHost = "127.0.0.1"
	}
	if envPort, ok := parseTCPPort(os.Getenv("LEMONADE_PORT")); ok {
		endpoints = appendLemonadeMetadataEndpoints(endpoints, "http", envHost, envPort)
	}

	for _, path := range lemonadeConfigPaths() {
		host, port, ok := readLemonadeEndpointConfig(path)
		if !ok {
			continue
		}
		endpoints = appendLemonadeMetadataEndpoints(endpoints, "http", host, port)
	}

	return uniqueStrings(endpoints)
}

func appendLemonadeMetadataEndpoints(endpoints []string, scheme, host string, port int) []string {
	host, ok := safeLemonadeConnectHost(host)
	if !ok || port < 1 || port > 65535 {
		return endpoints
	}
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	base := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	base.Path = "/live"
	endpoints = append(endpoints, base.String())
	base.Path = "/v1/health"
	endpoints = append(endpoints, base.String())
	base.Path = "/v1/models"
	endpoints = append(endpoints, base.String())
	base.Path = "/api/v1/health"
	endpoints = append(endpoints, base.String())
	base.Path = "/api/v1/models"
	return append(endpoints, base.String())
}

func safeLemonadeConnectHost(host string) (string, bool) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1", true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	if ip.IsUnspecified() {
		return "127.0.0.1", true
	}
	if !ip.IsLoopback() {
		return "", false
	}
	return ip.String(), true
}

func portFromURL(u *url.URL) int {
	if u == nil {
		return 0
	}
	if port, ok := parseTCPPort(u.Port()); ok {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func parseTCPPort(value string) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	return port, err == nil && port > 0 && port <= 65535
}

func lemonadeConfigPaths() []string {
	var paths []string
	if cacheDir := strings.TrimSpace(os.Getenv("LEMONADE_CACHE_DIR")); cacheDir != "" {
		// An explicit cache directory is authoritative. Besides matching
		// lemond's documented override semantics, this prevents a caller/test
		// with an isolated cache from also reading machine-global config.
		return []string{filepath.Join(cacheDir, "config.json")}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// Standalone lemond and the Windows installer both use this location.
		paths = append(paths, filepath.Join(home, ".cache", "lemonade", "config.json"))
	}
	switch runtime.GOOS {
	case "darwin":
		paths = append(paths, "/Library/Application Support/lemonade/.cache/config.json")
	case "linux":
		paths = append(paths,
			"/var/lib/lemonade/.cache/lemonade/config.json",
			"/opt/var/lib/lemonade/.cache/lemonade/config.json",
		)
	}
	return uniqueStrings(paths)
}

func readLemonadeEndpointConfig(path string) (string, int, bool) {
	raw, err := readBoundedRegularFile(path, maxLemonadeConfigBytes)
	if err != nil {
		return "", 0, false
	}
	var cfg struct {
		Host string      `json:"host"`
		Port json.Number `json:"port"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return "", 0, false
	}
	port, ok := parseTCPPort(cfg.Port.String())
	if !ok {
		return "", 0, false
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	if _, ok := safeLemonadeConnectHost(host); !ok {
		return "", 0, false
	}
	return host, port, true
}

// detectLocalAPIModels reads only vetted, metadata-only endpoints on loopback.
// It intentionally does not use a generic OpenAI client: that would make it
// too easy for a future refactor to call an inference route or follow a
// redirect. The returned integer remains zero because scanSignals interprets
// it as a files_scanned count, and HTTP probes are not filesystem entries.
func (s *ContinuousDiscoveryService) detectLocalAPIModels(ctx context.Context) ([]AISignal, int, error) {
	out, files, _, err := s.detectLocalAPIModelsWithOutcome(ctx)
	return out, files, err
}

func (s *ContinuousDiscoveryService) detectLocalAPIModelsWithOutcome(ctx context.Context) ([]AISignal, int, localModelAPIOutcome, error) {
	outcome := localModelAPIOutcome{
		conclusive: make(map[string]bool),
		attempted:  make(map[string]bool),
		deferred:   make(map[string]bool),
	}
	if s == nil {
		return nil, 0, outcome, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, outcome, err
	}

	probes := buildLocalModelAPIProbes(s.catalog)
	if len(probes) == 0 {
		return nil, 0, outcome, nil
	}
	probes = s.rotateLocalModelAPIProbes(probes)
	discoveryCtx, cancel := context.WithTimeout(ctx, localModelAPITotalTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: localModelAPIRequestTimeout}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 32 << 10,
		ResponseHeaderTimeout:  localModelAPIRequestTimeout,
		TLSHandshakeTimeout:    localModelAPIRequestTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   localModelAPIRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	trustedLemonadeOrigins := trustedLemonadeCredentialOrigins()

	var (
		out               []AISignal
		probeErrs         []error
		seenFingerprints  = make(map[string]struct{})
		candidateGroups   = make(map[string][]localModelSignalCandidate)
		candidateOrder    []string
		pageStates        = make(map[string]localModelAPIPageState)
		lemonadeOrigins   = make(map[string]bool)
		lemonadeLiveOK    = make(map[string]bool)
		lemonadeLiveSeen  = make(map[string]bool)
		completedGroups   = make(map[string]bool)
		deferredFrom      = -1
		requestsAttempted = 0
	)
	markDeferredFrom := func(index int) {
		if index < 0 {
			index = 0
		}
		if index > len(probes) {
			index = len(probes)
		}
		for _, remainingProbe := range probes[index:] {
			key := localModelAPICoverageKey(remainingProbe)
			if !outcome.conclusive[key] {
				outcome.deferred[key] = true
			}
		}
	}

	for i, probe := range probes {
		if err := discoveryCtx.Err(); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				markDeferredFrom(i)
				return out, 0, outcome, ctxErr
			}
			deferredFrom = i
			break // internal time budget exhausted; absence is not an error
		}
		coverageKey := localModelAPICoverageKey(probe)
		groupKey := localModelAPIProbeGroupKey(probe)
		if completedGroups[groupKey] {
			continue
		}
		// Lemonade exposes Ollama/OpenAI compatibility routes. Once its native
		// health or model response identifies an origin, suppress compatibility
		// probes for that same listener so one model is not attributed twice.
		if probe.provider != localModelProviderLemonade && lemonadeOrigins[probe.origin] {
			outcome.conclusive[coverageKey] = true
			continue
		}
		if requestsAttempted >= maxLocalModelAPIEndpoints {
			deferredFrom = i
			break
		}
		requestsAttempted++
		outcome.attempted[coverageKey] = true

		req, err := http.NewRequestWithContext(discoveryCtx, http.MethodGet, probe.endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Connection", "close")
		req.Header.Set("User-Agent", "defenseclaw-discovery/1.0 (+https://defenseclaw.com/discovery)")
		if probe.provider == localModelProviderLemonade {
			if token := lemonadeBearerToken(); token != "" {
				if trustedLemonadeOrigins[probe.origin] && !lemonadeLiveSeen[probe.origin] {
					lemonadeLiveSeen[probe.origin] = true
					lemonadeLiveOK[probe.origin] = verifyLemonadeLive(discoveryCtx, client, probe.origin)
				}
				if trustedLemonadeOrigins[probe.origin] && lemonadeLiveOK[probe.origin] {
					req.Header.Set("Authorization", "Bearer "+token)
				}
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				markDeferredFrom(i)
				return out, 0, outcome, ctxErr
			}
			// Connection refusal/timeouts are the normal "server absent" case.
			continue
		}
		body, readErr := readLocalModelMetadataBody(resp)
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if readErr != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s model metadata: %w", probe.providerKey, readErr))
			continue
		}

		cursorKey := localModelAPIItemCursorKey(probe)
		priorCursor := s.localModelAPIItemCursor(cursorKey)
		observations, identifiesLemonade, _, nextCursor, resumed, parseErr := parseLocalModelAPIResponse(
			probe, body, maxLocalModelAPIItems, priorCursor,
		)
		if parseErr != nil && priorCursor > 0 {
			// The provider may reorder or replace its model list between
			// passes. A byte cursor that no longer lands on a compatible item
			// must not wedge discovery forever; retry once from the beginning.
			priorCursor = 0
			observations, identifiesLemonade, _, nextCursor, resumed, parseErr = parseLocalModelAPIResponse(
				probe, body, maxLocalModelAPIItems, 0,
			)
		}
		if parseErr != nil {
			probeErrs = append(probeErrs, fmt.Errorf("%s model metadata: %w", probe.providerKey, parseErr))
			continue
		}
		if probe.provider == localModelProviderLemonade {
			if identifiesLemonade {
				lemonadeOrigins[probe.origin] = true
			}
			// Do not label an arbitrary OpenAI service on a configured/default
			// Lemonade port as Lemonade unless native metadata identified it.
			if !lemonadeOrigins[probe.origin] {
				continue
			}
		}
		completedGroups[groupKey] = true
		pageStates[coverageKey] = localModelAPIPageState{
			cursorKey: cursorKey, priorCursor: priorCursor,
			nextCursor: nextCursor, resumed: resumed,
		}

		for _, observation := range observations {
			detector := "model_api"
			if observation.model.Status == "loaded" {
				detector = "model_runtime"
			}
			signal := signalForLocalAPIModel(probe, detector, observation)
			if _, exists := seenFingerprints[signal.Fingerprint]; exists {
				continue
			}
			seenFingerprints[signal.Fingerprint] = struct{}{}
			if len(candidateGroups[coverageKey]) == 0 {
				candidateOrder = append(candidateOrder, coverageKey)
			}
			candidateGroups[coverageKey] = append(candidateGroups[coverageKey], localModelSignalCandidate{
				signal: signal, cursorAfter: observation.cursorAfter,
			})
		}
	}
	if deferredFrom >= 0 {
		markDeferredFrom(deferredFrom)
	}

	// Allocate the global output cap only across sources that actually
	// responded with local models. Pre-dividing the cap across every configured
	// endpoint wastes most of the inventory budget when the other engines are
	// absent; round-robin flattening lets a lone engine use all 256 slots while
	// ensuring multiple live engines cannot starve each other.
	emittedByGroup := make(map[string]int, len(candidateOrder))
	for len(out) < maxLocalModelAPIItems {
		progressed := false
		for _, key := range candidateOrder {
			index := emittedByGroup[key]
			if index >= len(candidateGroups[key]) {
				continue
			}
			out = append(out, candidateGroups[key][index].signal)
			emittedByGroup[key] = index + 1
			progressed = true
			if len(out) >= maxLocalModelAPIItems {
				break
			}
		}
		if !progressed {
			break
		}
	}
	for key, page := range pageStates {
		emitted := emittedByGroup[key]
		candidates := candidateGroups[key]
		nextCursor := page.nextCursor
		fullyEmitted := emitted >= len(candidates)
		if !fullyEmitted {
			if emitted > 0 {
				nextCursor = candidates[emitted-1].cursorAfter
			} else {
				nextCursor = page.priorCursor
			}
		}
		s.setLocalModelAPIItemCursor(page.cursorKey, nextCursor)
		delete(outcome.conclusive, key)
		if nextCursor == 0 && !page.resumed && fullyEmitted {
			outcome.conclusive[key] = true
			delete(outcome.deferred, key)
		} else {
			outcome.deferred[key] = true
		}
	}

	sortAISignals(out)
	// The scanSignals caller interprets this detector's integer as
	// files_scanned. Network probes are not files, so keep that counter at zero.
	return out, 0, outcome, errors.Join(probeErrs...)
}

func (s *ContinuousDiscoveryService) rotateLocalModelAPIProbes(probes []localModelAPIProbe) []localModelAPIProbe {
	if len(probes) <= 1 {
		return probes
	}
	if len(probes) > maxLocalModelAPIEndpoints {
		advance := uint64(maxLocalModelAPIEndpoints)
		start := int((s.modelAPIProbeCursor.Add(advance) - advance) % uint64(len(probes)))
		rotated := make([]localModelAPIProbe, 0, len(probes))
		rotated = append(rotated, probes[start:]...)
		rotated = append(rotated, probes[:start]...)
		return rotated
	}

	// The wall-clock budget can be exhausted even below the request-count cap
	// when one loopback listener accepts connections but stalls metadata reads.
	// Rotate complete origins between passes while preserving the probe order
	// within each origin (notably Lemonade health before compatibility routes).
	originOrder := make([]string, 0)
	byOrigin := make(map[string][]localModelAPIProbe)
	for _, probe := range probes {
		if _, exists := byOrigin[probe.origin]; !exists {
			originOrder = append(originOrder, probe.origin)
		}
		byOrigin[probe.origin] = append(byOrigin[probe.origin], probe)
	}
	if len(originOrder) <= 1 {
		return probes
	}
	start := int((s.modelAPIProbeCursor.Add(1) - 1) % uint64(len(originOrder)))
	rotated := make([]localModelAPIProbe, 0, len(probes))
	for offset := 0; offset < len(originOrder); offset++ {
		origin := originOrder[(start+offset)%len(originOrder)]
		rotated = append(rotated, byOrigin[origin]...)
	}
	return rotated
}

func localModelAPIDetectorForProbe(probe localModelAPIProbe) string {
	switch probe.kind {
	case localModelEndpointOllamaPS, localModelEndpointLemonadeHealth:
		return "model_runtime"
	default:
		return "model_api"
	}
}

func localModelAPIOutcomeKey(providerKey, sourceHash, detector string) string {
	return providerKey + "\x00" + sourceHash + "\x00" + detector
}

func localModelAPICoverageKey(probe localModelAPIProbe) string {
	return localModelAPIOutcomeKey(probe.providerKey, hashValue(probe.origin), localModelAPIDetectorForProbe(probe))
}

func localModelAPIItemCursorKey(probe localModelAPIProbe) string {
	return localModelAPICoverageKey(probe) + "\x00" + probe.endpoint
}

func (s *ContinuousDiscoveryService) localModelAPIItemCursor(key string) int {
	if s == nil || key == "" {
		return 0
	}
	s.modelAPIItemCursorMu.Lock()
	defer s.modelAPIItemCursorMu.Unlock()
	return s.modelAPIItemCursors[key]
}

func (s *ContinuousDiscoveryService) setLocalModelAPIItemCursor(key string, cursor int) {
	if s == nil || key == "" {
		return
	}
	s.modelAPIItemCursorMu.Lock()
	defer s.modelAPIItemCursorMu.Unlock()
	if cursor <= 0 {
		delete(s.modelAPIItemCursors, key)
		return
	}
	if s.modelAPIItemCursors == nil {
		s.modelAPIItemCursors = make(map[string]int)
	}
	s.modelAPIItemCursors[key] = cursor
}

func localModelAPIProbeGroupKey(probe localModelAPIProbe) string {
	return probe.providerKey + "\x00" + probe.origin + "\x00" + strconv.Itoa(int(probe.kind))
}

func buildLocalModelAPIProbes(catalog []AISignature) []localModelAPIProbe {
	var probes []localModelAPIProbe
	seen := make(map[string]struct{})
	for _, sig := range catalog {
		provider := localModelProviderForSignature(sig)
		providerKey := normalizeAIID(sig.ID)
		if providerKey == "" {
			providerKey = normalizeAIID(sig.Name)
		}
		for _, endpoint := range localEndpointsForSignature(sig) {
			probe, ok := makeLocalModelAPIProbe(sig, providerKey, provider, endpoint)
			if !ok {
				continue
			}
			// Keep distinct vetted paths on the same origin. In particular,
			// /v1/* and /api/v1/* are compatibility alternatives across
			// Lemonade releases; output-level fingerprinting deduplicates a
			// model when both routes succeed.
			key := providerKey + "|" + probe.endpoint
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				probes = append(probes, probe)
			}

			if provider == localModelProviderOllama && probe.kind == localModelEndpointOllamaTags {
				u, _ := url.Parse(probe.endpoint)
				u.Path = "/api/ps"
				psProbe, psOK := makeLocalModelAPIProbe(sig, providerKey, provider, u.String())
				psKey := providerKey + "|" + psProbe.endpoint
				if psOK {
					if _, exists := seen[psKey]; !exists {
						seen[psKey] = struct{}{}
						probes = append(probes, psProbe)
					}
				}
			}
		}
	}

	sort.Slice(probes, func(i, j int) bool {
		pi, pj := localModelProbePriority(probes[i]), localModelProbePriority(probes[j])
		if pi != pj {
			return pi < pj
		}
		ci, cj := canonicalMetadataPathPriority(probes[i].endpoint), canonicalMetadataPathPriority(probes[j].endpoint)
		if ci != cj {
			return ci < cj
		}
		return probes[i].providerKey+"|"+probes[i].endpoint < probes[j].providerKey+"|"+probes[j].endpoint
	})
	return probes
}

func makeLocalModelAPIProbe(sig AISignature, providerKey string, provider localModelProviderKind, endpoint string) (localModelAPIProbe, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || !isSafeLoopbackEndpoint(endpoint) {
		return localModelAPIProbe{}, false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return localModelAPIProbe{}, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.RawPath = ""
	u.ForceQuery = false

	var kind localModelEndpointKind
	switch u.Path {
	case "/v1/models", "/api/v1/models":
		kind = localModelEndpointOpenAIModels
	case "/v1/health", "/api/v1/health":
		if provider != localModelProviderLemonade {
			return localModelAPIProbe{}, false
		}
		kind = localModelEndpointLemonadeHealth
	case "/api/tags":
		if provider != localModelProviderOllama {
			return localModelAPIProbe{}, false
		}
		kind = localModelEndpointOllamaTags
	case "/api/ps":
		if provider != localModelProviderOllama {
			return localModelAPIProbe{}, false
		}
		kind = localModelEndpointOllamaPS
	default:
		return localModelAPIProbe{}, false
	}

	return localModelAPIProbe{
		signature:   sig,
		providerKey: providerKey,
		provider:    provider,
		kind:        kind,
		endpoint:    u.String(),
		origin:      canonicalLoopbackOrigin(u),
	}, true
}

func localModelProviderForSignature(sig AISignature) localModelProviderKind {
	id := normalizeAIID(sig.ID)
	name := normalizeAIID(sig.Name)
	if id == "lemonade" || id == "lemonade-server" || name == "lemonade" || name == "lemonade-server" {
		return localModelProviderLemonade
	}
	if id == "ollama" || name == "ollama" {
		return localModelProviderOllama
	}
	return localModelProviderOpenAI
}

func localModelProbePriority(probe localModelAPIProbe) int {
	switch {
	case probe.provider == localModelProviderLemonade && probe.kind == localModelEndpointLemonadeHealth:
		return 0
	case probe.provider == localModelProviderLemonade:
		return 1
	case probe.kind == localModelEndpointOllamaPS:
		return 2
	default:
		return 3
	}
}

func canonicalMetadataPathPriority(endpoint string) int {
	u, err := url.Parse(endpoint)
	if err == nil && (u.Path == "/v1/models" || u.Path == "/v1/health") {
		return 0
	}
	return 1
}

func canonicalLoopbackOrigin(u *url.URL) string {
	port := portFromURL(u)
	host := strings.Trim(strings.ToLower(u.Hostname()), "[]")
	if host == "localhost" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func lemonadeBearerToken() string {
	// Model and health routes are regular Lemonade APIs. Never expose the
	// elevated admin credential to read-only discovery requests; operators who
	// protect regular endpoints should provide the least-privileged API key.
	return strings.TrimSpace(os.Getenv("LEMONADE_API_KEY"))
}

func trustedLemonadeCredentialOrigins() map[string]bool {
	out := make(map[string]bool)
	add := func(host string, port int) {
		host, ok := safeLemonadeConnectHost(host)
		if !ok || port < 1 || port > 65535 {
			return
		}
		u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port))}
		out[canonicalLoopbackOrigin(u)] = true
	}
	if port, ok := parseTCPPort(os.Getenv("LEMONADE_PORT")); ok {
		host := strings.TrimSpace(os.Getenv("LEMONADE_HOST"))
		if host == "" {
			host = "127.0.0.1"
		}
		add(host, port)
	}
	for _, path := range lemonadeConfigPaths() {
		if host, port, ok := readLemonadeEndpointConfig(path); ok {
			add(host, port)
		}
	}
	return out
}

func verifyLemonadeLive(ctx context.Context, client *http.Client, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/live", "", "", ""
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
		if err != nil {
			return false
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Connection", "close")
		req.Header.Set("User-Agent", "defenseclaw-discovery/1.0 (+https://defenseclaw.com/discovery)")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
		if method == http.MethodHead {
			continue
		}
		return false
	}
	return false
}

func readLocalModelMetadataBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, io.ErrUnexpectedEOF
	}
	if resp.ContentLength > maxLocalModelAPIResponseBytes {
		return nil, errLocalModelAPIResponseTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxLocalModelAPIResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxLocalModelAPIResponseBytes {
		return nil, errLocalModelAPIResponseTooLarge
	}
	return raw, nil
}

func parseLocalModelAPIResponse(
	probe localModelAPIProbe, body []byte, limit, cursor int,
) ([]localModelObservation, bool, bool, int, bool, error) {
	switch probe.kind {
	case localModelEndpointLemonadeHealth:
		observations, identified, truncated, next, resumed, err := parseLemonadeHealth(body, limit, cursor)
		return observations, identified, truncated, next, resumed, err
	case localModelEndpointOllamaTags:
		observations, truncated, next, resumed, err := parseOllamaModels(body, "installed", limit, cursor)
		return observations, false, truncated, next, resumed, err
	case localModelEndpointOllamaPS:
		observations, truncated, next, resumed, err := parseOllamaModels(body, "loaded", limit, cursor)
		return observations, false, truncated, next, resumed, err
	default:
		observations, identifiesLemonade, truncated, next, resumed, err := parseOpenAIModels(
			body, probe.provider == localModelProviderLemonade, limit, cursor,
		)
		return observations, identifiesLemonade, truncated, next, resumed, err
	}
}

type openAIModelMetadata struct {
	ID         string      `json:"id"`
	OwnedBy    string      `json:"owned_by"`
	Checkpoint string      `json:"checkpoint"`
	Recipe     string      `json:"recipe"`
	Format     string      `json:"format"`
	Modality   string      `json:"modality"`
	Size       json.Number `json:"size"`
	Downloaded *bool       `json:"downloaded"`
}

func parseOpenAIModels(body []byte, lemonade bool, limit, cursor int) ([]localModelObservation, bool, bool, int, bool, error) {
	var envelope struct {
		Object string          `json:"object"`
		Data   json.RawMessage `json:"data"`
	}
	if err := decodeBoundedJSON(body, &envelope); err != nil {
		return nil, false, false, 0, false, err
	}
	if len(envelope.Data) == 0 {
		return nil, false, false, 0, false, errors.New("model list is missing data array")
	}

	limit = clampLocalModelLimit(limit)
	page, err := newBoundedJSONArrayPageDecoder(envelope.Data, cursor)
	if err != nil {
		return nil, false, false, 0, false, err
	}
	out := make([]localModelObservation, 0, limit)
	identifiesLemonade := false
	decodedItems := 0
	for page.dec.More() {
		if decodedItems >= maxLocalModelAPIDecodedItems {
			return out, identifiesLemonade, true, page.cursor(), page.resumed, nil
		}
		var item openAIModelMetadata
		if err := page.dec.Decode(&item); err != nil {
			return nil, false, false, 0, page.resumed, err
		}
		decodedItems++
		if strings.EqualFold(strings.TrimSpace(item.OwnedBy), "lemonade") {
			identifiesLemonade = true
		}
		if item.Downloaded != nil && !*item.Downloaded {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Recipe), "cloud") {
			continue
		}
		id, ok := safeLocalModelID(item.ID)
		if !ok {
			continue
		}
		format := boundedLocalModelField(item.Format, maxLocalModelFormatBytes)
		if format == "" {
			format = inferLocalModelFormat(item.Recipe, item.Checkpoint)
		}
		observation := localModelObservation{
			model: LocalModelInfo{
				ID:       id,
				Status:   "installed",
				Format:   format,
				Recipe:   boundedLocalModelField(item.Recipe, maxLocalModelFieldBytes),
				Modality: boundedLocalModelField(item.Modality, maxLocalModelModalityBytes),
			},
			source: localModelSourceMetadata{
				Checkpoint: boundedLocalEvidenceMetadata(item.Checkpoint),
				OwnedBy:    boundedLocalEvidenceMetadata(item.OwnedBy),
			},
		}
		observation.cursorAfter = page.cursor()
		if lemonade {
			observation.model.SizeBytes = decimalGBToBytes(item.Size)
		}
		out = append(out, observation)
		if len(out) >= limit {
			if page.dec.More() {
				return out, identifiesLemonade, true, page.cursor(), page.resumed, nil
			}
			if err := page.finish(); err != nil {
				return nil, false, false, 0, page.resumed, err
			}
			return out, identifiesLemonade, page.resumed, 0, page.resumed, nil
		}
	}
	if err := page.finish(); err != nil {
		return nil, false, false, 0, page.resumed, err
	}
	return out, identifiesLemonade, page.resumed, 0, page.resumed, nil
}

type lemonadeLoadedModel struct {
	ModelName    string      `json:"model_name"`
	Checkpoint   string      `json:"checkpoint"`
	Type         string      `json:"type"`
	Device       string      `json:"device"`
	Recipe       string      `json:"recipe"`
	Status       string      `json:"status"`
	PID          json.Number `json:"pid"`
	LastUse      json.Number `json:"last_use"`
	Pinned       bool        `json:"pinned"`
	Loaded       *bool       `json:"loaded"`
	BackendAlive *bool       `json:"backend_alive"`
}

func parseLemonadeHealth(body []byte, limit, cursor int) ([]localModelObservation, bool, bool, int, bool, error) {
	var envelope struct {
		Status          string          `json:"status"`
		AllModelsLoaded json.RawMessage `json:"all_models_loaded"`
	}
	if err := decodeBoundedJSON(body, &envelope); err != nil {
		return nil, false, false, 0, false, err
	}
	identified := strings.EqualFold(strings.TrimSpace(envelope.Status), "ok") && len(envelope.AllModelsLoaded) > 0
	if !identified {
		return nil, false, false, 0, false, nil
	}

	page, err := newBoundedJSONArrayPageDecoder(envelope.AllModelsLoaded, cursor)
	if err != nil {
		return nil, false, false, 0, false, err
	}
	limit = clampLocalModelLimit(limit)
	out := make([]localModelObservation, 0, limit)
	decodedItems := 0
	for page.dec.More() {
		if decodedItems >= maxLocalModelAPIDecodedItems {
			return out, true, true, page.cursor(), page.resumed, nil
		}
		var item lemonadeLoadedModel
		if err := page.dec.Decode(&item); err != nil {
			return nil, false, false, 0, page.resumed, err
		}
		decodedItems++
		if item.Loaded != nil && !*item.Loaded {
			continue
		}
		if item.BackendAlive != nil && !*item.BackendAlive {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Recipe), "cloud") {
			continue
		}
		id, ok := safeLocalModelID(item.ModelName)
		if !ok {
			continue
		}
		lastActive := parseFlexibleUnixTime(item.LastUse)
		observation := localModelObservation{
			model: LocalModelInfo{
				ID:       id,
				Status:   "loaded",
				Format:   inferLocalModelFormat(item.Recipe, item.Checkpoint),
				Recipe:   boundedLocalModelField(item.Recipe, maxLocalModelFieldBytes),
				Modality: boundedLocalModelField(item.Type, maxLocalModelModalityBytes),
				Device:   boundedLocalModelField(item.Device, maxLocalModelFieldBytes),
				Pinned:   item.Pinned,
			},
			pid:          positiveInt(item.PID),
			lastActiveAt: lastActive,
			source: localModelSourceMetadata{
				Checkpoint:   boundedLocalEvidenceMetadata(item.Checkpoint),
				RuntimeState: boundedLocalEvidenceMetadata(item.Status),
			},
		}
		observation.cursorAfter = page.cursor()
		out = append(out, observation)
		if len(out) >= limit {
			if page.dec.More() {
				return out, true, true, page.cursor(), page.resumed, nil
			}
			if err := page.finish(); err != nil {
				return nil, false, false, 0, page.resumed, err
			}
			return out, true, page.resumed, 0, page.resumed, nil
		}
	}
	if err := page.finish(); err != nil {
		return nil, false, false, 0, page.resumed, err
	}
	return out, true, page.resumed, 0, page.resumed, nil
}

type ollamaModelMetadata struct {
	Name       string      `json:"name"`
	Model      string      `json:"model"`
	ModifiedAt string      `json:"modified_at"`
	ExpiresAt  string      `json:"expires_at"`
	Digest     string      `json:"digest"`
	Size       json.Number `json:"size"`
	SizeVRAM   json.Number `json:"size_vram"`
	Details    struct {
		Format string `json:"format"`
	} `json:"details"`
}

func parseOllamaModels(body []byte, status string, limit, cursor int) ([]localModelObservation, bool, int, bool, error) {
	var envelope struct {
		Models json.RawMessage `json:"models"`
	}
	if err := decodeBoundedJSON(body, &envelope); err != nil {
		return nil, false, 0, false, err
	}
	if len(envelope.Models) == 0 {
		return nil, false, 0, false, errors.New("model list is missing models array")
	}
	page, err := newBoundedJSONArrayPageDecoder(envelope.Models, cursor)
	if err != nil {
		return nil, false, 0, false, err
	}
	limit = clampLocalModelLimit(limit)
	out := make([]localModelObservation, 0, limit)
	decodedItems := 0
	for page.dec.More() {
		if decodedItems >= maxLocalModelAPIDecodedItems {
			return out, true, page.cursor(), page.resumed, nil
		}
		var item ollamaModelMetadata
		if err := page.dec.Decode(&item); err != nil {
			return nil, false, 0, page.resumed, err
		}
		decodedItems++
		id := item.Model
		if strings.TrimSpace(id) == "" {
			id = item.Name
		}
		id, ok := safeLocalModelID(id)
		if !ok {
			continue
		}
		observation := localModelObservation{
			model: LocalModelInfo{
				ID:        id,
				Status:    status,
				Format:    boundedLocalModelField(item.Details.Format, maxLocalModelFormatBytes),
				SizeBytes: positiveInt64(item.Size),
			},
			source: localModelSourceMetadata{
				Digest:     boundedLocalEvidenceMetadata(item.Digest),
				ModifiedAt: boundedLocalEvidenceMetadata(item.ModifiedAt),
				SizeVRAM:   positiveInt64(item.SizeVRAM),
			},
		}
		observation.cursorAfter = page.cursor()
		out = append(out, observation)
		if len(out) >= limit {
			if page.dec.More() {
				return out, true, page.cursor(), page.resumed, nil
			}
			if err := page.finish(); err != nil {
				return nil, false, 0, page.resumed, err
			}
			return out, page.resumed, 0, page.resumed, nil
		}
	}
	if err := page.finish(); err != nil {
		return nil, false, 0, page.resumed, err
	}
	return out, page.resumed, 0, page.resumed, nil
}

type boundedJSONArrayPageDecoder struct {
	dec       *json.Decoder
	base      int
	synthetic bool
	resumed   bool
}

func newBoundedJSONArrayPageDecoder(raw []byte, cursor int) (*boundedJSONArrayPageDecoder, error) {
	pageRaw := raw
	page := &boundedJSONArrayPageDecoder{}
	if cursor > 0 && cursor < len(raw) {
		start := cursor
		for start < len(raw) && isJSONSpace(raw[start]) {
			start++
		}
		if start < len(raw) && raw[start] == ',' {
			start++
			for start < len(raw) && isJSONSpace(raw[start]) {
				start++
			}
		}
		if start < len(raw) && raw[start] != ']' {
			candidate := make([]byte, 1+len(raw)-start)
			candidate[0] = '['
			copy(candidate[1:], raw[start:])
			if json.Valid(candidate) {
				pageRaw = candidate
				page.base = start
				page.synthetic = true
				page.resumed = true
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(pageRaw))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		return nil, errors.New("model list field must be an array")
	}
	page.dec = dec
	return page, nil
}

func (p *boundedJSONArrayPageDecoder) cursor() int {
	if p == nil || p.dec == nil {
		return 0
	}
	offset := int(p.dec.InputOffset())
	if p.synthetic {
		return p.base + offset - 1
	}
	return offset
}

func (p *boundedJSONArrayPageDecoder) finish() error {
	if p == nil {
		return io.ErrUnexpectedEOF
	}
	return finishBoundedJSONArrayDecoder(p.dec)
}

func isJSONSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func finishBoundedJSONArrayDecoder(dec *json.Decoder) error {
	if dec == nil {
		return io.ErrUnexpectedEOF
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != ']' {
		return errors.New("model list array is not terminated")
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value after model list")
		}
		return err
	}
	return nil
}

func decodeBoundedJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func signalForLocalAPIModel(probe localModelAPIProbe, detector string, observation localModelObservation) AISignal {
	sig := probe.signature
	providerKey := probe.providerKey
	model := observation.model
	model.Provider = boundedLocalModelField(providerKey, maxLocalModelProviderBytes)
	sourceHash := hashValue(probe.origin)
	evidencePayload := struct {
		Provider string                   `json:"provider"`
		Detector string                   `json:"detector"`
		Model    LocalModelInfo           `json:"model"`
		PID      int                      `json:"pid"`
		Source   localModelSourceMetadata `json:"source"`
	}{
		Provider: providerKey,
		Detector: detector,
		Model:    model,
		PID:      observation.pid,
		Source:   observation.source,
	}
	raw, _ := json.Marshal(evidencePayload)
	evidence := []AIEvidence{{
		Type:      detector,
		ValueHash: hashValue(string(raw)),
		Quality:   1,
		MatchKind: MatchKindExact,
	}}
	fingerprint := hashValue(strings.Join([]string{
		"local-model",
		providerKey,
		sourceHash,
		model.ID,
		detector,
	}, "|"))

	signal := AISignal{
		Fingerprint:        fingerprint,
		SignatureID:        sig.ID,
		Name:               sig.Name,
		Vendor:             sig.Vendor,
		Product:            sig.Name,
		Category:           SignalLocalModel,
		SupportedConnector: sig.SupportedConnector,
		Confidence:         sig.Confidence,
		Detector:           detector,
		Source:             "sidecar",
		EvidenceTypes:      []string{detector},
		EvidenceHash:       hashEvidence(evidence),
		Evidence:           evidence,
		Model:              &model,
		ModelAPISourceHash: sourceHash,
		LastActiveAt:       observation.lastActiveAt,
	}
	if observation.pid > 0 {
		signal.Runtime = &ProcessRuntime{PID: observation.pid}
	}
	return signal
}

func safeLocalModelID(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLocalModelIDBytes || !utf8.ValidString(value) {
		return "", false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return value, true
}

func boundedLocalModelField(value string, maxBytes int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > maxBytes {
		value = strings.ToValidUTF8(value[:maxBytes], "")
	}
	return value
}

func boundedLocalEvidenceMetadata(value string) string {
	return boundedLocalModelField(value, maxLocalModelEvidenceMetadataBytes)
}

func inferLocalModelFormat(recipe, checkpoint string) string {
	lowerCheckpoint := strings.ToLower(checkpoint)
	for _, format := range []string{"gguf", "safetensors", "onnx", "q4nx", "bin"} {
		if strings.Contains(lowerCheckpoint, "."+format) {
			return format
		}
	}
	switch strings.ToLower(strings.TrimSpace(recipe)) {
	case "llamacpp":
		return "gguf"
	case "ryzenai-llm":
		return "onnx"
	case "flm":
		return "q4nx"
	case "whispercpp":
		return "bin"
	case "sd-cpp":
		return "safetensors"
	default:
		return ""
	}
}

func decimalGBToBytes(value json.Number) int64 {
	if value.String() == "" {
		return 0
	}
	gb, err := strconv.ParseFloat(value.String(), 64)
	if err != nil || gb <= 0 || gb > float64(math.MaxInt64)/1e9 {
		return 0
	}
	return int64(math.Round(gb * 1e9))
}

func positiveInt(value json.Number) int {
	n := positiveInt64(value)
	if n <= 0 || int64(int(n)) != n {
		return 0
	}
	return int(n)
}

func positiveInt64(value json.Number) int64 {
	if value.String() == "" {
		return 0
	}
	n, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func parseFlexibleUnixTime(value json.Number) *time.Time {
	if value.String() == "" {
		return nil
	}
	n, err := strconv.ParseFloat(value.String(), 64)
	if err != nil || n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return nil
	}
	var parsed time.Time
	if n >= 1e11 { // current Lemonade emits milliseconds; older docs show seconds
		parsed = time.UnixMilli(int64(n)).UTC()
	} else {
		seconds, fractional := math.Modf(n)
		parsed = time.Unix(int64(seconds), int64(fractional*float64(time.Second))).UTC()
	}
	if parsed.Year() < 2000 || parsed.Year() > 2200 {
		return nil
	}
	return &parsed
}

func clampLocalModelLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	if limit > maxLocalModelAPIItems {
		return maxLocalModelAPIItems
	}
	return limit
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
