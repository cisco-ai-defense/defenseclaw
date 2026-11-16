// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// A managed Windows install writes no native OTLP exporter into an account's
// own agent configuration: machine policy delivers Codex and Claude Code and
// the gateway service serves them. An exporter a pre-1.0.4 per-user install
// left there can outlive every credential the install could name (its token
// sidecar and setup backup gone), so the ownership rule above (a known
// credential, never endpoint, token shape or x-defenseclaw-* markers) keeps
// it, and the agent sends its prompt telemetry and bearer to a loopback port
// no DefenseClaw process holds, which another account can bind (GAP-0836).
//
// For that profile only (SetupOpts.ManagedMarkedOrphanExporters, set by the
// Windows managed take-back and Verify, never by host setup), one exact shape
// is the product's as well: an exporter whose endpoint is a loopback address
// on an explicit port the managed gateway does not serve
// (SetupOpts.ManagedServedAddrs), and whose headers carry both of the
// markers DefenseClaw's own render wrote, x-defenseclaw-source naming the
// connector and x-defenseclaw-client naming its OTLP client. Its bearer then
// counts as a known credential, so the take-back removes the exporter the
// way it removes one with a recorded credential. Any other shape (one marker,
// another host, a served port, no bearer) keeps the rule; Verify names it
// with the manual step (UserNativeOTLPMarkedKeptIn). LEAD DECISION 05:36.

// markedOrphanSources is the x-defenseclaw-source value and the
// x-defenseclaw-client prefix the product's render wrote per connector.
var markedOrphanSources = map[string]struct{ source, clientPrefix string }{
	"codex":      {"codex", "codex-otel/"},
	"claudecode": {"claudecode", "claudecode-otel/"},
}

// withMarkedOrphanExporterCredentials gives opts the bearer of every exporter
// in raw that has the managed orphan shape. A no-op unless the managed
// profile asked for it.
func withMarkedOrphanExporterCredentials(opts SetupOpts, connectorName string, raw []byte) SetupOpts {
	if !opts.ManagedMarkedOrphanExporters {
		return opts
	}
	credentials := markedOrphanExporterCredentials(connectorName, raw, opts.ManagedServedAddrs)
	if len(credentials) == 0 {
		return opts
	}
	known := make([]string, 0, len(opts.knownCredentials)+len(credentials))
	known = append(known, opts.knownCredentials...)
	opts.knownCredentials = append(known, credentials...)
	return opts
}

// UserNativeOTLPMarkedOrphanIn reports whether config (the account's Codex
// config.toml or Claude Code settings.json) holds an exporter that only the
// managed orphan shape makes the product's, so the take-back keeps a copy of
// the file before it removes the exporter and status names the removal.
func UserNativeOTLPMarkedOrphanIn(connectorName string, config []byte, opts SetupOpts) bool {
	if !opts.ManagedMarkedOrphanExporters {
		return false
	}
	return len(markedOrphanExporterCredentials(connectorName, config, opts.ManagedServedAddrs)) > 0
}

// markedOrphanExporterCredentials returns the bearers of the exporters in raw
// with the managed orphan shape.
func markedOrphanExporterCredentials(connectorName string, raw []byte, served []string) []string {
	marks, ok := markedOrphanSources[connectorName]
	if !ok || len(raw) == 0 || int64(len(raw)) > userNativeOTLPReadLimit {
		return nil
	}
	servedPorts := map[string]bool{}
	for _, addr := range served {
		if _, port, err := net.SplitHostPort(strings.TrimSpace(addr)); err == nil && port != "" {
			servedPorts[port] = true
		}
	}
	var out []string
	add := func(endpoint string, headers map[string]string) {
		if !markedOrphanEndpoint(endpoint, servedPorts) {
			return
		}
		if headers["x-defenseclaw-source"] != marks.source ||
			!strings.HasPrefix(headers["x-defenseclaw-client"], marks.clientPrefix) {
			return
		}
		credential, ok := otlpBearerCredential(headers["authorization"])
		if !ok || len(credential) < otlpMinKnownTokenLen {
			return
		}
		out = append(out, credential)
	}
	switch connectorName {
	case "codex":
		for _, exporter := range codexMarkedExporters(raw) {
			add(exporter.endpoint, exporter.headers)
		}
	case "claudecode":
		env := claudeCodeSettingsEnv(raw)
		for key, value := range env {
			endpoint, _ := value.(string)
			if endpoint == "" || !claudeCodeOTLPEndpointKey(key) {
				continue
			}
			add(endpoint, otlpHeaderList(claudeCodeEffectiveEndpointHeaders(env, key)))
		}
	}
	return out
}

// markedOrphanEndpoint reports an http(s) endpoint on a loopback host with an
// explicit port that is not one of servedPorts.
func markedOrphanEndpoint(endpoint string, servedPorts map[string]bool) bool {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	port := u.Port()
	if port == "" || servedPorts[port] {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// codexMarkedExporter is one Codex OTLP exporter: its endpoint and headers
// (names lower-cased), and the [otel] key it is under.
type codexMarkedExporter struct {
	key, endpoint string
	headers       map[string]string
}

// codexMarkedExporters lists the otlp-http and otlp-grpc exporters of a Codex
// config.toml's [otel] table.
func codexMarkedExporters(raw []byte) []codexMarkedExporter {
	cfg := map[string]interface{}{}
	if err := parseCodexTOML(raw, &cfg); err != nil {
		return nil
	}
	otel, _ := cfg["otel"].(map[string]interface{})
	var out []codexMarkedExporter
	for key, value := range otel {
		table, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for _, kind := range []string{"otlp-http", "otlp-grpc"} {
			exporter, ok := table[kind].(map[string]interface{})
			if !ok {
				continue
			}
			endpoint, _ := exporter["endpoint"].(string)
			headers := map[string]string{}
			if raw, ok := exporter["headers"].(map[string]interface{}); ok {
				for name, value := range raw {
					if text, ok := value.(string); ok {
						headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(text)
					}
				}
			}
			out = append(out, codexMarkedExporter{key: key, endpoint: endpoint, headers: headers})
		}
	}
	return out
}

// claudeCodeSettingsEnv is the env block of a Claude Code settings.json, nil
// when it cannot be parsed.
func claudeCodeSettingsEnv(raw []byte) map[string]interface{} {
	settings := map[string]interface{}{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil
	}
	env, _ := settings["env"].(map[string]interface{})
	return env
}

// otlpHeaderList parses an OTEL_EXPORTER_OTLP_*_HEADERS value (comma
// separated name=value pairs, values percent-encoded) with lower-cased names.
func otlpHeaderList(value string) map[string]string {
	headers := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		name, headerValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		decoded, err := url.PathUnescape(strings.TrimSpace(headerValue))
		if err != nil {
			decoded = strings.TrimSpace(headerValue)
		}
		headers[strings.ToLower(strings.TrimSpace(name))] = decoded
	}
	return headers
}

// UserNativeOTLPMarkedKeptIn names the exporters in config that carry an
// x-defenseclaw-* header but that the take-back keeps: no credential this
// install can name, and not the managed orphan shape. Verify warns with them
// and the manual step (LEAD DECISION 05:36 option (b)); they are never
// removed or failed on.
func UserNativeOTLPMarkedKeptIn(connectorName string, config, backup []byte, opts SetupOpts) []string {
	removed, err := UserNativeOTLPResidueIn(connectorName, config, backup, opts)
	if err != nil {
		return nil
	}
	gone := map[string]bool{}
	for _, name := range removed {
		gone[name] = true
	}
	marked := map[string]bool{}
	switch connectorName {
	case "codex":
		for _, exporter := range codexMarkedExporters(config) {
			for name := range exporter.headers {
				if strings.HasPrefix(name, "x-defenseclaw-") {
					marked["config.toml otel."+exporter.key] = true
				}
			}
		}
	case "claudecode":
		for key, value := range claudeCodeSettingsEnv(config) {
			text, _ := value.(string)
			if claudeCodeOTLPHeadersKey(key) && strings.Contains(strings.ToLower(text), "x-defenseclaw-") {
				marked["settings.json env."+key] = true
			}
		}
	}
	var kept []string
	for name := range marked {
		if !gone[name] {
			kept = append(kept, name)
		}
	}
	sort.Strings(kept)
	return kept
}
