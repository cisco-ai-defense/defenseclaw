// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package sensor

import (
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// scriptableRuntimes are the interpreters and runtimes an agent is plausibly
// hosted inside. Plane A only raises an inference heartbeat for these: a
// compiled application burning CPU is a compiled application burning CPU, and
// scoring every busy process would make the signal worthless.
var scriptableRuntimes = map[string]bool{
	"python": true, "python3": true, "python3.10": true, "python3.11": true,
	"python3.12": true, "python3.13": true, "pypy": true, "pypy3": true,
	"node": true, "nodejs": true, "bun": true, "deno": true,
	"ruby": true, "perl": true, "java": true, "dotnet": true, "mono": true,
	"uv": true, "uvx": true, "npx": true, "pnpm": true, "yarn": true,
}

// localModelRuntimes are processes that *are* a model server, as opposed to
// something calling one.
var localModelRuntimes = map[string]bool{
	"ollama": true, "ollama_llama_server": true,
	"llama-server": true, "llama-cli": true, "llamacpp": true, "llama.cpp": true,
	"lm-studio": true, "lms": true, "lmstudio": true,
	"vllm": true, "localai": true, "local-ai": true,
	"gpt4all": true, "koboldcpp": true, "text-generation-server": true,
	"mlx_lm.server": true, "lemonade": true, "lemond": true,
	"lemonadeserver.exe": true, "jan": true, "cortex": true,
}

// isKnownModelRuntime reports whether a process name is itself a model server.
func isKnownModelRuntime(name string) bool { return localModelRuntimes[strings.ToLower(name)] }

// inferenceCPUFraction is the share of one core a process must sustain across
// a poll interval to count as an inference heartbeat.
//
// Deliberately well below saturation. Batched inference on a laptop is bursty,
// and a threshold set at full utilisation would see only the largest models.
const inferenceCPUFraction = 0.35

// modelResidentBytes is the RSS at which a process is holding enough memory to
// contain model weights.
//
// A weak signal on its own -- an IDE or a browser clears this easily -- and
// weighted as such. It earns its place only in combination.
const modelResidentBytes int64 = 1 << 30

// planeA classifies one process's compute behaviour.
func planeA(process procprobe.Process, cpuDelta time.Duration, window time.Duration) []scoring.Signal {
	name := strings.ToLower(process.Name)
	signals := make([]scoring.Signal, 0, 3)

	if localModelRuntimes[name] {
		signals = append(signals, scoring.Signal{
			ID:     "local_model_runtime",
			Title:  "process is a local model runtime",
			Detail: process.Name,
			Weight: scoring.WeightLocalRuntimeProcess,
		})
	}

	// A heartbeat needs a scriptable runtime *or* a known model runtime.
	// Sustained CPU in anything else is not evidence of inference.
	if window > 0 && (scriptableRuntimes[name] || localModelRuntimes[name]) {
		if float64(cpuDelta) >= inferenceCPUFraction*float64(window) {
			signals = append(signals, scoring.Signal{
				ID:    "inference_heartbeat",
				Title: "sustained compute in a scriptable runtime",
				Detail: process.Name + " used " + cpuDelta.Truncate(time.Millisecond).String() +
					" of CPU over " + window.Truncate(time.Second).String(),
				Weight: scoring.WeightInferenceHeartbeat,
			})
		}
	}

	if process.RSSBytes >= modelResidentBytes &&
		(scriptableRuntimes[name] || localModelRuntimes[name]) {
		signals = append(signals, scoring.Signal{
			ID:     "model_resident_memory",
			Title:  "resident memory large enough to hold model weights",
			Detail: process.Name,
			Weight: scoring.WeightModelResidentMemory,
		})
	}
	return signals
}

// planeBResult is what one process's connections produced.
type planeBResult struct {
	signals   []scoring.Signal
	providers []ProviderReach
	// unattributedPublicPeers counts distinct public peers this process
	// reached that could not be named. Repetition across polls is what
	// escalates them; a single sighting is deliberately too weak to report.
	unattributedPublicPeers int
	// localInferenceClient is set when the process talked to a loopback model
	// server, which is the client half of local inference.
	localInferenceClient bool
	// listeningModelPort names the runtime a listening port is reserved to.
	listeningModelPort string
}

// planeB classifies one process's connections.
func planeB(
	connections []netprobe.Connection,
	processName string,
	providers *catalog.Catalog,
	resolve func(netprobe.Connection) (hostname string, confidence float64, source string),
	sanctioned map[string]bool,
) planeBResult {
	result := planeBResult{}
	seenPeers := make(map[string]bool, len(connections))
	reachedSanctioned := false
	reachedProvider := false

	for _, connection := range connections {
		if connection.State == netprobe.StateListen {
			// A reserved port names its runtime on its own. An ambiguous one
			// -- 8080, 8000, 5000, 1234, 1337 -- needs the process to agree,
			// because otherwise any developer's web server becomes a local
			// model finding at a weight that clears the reporting floor.
			if runtime, corroborated := netprobe.LocalModelRuntimeForPort(connection.LocalPort); runtime != "" {
				if corroborated || isKnownModelRuntime(processName) {
					result.listeningModelPort = runtime
				}
			}
			continue
		}
		if connection.Loopback() {
			if runtime, corroborated := netprobe.LocalModelRuntimeForPort(connection.RemotePort); runtime != "" {
				// A client of an ambiguous port needs a scriptable runtime
				// behind it; a browser talking to localhost:8080 is not
				// evidence of local inference.
				if corroborated || isScriptable(processName) {
					result.localInferenceClient = true
				}
			}
			continue
		}
		if !connection.Public() {
			continue
		}
		hostname, confidence, source := resolve(connection)
		if hostname == "" {
			// An unnamed public peer. Counted rather than scored here: a
			// single one is noise, and repetition across polls is what makes
			// it evidence.
			key := connection.RemoteIP.String()
			if !seenPeers[key] {
				seenPeers[key] = true
				result.unattributedPublicPeers++
			}
			continue
		}
		if sanctioned[strings.ToLower(hostname)] {
			reachedSanctioned = true
			result.providers = append(result.providers, ProviderReach{
				Hostname: hostname, Address: connection.RemoteIP.String(),
				Port: connection.RemotePort, Category: "sanctioned",
				Confidence: confidence, AttributionSource: source,
			})
			continue
		}
		provider, known := providers.Lookup(hostname)
		if !known {
			if !catalog.InferenceShaped(hostname) {
				continue
			}
			provider = catalog.Unknown(hostname)
		}
		reachedProvider = true
		result.providers = append(result.providers, ProviderReach{
			Hostname: hostname, Address: connection.RemoteIP.String(),
			Port: connection.RemotePort, Category: string(provider.Category),
			Confidence: confidence, AttributionSource: source,
		})
		signalID := "shadow_ai_egress"
		title := "connection to a known AI provider"
		if provider.ID == "" {
			signalID = "unknown_provider_egress"
			title = "connection to an inference-shaped host not in the catalog"
		}
		result.signals = append(result.signals, scoring.Signal{
			ID: signalID, Title: title,
			Detail: hostname + " (" + string(provider.Category) + ")",
			Weight: scoring.ConfidenceWeighted(provider.Weight(), confidence),
		})
	}

	if result.localInferenceClient {
		result.signals = append(result.signals, scoring.Signal{
			ID:     "local_inference_client",
			Title:  "process is calling a local model server",
			Weight: scoring.WeightLocalRuntimeClient,
		})
	}
	if result.listeningModelPort != "" {
		result.signals = append(result.signals, scoring.Signal{
			ID:     "local_model_server_port",
			Title:  "listening on a port reserved to a model runtime",
			Detail: result.listeningModelPort,
			Weight: scoring.WeightLocalRuntimeProcess,
		})
	}
	if reachedSanctioned && !reachedProvider {
		// Approved-path AI use. Inventory, not alarm.
		result.signals = append(result.signals, scoring.Signal{
			ID:     "sanctioned_ai_egress",
			Title:  "AI use through an approved gateway",
			Weight: scoring.WeightSanctionedEgress,
		})
	}
	if reachedProvider && len(sanctioned) > 0 {
		// An approved gateway exists on this host and this process went around
		// it. That is a different fact from reaching a provider on a host with
		// no gateway at all, and is scored as one.
		result.signals = append(result.signals, scoring.Signal{
			ID:     "gateway_bypass",
			Title:  "an approved gateway exists and was gone around",
			Weight: scoring.WeightGatewayBypass,
		})
	}
	return result
}

// unattributedEgressSignal prices repeated unnamed public peers.
//
// Repetition is the corroboration a single sighting lacks. Without the
// escalation, a real provider connection whose address attribution keeps
// missing could repeat forever and never clear the reporting floor.
func unattributedEgressSignal(repeatCount int) (scoring.Signal, bool) {
	if repeatCount <= 0 {
		return scoring.Signal{}, false
	}
	weight := scoring.WeightUnattributedEgress
	title := "repeated unnamed TLS egress from a scriptable runtime"
	if repeatCount >= scoring.UnattributedEgressRepeatThreshold {
		weight = scoring.WeightUnattributedEgressEscalated
		title = "persistent unnamed TLS egress from a scriptable runtime"
	}
	return scoring.Signal{
		ID: "unattributed_tls_egress", Title: title, Weight: weight,
	}, true
}
