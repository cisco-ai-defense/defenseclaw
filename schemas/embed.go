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

// Package schemas embeds DefenseClaw's canonical public schemas for consumers
// that cannot rely on a repository checkout at runtime.
package schemas

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"sync"
)

const maxTelemetryRuntimeAssetBytes = 16 * 1024 * 1024

type compressedTelemetryAsset struct {
	name       string
	compressed []byte
	once       sync.Once
	decoded    []byte
	err        error
}

func (asset *compressedTelemetryAsset) bytes() []byte {
	asset.once.Do(func() {
		reader, err := gzip.NewReader(bytes.NewReader(asset.compressed))
		if err != nil {
			asset.err = err
			return
		}
		defer reader.Close()
		asset.decoded, asset.err = io.ReadAll(io.LimitReader(reader, maxTelemetryRuntimeAssetBytes+1))
		if asset.err == nil && len(asset.decoded) > maxTelemetryRuntimeAssetBytes {
			asset.err = fmt.Errorf("decoded asset exceeds %d bytes", maxTelemetryRuntimeAssetBytes)
		}
	})
	if asset.err != nil {
		panic(fmt.Sprintf("schemas: decode embedded telemetry asset %s: %v", asset.name, asset.err))
	}
	return append([]byte(nil), asset.decoded...)
}

//go:embed config/v8/defenseclaw-config.schema.json
var defenseClawConfigV8Schema []byte

//go:embed config/v8/reference/observability.yaml
var defenseClawConfigV8ObservabilityReferenceYAML []byte

//go:embed config/v8/reference/observability.md
var defenseClawConfigV8ObservabilityReferenceMarkdown []byte

//go:embed gateway-event-envelope.json
var gatewayEventEnvelopeSchema []byte

//go:embed scan-event.json
var gatewayScanEventSchema []byte

//go:embed scan-finding-event.json
var gatewayScanFindingEventSchema []byte

//go:embed activity-event.json
var gatewayActivityEventSchema []byte

//go:embed telemetry/v8/registry.yaml
var telemetryV8Registry []byte

//go:embed telemetry/v8/semconv.lock.yaml
var telemetryV8SemconvLock []byte

//go:embed telemetry/runtime/telemetry.schema.json.gz
var telemetryV8SchemaCompressed []byte

//go:embed telemetry/runtime/catalog.json.gz
var telemetryV8CatalogCompressed []byte

//go:embed telemetry/runtime/compatibility/galileo-rich-v2.json.gz
var telemetryV8GalileoCompatibilityProfileCompressed []byte

//go:embed telemetry/runtime/compatibility/local-observability-v1.json.gz
var telemetryV8LocalObservabilityCompatibilityProfileCompressed []byte

//go:embed telemetry/runtime/compatibility/openinference-v1.json.gz
var telemetryV8OpenInferenceCompatibilityProfileCompressed []byte

var (
	telemetryV8SchemaAsset = compressedTelemetryAsset{
		name:       "telemetry.schema.json",
		compressed: telemetryV8SchemaCompressed,
	}
	telemetryV8CatalogAsset = compressedTelemetryAsset{
		name:       "catalog.json",
		compressed: telemetryV8CatalogCompressed,
	}
	telemetryV8GalileoCompatibilityProfileAsset = compressedTelemetryAsset{
		name:       "galileo-rich-v2.json",
		compressed: telemetryV8GalileoCompatibilityProfileCompressed,
	}
	telemetryV8LocalObservabilityCompatibilityProfileAsset = compressedTelemetryAsset{
		name:       "local-observability-v1.json",
		compressed: telemetryV8LocalObservabilityCompatibilityProfileCompressed,
	}
	telemetryV8OpenInferenceCompatibilityProfileAsset = compressedTelemetryAsset{
		name:       "openinference-v1.json",
		compressed: telemetryV8OpenInferenceCompatibilityProfileCompressed,
	}
)

// DefenseClawConfigV8Schema returns a copy of the exact checked-in canonical v8
// configuration schema bytes. Callers cannot mutate the process-wide embed.
func DefenseClawConfigV8Schema() []byte {
	return append([]byte(nil), defenseClawConfigV8Schema...)
}

// DefenseClawConfigV8ObservabilityReferenceYAML returns a copy of the
// exhaustive, generated source-configuration example owned by the v8 schema.
func DefenseClawConfigV8ObservabilityReferenceYAML() []byte {
	return append([]byte(nil), defenseClawConfigV8ObservabilityReferenceYAML...)
}

// DefenseClawConfigV8ObservabilityReferenceMarkdown returns a copy of the
// generated human-readable v8 observability field catalog.
func DefenseClawConfigV8ObservabilityReferenceMarkdown() []byte {
	return append([]byte(nil), defenseClawConfigV8ObservabilityReferenceMarkdown...)
}

// GatewayEventEnvelopeSchema returns a defensive copy of the canonical legacy
// managed-ingest envelope schema.
func GatewayEventEnvelopeSchema() []byte {
	return append([]byte(nil), gatewayEventEnvelopeSchema...)
}

// GatewayScanEventSchema returns a defensive copy of the scan payload schema
// referenced by GatewayEventEnvelopeSchema.
func GatewayScanEventSchema() []byte {
	return append([]byte(nil), gatewayScanEventSchema...)
}

// GatewayScanFindingEventSchema returns a defensive copy of the scan-finding
// payload schema referenced by GatewayEventEnvelopeSchema.
func GatewayScanFindingEventSchema() []byte {
	return append([]byte(nil), gatewayScanFindingEventSchema...)
}

// GatewayActivityEventSchema returns a defensive copy of the activity payload
// schema referenced by GatewayEventEnvelopeSchema.
func GatewayActivityEventSchema() []byte {
	return append([]byte(nil), gatewayActivityEventSchema...)
}

// TelemetryV8Registry returns a copy of the immutable v8 telemetry registry
// manifest, including semantic-profile bindings.
func TelemetryV8Registry() []byte {
	return append([]byte(nil), telemetryV8Registry...)
}

// TelemetryV8SemconvLock returns a copy of the pinned upstream semantic
// convention revisions used to validate those profiles.
func TelemetryV8SemconvLock() []byte {
	return append([]byte(nil), telemetryV8SemconvLock...)
}

// TelemetryV8Schema returns a copy of the generated canonical v8 telemetry
// schema bundle. Callers cannot mutate the process-wide embed.
func TelemetryV8Schema() []byte {
	return telemetryV8SchemaAsset.bytes()
}

// TelemetryV8Catalog returns a copy of the generated canonical v8 telemetry
// catalog. Callers cannot mutate the process-wide embed.
func TelemetryV8Catalog() []byte {
	return telemetryV8CatalogAsset.bytes()
}

// TelemetryV8CompatibilityProfile returns a copy of one generated compatibility
// profile manifest. Unknown profile IDs deliberately return nil.
func TelemetryV8CompatibilityProfile(profileID string) []byte {
	var asset *compressedTelemetryAsset
	switch profileID {
	case "galileo-rich-v2":
		asset = &telemetryV8GalileoCompatibilityProfileAsset
	case "local-observability-v1":
		asset = &telemetryV8LocalObservabilityCompatibilityProfileAsset
	case "openinference-v1":
		asset = &telemetryV8OpenInferenceCompatibilityProfileAsset
	default:
		return nil
	}
	return asset.bytes()
}
