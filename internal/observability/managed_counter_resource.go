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

package observability

// The managed sandbox counters (defenseclaw.sandbox.managed.*) carry no
// user, account, host or device label. A collector that turns resource
// attributes into labels (Prometheus remote write, for one) would add the
// host, tenant, workspace and device key ones, so a metric destination
// sends these counters with a resource cut to the keys below. The bundled
// collector cuts the same keys (bundles/local_observability_stack/
// otel-collector/config.yaml, transform/managed-sandbox-resource).
// service.instance.id stays: it is a random id per gateway process, and
// each process keeps its own running total.

var resourceRestrictedMetrics = map[string]bool{
	TelemetryInstrumentDefenseClawSandboxManagedRefusals:     true,
	TelemetryInstrumentDefenseClawSandboxManagedAsks:         true,
	TelemetryInstrumentDefenseClawSandboxManagedForeignItems: true,
	TelemetryInstrumentDefenseClawSandboxManagedProvisional:  true,
	TelemetryInstrumentDefenseClawSandboxManagedDrift:        true,
}

var restrictedMetricResourceKeys = map[string]bool{
	"service.name": true, "service.namespace": true, "service.version": true, "service.instance.id": true,
	"deployment.environment.name": true, "os.type": true,
}

// ResourceRestrictedMetric reports whether metric name is exported with a
// resource cut to RestrictedMetricResourceKey.
func ResourceRestrictedMetric(name string) bool { return resourceRestrictedMetrics[name] }

// RestrictedMetricResourceKey reports whether a resource-restricted metric
// keeps the resource attribute key.
func RestrictedMetricResourceKey(key string) bool { return restrictedMetricResourceKeys[key] }
