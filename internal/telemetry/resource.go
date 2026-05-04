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

package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"runtime"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func resolveServiceName(attrs map[string]string) string {
	if v := os.Getenv("OTEL_SERVICE_NAME"); v != "" {
		return v
	}
	if v, ok := attrs["service.name"]; ok && v != "" {
		return v
	}
	return "defenseclaw"
}

func buildResource(cfg *config.Config, version string) *resource.Resource {
	hostname, _ := os.Hostname()
	serviceName := resolveServiceName(cfg.OTel.Resource.Attributes)

	attrs := []attribute.KeyValue{
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
		attribute.String("service.namespace", "ai-governance"),
		attribute.String("deployment.environment", cfg.Environment),
		attribute.String("host.name", hostname),
		attribute.String("host.arch", runtime.GOARCH),
		attribute.String("os.type", runtime.GOOS),
		attribute.String("defenseclaw.claw.mode", string(cfg.Claw.Mode)),
		attribute.String("defenseclaw.claw.home_dir", cfg.Claw.HomeDir),
		attribute.String("defenseclaw.gateway.host", cfg.Gateway.Host),
		attribute.Int("defenseclaw.gateway.port", cfg.Gateway.Port),
		attribute.String("defenseclaw.instance.id", uuid.New().String()),
	}
	if cfg.TenantID != "" {
		attrs = append(attrs, attribute.String("tenant.id", cfg.TenantID))
	}
	if cfg.WorkspaceID != "" {
		attrs = append(attrs, attribute.String("workspace.id", cfg.WorkspaceID))
	}
	if cfg.DeploymentMode != "" {
		attrs = append(attrs, attribute.String("deployment.mode", cfg.DeploymentMode))
	}
	if cfg.DiscoverySource != "" {
		attrs = append(attrs, attribute.String("discovery.source", cfg.DiscoverySource))
	}

	if cfg.Gateway.DeviceKeyFile != "" {
		if fp := deviceFingerprint(cfg.Gateway.DeviceKeyFile); fp != "" {
			attrs = append(attrs, attribute.String("device.id", fp))
		}
	}

	for k, v := range cfg.OTel.Resource.Attributes {
		if k == "service.name" {
			continue
		}
		attrs = append(attrs, attribute.String(k, v))
	}

	r, _ := resource.New(
		context.Background(),
		resource.WithAttributes(attrs...),
	)
	return r
}

// deviceFingerprint derives the public-key fingerprint from the Ed25519
// device key file, matching the DeviceID produced by gateway/device.go.
// This avoids hashing secret material and ensures the telemetry resource
// attribute matches the identity used on the wire.
func deviceFingerprint(keyFile string) string {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	seed := block.Bytes
	if len(seed) != ed25519.SeedSize {
		return ""
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
