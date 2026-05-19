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
	"fmt"
	"time"

	"go.opentelemetry.io/otel/log"
)

// actionMapping maps audit.Event.Action strings to OTel lifecycle attributes.
// Keys mirror internal/audit Action* constants; telemetry cannot import audit
// because audit.Logger already depends on telemetry.Provider.
type actionMapping struct {
	LifecycleAction string
	Actor           string
}

var actionMap = map[string]actionMapping{
	"install-detected":             {LifecycleAction: "install", Actor: "watcher"},
	"install-rejected":             {LifecycleAction: "block", Actor: "watcher"},
	"install-allowed":              {LifecycleAction: "allow", Actor: "watcher"},
	"install-allowed-skip-enforce": {LifecycleAction: "allow", Actor: "watcher"},
	"install-clean":                {LifecycleAction: "install", Actor: "watcher"},
	"install-warning":              {LifecycleAction: "install", Actor: "watcher"},
	"install-scan-error":           {LifecycleAction: "scan-error", Actor: "watcher"},
	"install-enforced":             {LifecycleAction: "block", Actor: "watcher"},
	"watch-start":                  {LifecycleAction: "watch-start", Actor: "watcher"},
	"watch-stop":                   {LifecycleAction: "watch-stop", Actor: "watcher"},
	"block":                        {LifecycleAction: "block", Actor: "user"},
	"watcher-block":                {LifecycleAction: "block", Actor: "watcher"},
	"allow":                        {LifecycleAction: "allow", Actor: "user"},
	"quarantine":                   {LifecycleAction: "quarantine", Actor: "defenseclaw"},
	"restore":                      {LifecycleAction: "restore", Actor: "user"},
	"deploy":                       {LifecycleAction: "install", Actor: "user"},
	"stop":                         {LifecycleAction: "uninstall", Actor: "user"},
	"disable":                      {LifecycleAction: "disable", Actor: "defenseclaw"},
	"enable":                       {LifecycleAction: "enable", Actor: "user"},
	"api-skill-disable":            {LifecycleAction: "disable", Actor: "user"},
	"api-skill-enable":             {LifecycleAction: "enable", Actor: "user"},
	"api-plugin-disable":           {LifecycleAction: "disable", Actor: "user"},
	"api-plugin-enable":            {LifecycleAction: "enable", Actor: "user"},
}

// severityToOTel maps string severity to OTel severity number.
func severityToOTel(sev string) (string, int) {
	switch sev {
	case "CRITICAL", "ERROR":
		return "ERROR", 17
	case "HIGH", "WARN":
		return "WARN", 13
	default:
		return "INFO", 9
	}
}

// EmitLifecycleEvent emits an OTel LogRecord for an asset lifecycle event.
func (p *Provider) EmitLifecycleEvent(
	action, target, assetType, reason, severity string,
	enforcement map[string]string,
) {
	if !p.LogsEnabled() {
		return
	}

	mapping, ok := actionMap[action]
	if !ok {
		return
	}

	sevText, sevNum := severityToOTel(severity)
	body := fmt.Sprintf("%s %s %s: %s", assetType, target, mapping.LifecycleAction, reason)

	now := time.Now()
	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(body))

	attrs := []log.KeyValue{
		log.String("event.name", mapping.LifecycleAction),
		log.String("event.domain", "defenseclaw.asset"),
		log.String("defenseclaw.asset.type", assetType),
		log.String("defenseclaw.asset.name", target),
		log.String("defenseclaw.lifecycle.action", mapping.LifecycleAction),
		log.String("defenseclaw.lifecycle.reason", reason),
		log.String("defenseclaw.lifecycle.actor", mapping.Actor),
	}

	if sourcePath, ok := enforcement["source_path"]; ok && sourcePath != "" {
		attrs = append(attrs, log.String("defenseclaw.asset.source_path", sourcePath))
	}
	if v, ok := enforcement["install"]; ok {
		attrs = append(attrs, log.String("defenseclaw.enforcement.install", v))
	}
	if v, ok := enforcement["file"]; ok {
		attrs = append(attrs, log.String("defenseclaw.enforcement.file", v))
	}
	if v, ok := enforcement["runtime"]; ok {
		attrs = append(attrs, log.String("defenseclaw.enforcement.runtime", v))
	}

	rec.AddAttributes(attrs...)
	p.logger.Emit(context.Background(), rec)
}
