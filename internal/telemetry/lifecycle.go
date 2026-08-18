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

// actionMapping maps audit.Event.Action strings to OTel lifecycle attributes.
// Keys mirror internal/audit Action* constants; telemetry cannot import audit
// because audit.Logger already depends on telemetry.Provider.
type actionMapping struct {
	LifecycleAction     string
	Actor               string
	CanonicalEvent      string
	CanonicalTransition string
}

var actionMap = map[string]actionMapping{
	"install-detected":             {LifecycleAction: "install", Actor: "watcher", CanonicalEvent: "asset.discovered", CanonicalTransition: "discover"},
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

// AssetLifecycleActionMapping is the closed translation contract used by the
// generated v8 asset-family adapter. An empty CanonicalEvent is intentional:
// the audit action describes another domain and must not be relabeled as an
// asset state transition.
type AssetLifecycleActionMapping struct {
	Transition     string
	CanonicalEvent string
}

func AssetLifecycleAction(action string) (AssetLifecycleActionMapping, bool) {
	mapping, ok := actionMap[action]
	if !ok {
		return AssetLifecycleActionMapping{}, false
	}
	return AssetLifecycleActionMapping{
		Transition:     mapping.CanonicalTransition,
		CanonicalEvent: mapping.CanonicalEvent,
	}, true
}
