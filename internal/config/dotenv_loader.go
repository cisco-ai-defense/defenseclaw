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

package config

// dotEnvLoader is the process's .env loader. The command package owns it
// because it applies the managed-host and process-control rules; the gateway
// package, which cannot import the command package, reaches it through
// LoadDotEnv.
var dotEnvLoader func(path string)

// RegisterDotEnvLoader installs the loader LoadDotEnv calls.
func RegisterDotEnvLoader(load func(path string)) { dotEnvLoader = load }

// LoadDotEnv loads the KEY=VALUE pairs of the .env file at path into the
// process environment through the registered loader. A variable that is
// already set keeps its value. With no loader registered it does nothing.
func LoadDotEnv(path string) {
	if load := dotEnvLoader; load != nil {
		load(path)
	}
}
