//go:build windows

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

package connector

import "errors"

// publishOpenClawPluginToken: the separate-user layout is Linux and macOS
// only in 1.0.10 (config validation refuses plugin_account on Windows).
func publishOpenClawPluginToken(string, string, string, string) error {
	return errors.New("the OpenClaw separate-user layout is supported on Linux and macOS only")
}
