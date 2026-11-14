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

//go:build windows

package gateway

import "errors"

// copyOpenClawScanTarget: the separate-user layout is refused on Windows
// (config validation), so a scan never needs the private copy there.
func copyOpenClawScanTarget(target string, anchors []string) (string, error) {
	return "", errors.New("the OpenClaw separate-user layout is not supported on Windows")
}
