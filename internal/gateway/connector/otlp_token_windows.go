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

package connector

import "os"

// otlpOpenNoFollow returns 0 on Windows (O_NOFOLLOW is a Unix concept;
// Windows does not follow symlinks during CreateFile by default).
func otlpOpenNoFollow() int {
	return 0
}

// otlpValidateOwner is a no-op on Windows. File ownership uses ACLs and
// the Unix UID check is not applicable.
func otlpValidateOwner(_ string, _ os.FileInfo) error {
	return nil
}
