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

// WriteManagedTargetRuntimeFile atomically publishes a private managed-runtime
// file for the authenticated effective target user. On Windows, both a matching
// no-op and a changed publication require the exact target-owned managed-file
// security contract; generic private-file protection is intentionally not
// treated as equivalent.
func WriteManagedTargetRuntimeFile(path string, data []byte) error {
	return writeManagedTargetRuntimeFilePlatform(path, data, true)
}

// PublishManagedTargetRuntimeFileNoReplace publishes an immutable private
// managed-runtime file. A destination-name collision is reported as an error
// compatible with os.ErrExist; an existing file is never accepted as a no-op
// and is never replaced.
func PublishManagedTargetRuntimeFileNoReplace(path string, data []byte) error {
	return writeManagedTargetRuntimeFilePlatform(path, data, false)
}
