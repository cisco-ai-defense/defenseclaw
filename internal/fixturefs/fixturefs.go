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

// Package fixturefs is the one place that says which file system a hook
// decision reads when it looks at a path the call names (a glob it expands, a
// target it stats, a link it follows).
//
// In every product build it is the identity: Map and Unmap return their
// argument and inline away. The S7 benchmark harness (build tag s7bench)
// maps the mutable system roots (/tmp, /var/tmp, /dev/shm and their macOS
// spellings) onto a fixture tree named by S7_FIXTURE_FS_ROOT, so a benchmark
// verdict never depends on what other processes left in the live /tmp
// (rel-1-0-10:GAP-0271). The path text the rules see is not changed, only the
// directory the read goes to.
package fixturefs
