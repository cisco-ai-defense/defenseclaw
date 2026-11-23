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

package registry

import (
	"context"
	"slices"
)

// RemoveApproved takes host out of the Approved hosts of the registration
// atespace/uid in s, when an always approval is taken back (GAP-0492), and
// reports whether the registration had it. Without admin only the
// registration's own person (callerID) may.
func RemoveApproved(ctx context.Context, s Store, atespace, uid, host, callerID string, admin bool) (bool, error) {
	r, ok, err := s.Get(ctx, atespace, uid)
	if err != nil || !ok || r.Deleted {
		return false, err
	}
	if !admin && (r.Person.Subject == "" || r.Person.ID() != callerID) {
		return false, nil
	}
	i := slices.Index(r.Approved, host)
	if i < 0 {
		return false, nil
	}
	r.Approved = slices.Delete(slices.Clone(r.Approved), i, i+1)
	return true, s.Put(ctx, r)
}
