//go:build !windows

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

package chainstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0394: on EKS (EBS gp3) the pod fsGroup makes every directory of the
// store volume 2770 and every file 0660 on each mount. The leader then
// refused every ChainObserve: "database directory .../chains is group- or
// other-writable". The leader owns those entries and takes them back to
// owner-only when it opens the chain state; the volume root stays as it is
// (audit.TrustVolumeRoot) and the audit check is not loosened.
func TestGAP0394FSGroupStoreTreeIsTakenBackAtOpen(t *testing.T) {
	vol := filepath.Join(t.TempDir(), "store")
	for _, d := range []string{"chains/eng-web", "actors"} {
		if err := os.MkdirAll(filepath.Join(vol, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(vol, "actors", "a.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What the kubelet does for fsGroup (fsGroupChangePolicy Always).
	for _, p := range []string{vol, filepath.Join(vol, "chains"), filepath.Join(vol, "chains", "eng-web"), filepath.Join(vol, "actors")} {
		if err := os.Chmod(p, 0o770|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(file, 0o660); err != nil {
		t.Fatal(err)
	}
	audit.TrustVolumeRoot(vol)
	if _, err := New(Options{Dir: vol, EgressAction: EgressBlock}); err != nil {
		t.Fatalf("New on the fsGroup volume: %v", err)
	}
	for _, p := range []string{filepath.Join(vol, "chains"), filepath.Join(vol, "chains", "eng-web"), filepath.Join(vol, "actors"), file} {
		info, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 || info.Mode()&os.ModeSetgid != 0 {
			t.Fatalf("%s is still %s after the chain state opened", p, info.Mode())
		}
	}
	// The chain store of an actor now opens under the fsGroup volume.
	st, err := audit.NewStore(filepath.Join(vol, "chains", "eng-web", "u-1.db"))
	if err != nil {
		t.Fatalf("chain store under the fsGroup volume: %v", err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	// Entries another account owns are not this process's to change; the
	// volume root keeps its mode (TrustVolumeRoot accepts it as an ancestor).
	if info, _ := os.Lstat(vol); info.Mode().Perm() != 0o770 {
		t.Fatalf("the volume root was changed: %s", info.Mode())
	}
}
