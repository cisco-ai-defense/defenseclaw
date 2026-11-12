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

package auth

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiEntropy binds the ciphertext to this use; the context name is
// appended so one context's file cannot be read as another's.
const dpapiEntropy = "defenseclaw-substrate-signin-v1:"

func osStore() (Store, error) {
	dir := tokenDir()
	return &sealedStore{
		dir:  dir,
		s:    dpapiSealer{},
		desc: fmt.Sprintf("Windows DPAPI (current user) with sealed files in %s", dir),
	}, nil
}

type dpapiSealer struct{}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func (dpapiSealer) seal(name string, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("nothing to seal")
	}
	var out windows.DataBlob
	ent := []byte(dpapiEntropy + name)
	if err := windows.CryptProtectData(blob(plain), nil, blob(ent), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("the Windows DPAPI could not protect the sign-in: %w", err)
	}
	return takeBlob(&out), nil
}

func (dpapiSealer) open(name string, sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("the file is empty")
	}
	var out windows.DataBlob
	ent := []byte(dpapiEntropy + name)
	if err := windows.CryptUnprotectData(blob(sealed), nil, blob(ent), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, errors.New("the Windows DPAPI could not unprotect it (another user or computer sealed it)")
	}
	return takeBlob(&out), nil
}
