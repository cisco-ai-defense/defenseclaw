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

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// keepConfigDACL captures the protected DACL Setup put on config.yaml. The
// writer replaces the file (MoveFileExW), so the replacement and the files
// written next to it get the directory's inherited ACL; apply puts the
// captured DACL back on each of them, so the gateway service keeps reading
// exactly what it could read before.
func keepConfigDACL(path string) (apply func(paths ...string) error, err error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	return func(paths ...string) error {
		for _, target := range paths {
			extendedTarget, err := winpath.Extended(target)
			if err != nil {
				return err
			}
			if err := windows.SetNamedSecurityInfo(extendedTarget, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, dacl, nil); err != nil {
				return err
			}
		}
		return nil
	}, nil
}
