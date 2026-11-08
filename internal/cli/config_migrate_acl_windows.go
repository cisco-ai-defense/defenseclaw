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

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// keepConfigDACL captures the protected DACL Setup put on config.yaml. The
// writer replaces the file (MoveFileExW), so the replacement and config
// metadata written next to it may get the directory's inherited ACL; apply
// puts the captured DACL back on the caller's config-owned paths. Secret
// files such as .env retain their own DACL.
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

// keepConfigSecurity is keepConfigDACL for a writer that publishes a managed
// record under a name the hook guardian keeps at the canonical owner:
// apply gives the paths the owner and group of path as well as its protected
// DACL. A file created by the writing account (SYSTEM under Setup) carries
// that account as its owner, and renaming it into place leaves the record
// with the wrong owner until the guardian puts it back (GAP-0899).
//
// The owner is taken first with the writer's own token, then with the
// restore and take-ownership privileges enabled, as the guardian's repair
// does. A token that holds neither stamps the DACL alone, as before.
func keepConfigSecurity(path string) (apply func(paths ...string) error, err error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	group, _, err := sd.Group()
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
			if err := stampConfigSecurity(extendedTarget, owner, group, dacl); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// stampConfigSecurity stamps owner, group and the protected dacl on target.
func stampConfigSecurity(target string, owner, group *windows.SID, dacl *windows.ACL) error {
	daclOnly := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	full := daclOnly
	if owner != nil {
		full |= windows.OWNER_SECURITY_INFORMATION
	}
	if group != nil {
		full |= windows.GROUP_SECURITY_INFORMATION
	}
	set := func(information windows.SECURITY_INFORMATION) error {
		return windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, information, owner, group, dacl, nil)
	}
	if full == daclOnly {
		return set(daclOnly)
	}
	if err := set(full); err == nil {
		return nil
	}
	if err := managed.RunWithWindowsRepairPrivileges(func() error { return set(full) }); err == nil {
		return nil
	}
	return set(daclOnly)
}
