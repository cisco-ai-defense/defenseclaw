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
	"fmt"
	"os"
)

func withEnterpriseHookRotationLock(
	_ string,
	_ func() (enterpriseHookRotationJournal, error),
) (enterpriseHookRotationJournal, error) {
	return enterpriseHookRotationJournal{}, fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func enterpriseHookRotationLockHeld(string) (bool, error) {
	return false, nil
}

func enterpriseHookRotationFileOwner(os.FileInfo) (int, int, error) {
	return -1, -1, fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func enterpriseHookRotationRestoreOwner(enterpriseHookRotationSnapshot) error {
	return fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}

func checkEnterpriseHookRotationSpace(string) error {
	return fmt.Errorf("enterprise hooks rotate: Windows requires the native guardian adapter")
}
