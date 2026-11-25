// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import "golang.org/x/sys/windows/registry"

// platformSavedVariable reads the user's persistent environment
// (HKU\<sid>\Environment), loaded while the user is signed in.
func platformSavedVariable(_, sid, name string) string {
	if sid == "" {
		return ""
	}
	key, err := registry.OpenKey(registry.USERS, sid+`\Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}
