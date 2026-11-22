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
// (HKU\<sid>\Environment), loaded while the user is signed in. It reports
// false while the user's hive is not loaded (signed out): the value is then
// not known, which is not the same as not set.
func platformSavedVariable(_, sid, name string) (string, bool) {
	if sid == "" {
		return "", true
	}
	hive, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	_ = hive.Close()
	key, err := registry.OpenKey(registry.USERS, sid+`\Environment`, registry.QUERY_VALUE)
	if err != nil {
		return "", true
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return "", true
	}
	return value, true
}
