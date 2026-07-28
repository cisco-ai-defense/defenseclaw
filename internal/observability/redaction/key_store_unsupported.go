// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package redaction

func loadOrCreateCorrelationKeyPlatform(_ string, _ keyEntropyReader, _ keyStoreHooks) (CorrelationKey, error) {
	return CorrelationKey{}, keyStoreError(KeyStoreErrorUnsupported)
}
