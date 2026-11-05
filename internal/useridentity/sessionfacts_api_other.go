// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !windows

package useridentity

func readAPIPrincipal(string) (string, bool) { return "", true }
