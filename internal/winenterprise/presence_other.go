// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winenterprise

// The enterprise SCM deployment exists only on Windows.
func platformDetectDeployment() (Deployment, bool, error) { return Deployment{}, false, nil }

func platformCurrentProcessIsService() (bool, error) { return false, nil }
