// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

// InstallSettings returns the flattened settings of a SubstrateInstall
// document (for example atenet.egress.additionalExtprocService), so a caller
// can read what is installed without writing anything.
func InstallSettings(raw []byte) (map[string]string, error) {
	d, err := parseInstall(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(d.settings))
	for k, v := range d.settings {
		out[k] = v
	}
	return out, nil
}
