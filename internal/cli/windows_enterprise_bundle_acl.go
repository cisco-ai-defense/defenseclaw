// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

// These pure SDDL builders are shared by the Windows creator and host-neutral
// contract tests. The PowerShell table is compared against every result.
func windowsBundlePrivateSDDL() string {
	return "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

func windowsBundleAdminFileSDDL() string {
	return "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
}

func windowsBundleDirectorySDDL(serviceSID string) string {
	return "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICI;0x1200a9;;;" + serviceSID + ")"
}

func windowsBundleReceiptSDDL(serviceSID string) string {
	return "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)(A;;FR;;;" + serviceSID + ")"
}

func windowsBundleVersionSDDL(serviceSID string, directory bool) string {
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	return "O:BAG:BAD:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)(A;;0x1200a9;;;" + serviceSID + ")"
}
