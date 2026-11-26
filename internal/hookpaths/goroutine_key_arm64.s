// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

#include "textflag.h"

// func getg() uintptr: the g of the calling goroutine, from the register the
// runtime keeps it in (g, R28).
TEXT ·getg(SB),NOSPLIT,$0-8
	MOVD	g, R0
	MOVD	R0, ret+0(FP)
	RET
