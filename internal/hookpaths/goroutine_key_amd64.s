// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

#include "textflag.h"

// func getg() uintptr: the g of the calling goroutine, from the TLS slot the
// runtime keeps it in (runtime/go_tls.h: get_tls(r) is MOVQ TLS, r and g(r)
// is 0(r)(TLS*1)).
TEXT ·getg(SB),NOSPLIT,$0-8
	MOVQ	TLS, CX
	MOVQ	0(CX)(TLS*1), AX
	MOVQ	AX, ret+0(FP)
	RET
