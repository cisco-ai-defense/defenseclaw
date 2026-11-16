// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

#include "textflag.h"

TEXT krb5_init_context_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_init_context(SB)
GLOBL	·krb5InitContextAddr(SB), RODATA, $8
DATA	·krb5InitContextAddr(SB)/8, $krb5_init_context_trampoline<>(SB)

TEXT krb5_free_context_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_free_context(SB)
GLOBL	·krb5FreeContextAddr(SB), RODATA, $8
DATA	·krb5FreeContextAddr(SB)/8, $krb5_free_context_trampoline<>(SB)

TEXT krb5_cc_default_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_cc_default(SB)
GLOBL	·krb5CCDefaultAddr(SB), RODATA, $8
DATA	·krb5CCDefaultAddr(SB)/8, $krb5_cc_default_trampoline<>(SB)

TEXT krb5_cc_resolve_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_cc_resolve(SB)
GLOBL	·krb5CCResolveAddr(SB), RODATA, $8
DATA	·krb5CCResolveAddr(SB)/8, $krb5_cc_resolve_trampoline<>(SB)

TEXT krb5_cc_close_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_cc_close(SB)
GLOBL	·krb5CCCloseAddr(SB), RODATA, $8
DATA	·krb5CCCloseAddr(SB)/8, $krb5_cc_close_trampoline<>(SB)

TEXT krb5_cc_get_principal_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_cc_get_principal(SB)
GLOBL	·krb5CCGetPrincipalAddr(SB), RODATA, $8
DATA	·krb5CCGetPrincipalAddr(SB)/8, $krb5_cc_get_principal_trampoline<>(SB)

TEXT krb5_free_principal_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_free_principal(SB)
GLOBL	·krb5FreePrincipalAddr(SB), RODATA, $8
DATA	·krb5FreePrincipalAddr(SB)/8, $krb5_free_principal_trampoline<>(SB)

TEXT krb5_unparse_name_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_unparse_name(SB)
GLOBL	·krb5UnparseNameAddr(SB), RODATA, $8
DATA	·krb5UnparseNameAddr(SB)/8, $krb5_unparse_name_trampoline<>(SB)

TEXT krb5_free_unparsed_name_trampoline<>(SB),NOSPLIT,$0-0
	JMP	krb5_free_unparsed_name(SB)
GLOBL	·krb5FreeUnparsedNameAddr(SB), RODATA, $8
DATA	·krb5FreeUnparsedNameAddr(SB)/8, $krb5_free_unparsed_name_trampoline<>(SB)
