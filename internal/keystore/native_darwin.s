// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

#include "textflag.h"

TEXT sec_find_generic_password_trampoline<>(SB),NOSPLIT,$0-0
	JMP	SecKeychainFindGenericPassword(SB)
GLOBL	·secFindGenericPasswordAddr(SB), RODATA, $8
DATA	·secFindGenericPasswordAddr(SB)/8, $sec_find_generic_password_trampoline<>(SB)

TEXT sec_add_generic_password_trampoline<>(SB),NOSPLIT,$0-0
	JMP	SecKeychainAddGenericPassword(SB)
GLOBL	·secAddGenericPasswordAddr(SB), RODATA, $8
DATA	·secAddGenericPasswordAddr(SB)/8, $sec_add_generic_password_trampoline<>(SB)

TEXT sec_item_free_content_trampoline<>(SB),NOSPLIT,$0-0
	JMP	SecKeychainItemFreeContent(SB)
GLOBL	·secItemFreeContentAddr(SB), RODATA, $8
DATA	·secItemFreeContentAddr(SB)/8, $sec_item_free_content_trampoline<>(SB)
