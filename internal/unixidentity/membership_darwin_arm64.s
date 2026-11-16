// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

#include "textflag.h"

// Trampolines to the libSystem functions membership_darwin.go imports
// (golang.org/x/sys/unix uses the same form).

TEXT libc_mbr_uid_to_uuid_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mbr_uid_to_uuid(SB)
GLOBL	·mbrUIDToUUIDTrampolineAddr(SB), RODATA, $8
DATA	·mbrUIDToUUIDTrampolineAddr(SB)/8, $libc_mbr_uid_to_uuid_trampoline<>(SB)

TEXT libc_mbr_gid_to_uuid_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mbr_gid_to_uuid(SB)
GLOBL	·mbrGIDToUUIDTrampolineAddr(SB), RODATA, $8
DATA	·mbrGIDToUUIDTrampolineAddr(SB)/8, $libc_mbr_gid_to_uuid_trampoline<>(SB)

TEXT libc_mbr_check_membership_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mbr_check_membership(SB)
GLOBL	·mbrCheckMembershipTrampolineAddr(SB), RODATA, $8
DATA	·mbrCheckMembershipTrampolineAddr(SB)/8, $libc_mbr_check_membership_trampoline<>(SB)
