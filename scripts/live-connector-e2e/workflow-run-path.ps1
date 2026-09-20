# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

function Test-CanonicalWindowsWorkflowRunPath([AllowEmptyString()][string]$Path) {
    $expectedPath = '.github/workflows/windows-native.yml'
    $maximumReferenceLength = 4096
    $maximumComponentLength = 255
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    if ($Path.Length -gt $expectedPath.Length + 1 + $maximumReferenceLength) {
        return $false
    }

    $separator = $Path.IndexOf('@')
    if ($separator -lt 0) { return $Path -ceq $expectedPath }

    $pathComponent = $Path.Substring(0, $separator)
    $reference = $Path.Substring($separator + 1)
    if ($pathComponent -cne $expectedPath -or
        [string]::IsNullOrEmpty($reference) -or
        $reference.Length -gt $maximumReferenceLength -or
        $reference -ceq '@') {
        return $false
    }
    if ($reference -match '[\x00-\x20\x7f~^:?*\[\\]' -or
        $reference.StartsWith('/') -or $reference.EndsWith('/') -or
        $reference.EndsWith('.') -or $reference.Contains('//') -or
        $reference.Contains('..') -or $reference.Contains('@{')) {
        return $false
    }
    foreach ($component in $reference.Split('/')) {
        if ($component.Length -gt $maximumComponentLength -or
            $component.StartsWith('.') -or
            $component.EndsWith('.lock', [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}
