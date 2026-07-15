# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Shared Authenticode evidence helpers for the native Windows builder and its
# post-install acceptance harness. Keep this file side-effect free: callers
# dot-source it under their own strict/error policy.

function Get-DefenseClawCertificateThumbprintSha256(
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-DefenseClawCertificateEvidence(
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
) {
    if ($null -eq $Certificate) { return $null }
    return [ordered]@{
        subject = [string]$Certificate.Subject
        issuer = [string]$Certificate.Issuer
        serial_number = ([string]$Certificate.SerialNumber).ToLowerInvariant()
        thumbprint_sha1 = ([string]$Certificate.Thumbprint).ToLowerInvariant()
        thumbprint_sha256 = Get-DefenseClawCertificateThumbprintSha256 $Certificate
        not_before_utc = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-DefenseClawCertificateChainEvidence(
    [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
) {
    if ($null -eq $Certificate) { return $null }
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        # Get-AuthenticodeSignature performs the platform trust decision. This
        # second build records a deterministic offline chain identity without a
        # release depending on transient revocation-network availability.
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $disableDownloads = $chain.ChainPolicy.PSObject.Properties['DisableCertificateDownloads']
        if ($null -eq $disableDownloads) {
            throw 'Offline Authenticode chain evidence requires a runtime with cache-only certificate-chain support.'
        }
        $chain.ChainPolicy.DisableCertificateDownloads = $true
        $built = $chain.Build($Certificate)
        $statuses = @($chain.ChainStatus | ForEach-Object { [string]$_.Status } | Sort-Object -Unique)
        $certificates = @($chain.ChainElements | ForEach-Object {
            Get-DefenseClawCertificateEvidence $_.Certificate
        })
        return [ordered]@{
            build_succeeded = [bool]$built
            statuses = $statuses
            certificates = $certificates
        }
    } finally {
        $chain.Dispose()
    }
}

function Test-DefenseClawPortableExecutable([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { return $false }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or ([long]$peOffset + 4) -gt $stream.Length) { return $false }
        $stream.Position = $peOffset
        return $reader.ReadUInt32() -eq 0x00004550
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Test-DefenseClawNormalizedRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path) -or
        $Path -notmatch '^[^\x00-\x1f\\/:*?"<>|]+(?:/[^\x00-\x1f\\/:*?"<>|]+)*$') {
        return $false
    }
    foreach ($segment in $Path.Split('/')) {
        if ($segment -in @('.', '..') -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
            return $false
        }
    }
    return $true
}

function Get-DefenseClawByteHash([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-DefenseClawEmbeddedAuthenticodeCms([string]$Path) {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 256 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) {
        throw "Authenticode CMS input is not a portable executable: $Path"
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -lt 0 -or ([long]$peOffset + 160) -gt $bytes.Length -or
        [BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
        throw "Authenticode CMS input has an invalid PE header: $Path"
    }
    $optionalHeader = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optionalHeader)
    $dataDirectories = switch ($magic) {
        0x10B { $optionalHeader + 96 }
        0x20B { $optionalHeader + 112 }
        default { throw "Authenticode CMS input has an unsupported PE optional header: $Path" }
    }
    # IMAGE_DIRECTORY_ENTRY_SECURITY is the fifth data directory. Unlike the
    # other directory entries, VirtualAddress is an absolute file offset.
    $certificateOffset = [long][BitConverter]::ToUInt32($bytes, $dataDirectories + 32)
    $certificateSize = [long][BitConverter]::ToUInt32($bytes, $dataDirectories + 36)
    if ($certificateOffset -eq 0 -and $certificateSize -eq 0) { return $null }
    if ($certificateOffset -lt 0 -or $certificateSize -lt 8 -or
        ($certificateOffset + $certificateSize) -gt $bytes.Length) {
        throw "Authenticode CMS input has an invalid certificate table: $Path"
    }

    $selectedCms = $null
    $cursor = $certificateOffset
    $end = $certificateOffset + $certificateSize
    while (($cursor + 8) -le $end) {
        $length = [long][BitConverter]::ToUInt32($bytes, [int]$cursor)
        $certificateType = [BitConverter]::ToUInt16($bytes, [int]$cursor + 6)
        if ($length -lt 8 -or ($cursor + $length) -gt $end) {
            throw "Authenticode CMS input has a malformed WIN_CERTIFICATE record: $Path"
        }
        if ($certificateType -eq 0x0002) {
            if ($null -ne $selectedCms) {
                throw "Authenticode CMS input has multiple PKCS#7 certificate-table records: $Path"
            }
            $encoded = [byte[]]::new($length - 8)
            [Array]::Copy($bytes, [int]$cursor + 8, $encoded, 0, $encoded.Length)
            $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
            try {
                $cms.Decode($encoded)
            } catch {
                throw "Authenticode CMS input contains invalid PKCS#7 data: $Path"
            }
            if ($cms.SignerInfos.Count -ne 1) {
                throw "Authenticode CMS input must contain exactly one primary signer: $Path"
            }
            $selectedCms = $cms
        }
        $cursor += (($length + 7) -band -8)
    }
    return $selectedCms
}

function Initialize-DefenseClawTimestampVerifier {
    if ('DefenseClaw.WindowsTimestampVerifier' -as [type]) { return }
    $source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DefenseClaw {
    public sealed class TimestampEvidence {
        public DateTime SigningTimeUtc { get; internal set; }
        public string HashAlgorithmOid { get; internal set; }
        public string MessageImprintHex { get; internal set; }
        public string PolicyOid { get; internal set; }
        public string SerialNumberHex { get; internal set; }
        public string TsaThumbprintSha256 { get; internal set; }
    }

    public static class WindowsTimestampVerifier {
        [StructLayout(LayoutKind.Sequential)]
        private struct Blob {
            internal uint Length;
            internal IntPtr Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AlgorithmIdentifier {
            internal IntPtr ObjectId;
            internal Blob Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TimestampContext {
            internal uint EncodedLength;
            internal IntPtr Encoded;
            internal IntPtr TimestampInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TimestampInfo {
            internal uint Version;
            internal IntPtr PolicyId;
            internal AlgorithmIdentifier HashAlgorithm;
            internal Blob HashedMessage;
            internal Blob SerialNumber;
            internal System.Runtime.InteropServices.ComTypes.FILETIME Time;
            internal IntPtr Accuracy;
            [MarshalAs(UnmanagedType.Bool)] internal bool Ordering;
            internal Blob Nonce;
            internal Blob Tsa;
            internal uint ExtensionCount;
            internal IntPtr Extensions;
        }

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptVerifyTimeStampSignature(
            [In] byte[] timestamp, uint timestampLength,
            [In] byte[] signedData, uint signedDataLength,
            IntPtr additionalStore,
            out IntPtr timestampContext,
            out IntPtr timestampSigner,
            out IntPtr certificateStore);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CryptMemFree(IntPtr buffer);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertFreeCertificateContext(IntPtr certificateContext);

        [DllImport("crypt32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertCloseStore(IntPtr certificateStore, uint flags);

        private static byte[] CopyBlob(Blob blob) {
            if (blob.Length > int.MaxValue || (blob.Length > 0 && blob.Data == IntPtr.Zero))
                throw new InvalidOperationException("Windows returned an invalid timestamp blob.");
            byte[] value = new byte[(int)blob.Length];
            if (value.Length > 0) Marshal.Copy(blob.Data, value, 0, value.Length);
            return value;
        }

        private static string Hex(byte[] value) {
            return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
        }

        private static string Sha256(byte[] value) {
            using (SHA256 hash = SHA256.Create()) return Hex(hash.ComputeHash(value));
        }

        public static TimestampEvidence Verify(byte[] timestamp, byte[] signedData) {
            if (timestamp == null || timestamp.Length == 0)
                throw new ArgumentException("RFC3161 timestamp token is empty.", "timestamp");
            if (signedData == null || signedData.Length == 0)
                throw new ArgumentException("Authenticode signature value is empty.", "signedData");

            IntPtr context = IntPtr.Zero;
            IntPtr signer = IntPtr.Zero;
            IntPtr store = IntPtr.Zero;
            try {
                if (!CryptVerifyTimeStampSignature(timestamp, (uint)timestamp.Length,
                        signedData, (uint)signedData.Length,
                        IntPtr.Zero, out context, out signer, out store))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "CryptVerifyTimeStampSignature rejected the Authenticode RFC3161 token.");
                if (context == IntPtr.Zero)
                    throw new InvalidOperationException("Windows returned no timestamp context.");
                TimestampContext timestampContext =
                    (TimestampContext)Marshal.PtrToStructure(context, typeof(TimestampContext));
                if (timestampContext.TimestampInfo == IntPtr.Zero)
                    throw new InvalidOperationException("Windows returned no timestamp information.");
                TimestampInfo info =
                    (TimestampInfo)Marshal.PtrToStructure(timestampContext.TimestampInfo, typeof(TimestampInfo));
                long fileTime = ((long)(uint)info.Time.dwHighDateTime << 32) |
                    (uint)info.Time.dwLowDateTime;
                string tsaThumbprintSha256 = "";
                if (signer != IntPtr.Zero) {
                    using (X509Certificate2 certificate = new X509Certificate2(signer))
                        tsaThumbprintSha256 = Sha256(certificate.RawData);
                }
                return new TimestampEvidence {
                    SigningTimeUtc = DateTime.FromFileTimeUtc(fileTime),
                    HashAlgorithmOid = Marshal.PtrToStringAnsi(info.HashAlgorithm.ObjectId) ?? "",
                    MessageImprintHex = Hex(CopyBlob(info.HashedMessage)),
                    PolicyOid = Marshal.PtrToStringAnsi(info.PolicyId) ?? "",
                    SerialNumberHex = Hex(CopyBlob(info.SerialNumber)),
                    TsaThumbprintSha256 = tsaThumbprintSha256
                };
            } finally {
                if (signer != IntPtr.Zero) CertFreeCertificateContext(signer);
                if (store != IntPtr.Zero) CertCloseStore(store, 0);
                if (context != IntPtr.Zero) CryptMemFree(context);
            }
        }
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        Add-Type -TypeDefinition $source -ReferencedAssemblies System.Security
    } else {
        Add-Type -TypeDefinition $source
    }
}

function Get-DefenseClawTimestampEvidence(
    [string]$Path,
    [Security.Cryptography.Pkcs.SignerInfo]$Signer
) {
    $attributes = @($Signer.UnsignedAttributes | Where-Object {
        $_.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1'
    })
    if ($attributes.Count -eq 0) { return $null }
    if ($attributes.Count -ne 1 -or $attributes[0].Values.Count -ne 1) {
        throw "Authenticode signer must contain at most one RFC3161 token: $Path"
    }
    $token = [byte[]]$attributes[0].Values[0].RawData
    Initialize-DefenseClawTimestampVerifier
    $verified = [DefenseClaw.WindowsTimestampVerifier]::Verify($token, $Signer.GetSignature())

    $timestampCms = [Security.Cryptography.Pkcs.SignedCms]::new()
    try {
        $timestampCms.Decode($token)
    } catch {
        throw "Authenticode RFC3161 token contains invalid CMS data: $Path"
    }
    if ($timestampCms.ContentInfo.ContentType.Value -ne '1.2.840.113549.1.9.16.1.4' -or
        $timestampCms.SignerInfos.Count -ne 1 -or $null -eq $timestampCms.SignerInfos[0].Certificate) {
        throw "Authenticode RFC3161 token has an invalid signer contract: $Path"
    }
    $tokenCertificate = $timestampCms.SignerInfos[0].Certificate
    $tokenThumbprint = Get-DefenseClawCertificateThumbprintSha256 $tokenCertificate
    if ($tokenThumbprint -cne [string]$verified.TsaThumbprintSha256) {
        throw "Windows CryptoAPI and the embedded RFC3161 CMS selected different timestamp signers: $Path"
    }
    return [ordered]@{
        present = $true
        format = 'rfc3161'
        token_sha256 = Get-DefenseClawByteHash $token
        signing_time_utc = $verified.SigningTimeUtc.ToUniversalTime().ToString('o')
        policy_oid = [string]$verified.PolicyOid
        message_imprint_algorithm_oid = [string]$verified.HashAlgorithmOid
        message_imprint = [string]$verified.MessageImprintHex
        serial_number = [string]$verified.SerialNumberHex
        certificate = Get-DefenseClawCertificateEvidence $tokenCertificate
        chain = Get-DefenseClawCertificateChainEvidence $tokenCertificate
    }
}

function Get-DefenseClawEmbeddedSignatureEvidence(
    [string]$Path,
    [Security.Cryptography.Pkcs.SignedCms]$Cms,
    [string]$Scope = 'top-level',
    [int]$Depth = 0
) {
    if ($Depth -gt 4) { throw "Authenticode nested-signature depth is excessive: $Path" }
    $result = @()
    for ($index = 0; $index -lt $Cms.SignerInfos.Count; $index++) {
        $signer = $Cms.SignerInfos[$index]
        if ($null -eq $signer.Certificate) {
            throw "Embedded Authenticode signer has no certificate: $Path"
        }
        try {
            # Validates the CMS signature over its SPC indirect-data content.
            # The enclosing PE is separately bound by the inventory SHA-256.
            $signer.CheckSignature($true)
        } catch {
            throw "Embedded Authenticode CMS signature validation failed: $Path"
        }
        $timestamp = Get-DefenseClawTimestampEvidence $Path $signer
        $publisher = $signer.Certificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        $result += [pscustomobject][ordered]@{
            scope = "$Scope/$index"
            depth = $Depth
            publisher = $publisher
            digest_algorithm_oid = [string]$signer.DigestAlgorithm.Value
            signature_algorithm_oid = [string]$signer.SignatureAlgorithm.Value
            signer = Get-DefenseClawCertificateEvidence $signer.Certificate
            chain = Get-DefenseClawCertificateChainEvidence $signer.Certificate
            timestamp = if ($null -ne $timestamp) { $timestamp } else {
                [ordered]@{
                    present = $false
                    format = ''
                    token_sha256 = ''
                    signing_time_utc = ''
                    policy_oid = ''
                    message_imprint_algorithm_oid = ''
                    message_imprint = ''
                    serial_number = ''
                    certificate = $null
                    chain = $null
                }
            }
        }

        $nested = @($signer.UnsignedAttributes | Where-Object {
            $_.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1'
        })
        foreach ($attribute in $nested) {
            for ($nestedIndex = 0; $nestedIndex -lt $attribute.Values.Count; $nestedIndex++) {
                $nestedCms = [Security.Cryptography.Pkcs.SignedCms]::new()
                try {
                    $nestedCms.Decode([byte[]]$attribute.Values[$nestedIndex].RawData)
                } catch {
                    throw "Embedded Authenticode nested signature contains invalid CMS data: $Path"
                }
                $result += @(Get-DefenseClawEmbeddedSignatureEvidence `
                    $Path $nestedCms "$Scope/$index/nested/$nestedIndex" ($Depth + 1))
            }
        }
    }
    return $result
}

function Get-DefenseClawAuthenticodeEvidence(
    [string]$Path,
    [string]$InstalledPath,
    [string]$SbomFileName,
    [string]$Policy = 'pinned-input-observation',
    [string]$ExpectedStatus = '',
    [AllowEmptyString()][string]$ExpectedPublisher = '',
    [AllowEmptyString()][string]$ExpectedSignatureType = '',
    [bool]$TimestampRequired = $false,
    [AllowEmptyString()][string]$ExpectedSignerThumbprintSha256 = '',
    [AllowEmptyString()][string]$ExpectedTimestampSignerThumbprintSha256 = '',
    [AllowEmptyString()][string]$ExpectedTimestampTokenSha256 = ''
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Authenticode evidence input is missing: $Path"
    }
    if (-not (Test-DefenseClawPortableExecutable $Path)) {
        throw "Authenticode evidence input is not a portable executable: $Path"
    }
    if (-not (Test-DefenseClawNormalizedRelativePath $InstalledPath)) {
        throw "Authenticode installed path is not a normalized relative path: $InstalledPath"
    }
    if ([string]::IsNullOrWhiteSpace($SbomFileName) -or -not $SbomFileName.StartsWith('./') -or
        -not (Test-DefenseClawNormalizedRelativePath $SbomFileName.Substring(2))) {
        throw "Authenticode SPDX file identity is invalid: $SbomFileName"
    }

    if ($Policy -notin @(
        'defenseclaw-product-publisher', 'pinned-input-observation', 'digest-only-upstream'
    )) {
        throw "Authenticode policy is unsupported: $Policy"
    }
    $pinPlatformIdentity = $Policy -ne 'pinned-input-observation'
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $status = [string]$signature.Status
    if ($status -notin @('Valid', 'NotSigned')) {
        throw "Authenticode input has an unacceptable signature state: path=$Path status=$status"
    }
    $publisher = if ($signature.SignerCertificate) {
        $signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    } else { '' }
    $signatureType = [string]$signature.SignatureType
    $timestampPresent = $null -ne $signature.TimeStamperCertificate
    $signerEvidence = Get-DefenseClawCertificateEvidence $signature.SignerCertificate
    $embeddedCms = Get-DefenseClawEmbeddedAuthenticodeCms $Path
    $embeddedSignatures = @(
        if ($null -ne $embeddedCms) {
            Get-DefenseClawEmbeddedSignatureEvidence $Path $embeddedCms
        }
    )
    $selectedEmbeddedSignature = $null
    if ($signatureType -eq 'Authenticode') {
        $platformSignerThumbprint = [string]$signerEvidence.thumbprint_sha256
        $matches = @($embeddedSignatures | Where-Object {
            [string]$_.signer.thumbprint_sha256 -ceq $platformSignerThumbprint
        })
        if ($matches.Count -ne 1) {
            throw "Windows selected Authenticode but no unique embedded signer matches it: $Path"
        }
        $selectedEmbeddedSignature = $matches[0]
    }
    $timestampEvidence = if ($timestampPresent -and $null -ne $selectedEmbeddedSignature) {
        $selectedTimestamp = $selectedEmbeddedSignature.timestamp
        if (-not [bool]$selectedTimestamp.present -or
            [string]$selectedTimestamp.certificate.thumbprint_sha256 -cne
                (Get-DefenseClawCertificateThumbprintSha256 $signature.TimeStamperCertificate)) {
            throw "Windows selected Authenticode but its embedded RFC3161 signer does not match: $Path"
        }
        $selectedTimestamp
    } elseif ($timestampPresent) {
        # Catalog signatures are external to the shipped PE. Record the
        # platform-selected certificate/chain separately; embedded signatures
        # (including dual signatures) remain fully inventoried below.
        [ordered]@{
            present = $true
            format = "platform-$($signatureType.ToLowerInvariant())"
            token_sha256 = ''
            signing_time_utc = ''
            policy_oid = ''
            message_imprint_algorithm_oid = ''
            message_imprint = ''
            serial_number = ''
            certificate = Get-DefenseClawCertificateEvidence $signature.TimeStamperCertificate
            chain = Get-DefenseClawCertificateChainEvidence $signature.TimeStamperCertificate
        }
    } else {
        [ordered]@{
            present = $false
            format = ''
            token_sha256 = ''
            signing_time_utc = ''
            policy_oid = ''
            message_imprint_algorithm_oid = ''
            message_imprint = ''
            serial_number = ''
            certificate = $null
            chain = $null
        }
    }

    if ([string]::IsNullOrWhiteSpace($ExpectedStatus)) {
        $ExpectedStatus = $status
        if ($pinPlatformIdentity) {
            $ExpectedPublisher = $publisher
            $ExpectedSignatureType = $signatureType
            $TimestampRequired = $timestampPresent
        } else {
            # Catalog availability is machine-local. Pinned upstream bytes
            # must remain Valid when signed, while their exact portable
            # embedded signatures below are the cross-machine identity.
            $ExpectedPublisher = ''
            $ExpectedSignatureType = ''
            $TimestampRequired = $false
        }
    }
    if ($ExpectedStatus -notin @('Valid', 'NotSigned')) {
        throw "Authenticode expected status is invalid: $ExpectedStatus"
    }
    if ($pinPlatformIdentity -and [string]::IsNullOrWhiteSpace($ExpectedSignatureType)) {
        $ExpectedSignatureType = $signatureType
    }
    if ($status -cne $ExpectedStatus -or ($pinPlatformIdentity -and
        ($publisher -cne $ExpectedPublisher -or $signatureType -cne $ExpectedSignatureType))) {
        throw "Authenticode policy mismatch for ${Path}: expected=$ExpectedStatus/$ExpectedPublisher/$ExpectedSignatureType observed=$status/$publisher/$signatureType"
    }
    if ($TimestampRequired -and -not $timestampPresent) {
        throw "Authenticode timestamp is required but absent: $Path"
    }
    if ($status -eq 'Valid' -and $null -eq $signature.SignerCertificate) {
        throw "Valid Authenticode input has no signer certificate: $Path"
    }
    if ($status -eq 'NotSigned' -and ($signature.SignerCertificate -or $timestampPresent)) {
        throw "Unsigned Authenticode input exposed unexpected certificate evidence: $Path"
    }
    if ($Policy -eq 'defenseclaw-product-publisher') {
        if (($status -eq 'Valid' -and $ExpectedPublisher -ne 'Cisco Systems, Inc.') -or
            ($status -eq 'NotSigned' -and $ExpectedPublisher)) {
            throw "DefenseClaw product publisher policy is invalid: $Path"
        }
        if ($status -eq 'Valid' -and ($signatureType -ne 'Authenticode' -or $embeddedSignatures.Count -ne 1)) {
            throw "Signed DefenseClaw products require exactly one embedded Authenticode signature: $Path"
        }
        if ($status -eq 'NotSigned' -and $signatureType -ne 'None') {
            throw "Unsigned local DefenseClaw products expose an unexpected signature type: $Path"
        }
    } elseif ($Policy -eq 'pinned-input-observation') {
        if ($status -eq 'Valid' -and $embeddedSignatures.Count -eq 0) {
            throw "Signed pinned input has no portable embedded signature: $Path"
        }
    } elseif ($status -ne 'NotSigned' -or $signatureType -ne 'None' -or $embeddedSignatures.Count -ne 0) {
        throw "Digest-only upstream policy requires an unsigned portable executable: $Path"
    }
    if ($ExpectedStatus -eq 'Valid' -and $pinPlatformIdentity) {
        $observedSignerThumbprint = [string]$signerEvidence.thumbprint_sha256
        if ([string]::IsNullOrWhiteSpace($ExpectedSignerThumbprintSha256)) {
            $ExpectedSignerThumbprintSha256 = $observedSignerThumbprint
        }
        if ($ExpectedSignerThumbprintSha256 -cne $observedSignerThumbprint) {
            throw "Authenticode signer thumbprint does not match policy: $Path"
        }
        if ($timestampPresent) {
            $observedTimestampSignerThumbprint = [string]$timestampEvidence.certificate.thumbprint_sha256
            if ([string]::IsNullOrWhiteSpace($ExpectedTimestampSignerThumbprintSha256)) {
                $ExpectedTimestampSignerThumbprintSha256 = $observedTimestampSignerThumbprint
            }
            if ([string]::IsNullOrWhiteSpace($ExpectedTimestampTokenSha256)) {
                $ExpectedTimestampTokenSha256 = [string]$timestampEvidence.token_sha256
            }
            if ($ExpectedTimestampSignerThumbprintSha256 -cne $observedTimestampSignerThumbprint -or
                $ExpectedTimestampTokenSha256 -cne [string]$timestampEvidence.token_sha256) {
                throw "Authenticode timestamp identity does not match policy: $Path"
            }
        }
    } else {
        if ($ExpectedSignerThumbprintSha256 -or $ExpectedTimestampSignerThumbprintSha256 -or
            $ExpectedTimestampTokenSha256) {
            throw "Unsigned Authenticode policy cannot declare signer or timestamp identities: $Path"
        }
    }

    return [ordered]@{
        schema_version = 1
        installed_path = $InstalledPath
        sbom_file_name = $SbomFileName
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        expected = [ordered]@{
            policy = $Policy
            status = $ExpectedStatus
            publisher = $ExpectedPublisher
            signature_type = $ExpectedSignatureType
            platform_identity_required = $pinPlatformIdentity
            timestamp_required = [bool]$TimestampRequired
            signer_thumbprint_sha256 = $ExpectedSignerThumbprintSha256
            timestamp_signer_thumbprint_sha256 = $ExpectedTimestampSignerThumbprintSha256
            timestamp_token_sha256 = $ExpectedTimestampTokenSha256
        }
        observed = [ordered]@{
            status = $status
            publisher = $publisher
            signature_type = $signatureType
            signer = $signerEvidence
            chain = Get-DefenseClawCertificateChainEvidence $signature.SignerCertificate
            timestamp = $timestampEvidence
            embedded_signatures = $embeddedSignatures
        }
    }
}

function Get-DefenseClawEvidenceCertificateIdentity([AllowNull()]$Certificate) {
    if ($null -eq $Certificate) { return '' }
    return @(
        [string]$Certificate.subject,
        [string]$Certificate.issuer,
        [string]$Certificate.serial_number,
        [string]$Certificate.thumbprint_sha1,
        [string]$Certificate.thumbprint_sha256
    ) -join '|'
}

function Get-DefenseClawEvidenceScalar([AllowNull()]$Value) {
    if ($null -eq $Value) { return '' }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('o') }
    return [string]$Value
}

function Get-DefenseClawEmbeddedSignatureIdentity([object]$Signature) {
    $timestamp = $Signature.timestamp
    return @(
        [string]$Signature.scope,
        [string]$Signature.depth,
        [string]$Signature.publisher,
        [string]$Signature.digest_algorithm_oid,
        [string]$Signature.signature_algorithm_oid,
        (Get-DefenseClawEvidenceCertificateIdentity $Signature.signer),
        (Get-DefenseClawEvidenceScalar $timestamp.present),
        (Get-DefenseClawEvidenceScalar $timestamp.format),
        (Get-DefenseClawEvidenceScalar $timestamp.token_sha256),
        (Get-DefenseClawEvidenceScalar $timestamp.signing_time_utc),
        (Get-DefenseClawEvidenceScalar $timestamp.policy_oid),
        (Get-DefenseClawEvidenceScalar $timestamp.message_imprint_algorithm_oid),
        (Get-DefenseClawEvidenceScalar $timestamp.message_imprint),
        (Get-DefenseClawEvidenceScalar $timestamp.serial_number),
        (Get-DefenseClawEvidenceCertificateIdentity $timestamp.certificate)
    ) -join '|'
}

function Assert-DefenseClawAuthenticodeEvidence([string]$Path, [object]$ExpectedEvidence) {
    if ($null -eq $ExpectedEvidence -or [int]$ExpectedEvidence.schema_version -ne 1) {
        throw "Authenticode evidence schema is missing or unsupported for $Path"
    }
    $platformIdentityRequired = [string]$ExpectedEvidence.expected.policy -ne 'pinned-input-observation'
    if ([bool]$ExpectedEvidence.expected.platform_identity_required -ne $platformIdentityRequired) {
        throw "Authenticode platform identity policy is internally inconsistent for $Path"
    }
    $actual = Get-DefenseClawAuthenticodeEvidence `
        -Path $Path `
        -InstalledPath ([string]$ExpectedEvidence.installed_path) `
        -SbomFileName ([string]$ExpectedEvidence.sbom_file_name) `
        -Policy ([string]$ExpectedEvidence.expected.policy) `
        -ExpectedStatus ([string]$ExpectedEvidence.expected.status) `
        -ExpectedPublisher ([string]$ExpectedEvidence.expected.publisher) `
        -ExpectedSignatureType ([string]$ExpectedEvidence.expected.signature_type) `
        -TimestampRequired ([bool]$ExpectedEvidence.expected.timestamp_required) `
        -ExpectedSignerThumbprintSha256 ([string]$ExpectedEvidence.expected.signer_thumbprint_sha256) `
        -ExpectedTimestampSignerThumbprintSha256 `
            ([string]$ExpectedEvidence.expected.timestamp_signer_thumbprint_sha256) `
        -ExpectedTimestampTokenSha256 ([string]$ExpectedEvidence.expected.timestamp_token_sha256)

    foreach ($field in @('sha256')) {
        if ([string]$actual.$field -cne [string]$ExpectedEvidence.$field) {
            throw "Authenticode evidence $field mismatch for $Path"
        }
    }
    $platformFields = if ($platformIdentityRequired) {
        @('status', 'publisher', 'signature_type')
    } else { @('status') }
    foreach ($field in $platformFields) {
        if ([string]$actual.observed.$field -cne [string]$ExpectedEvidence.observed.$field) {
            throw "Authenticode observed $field mismatch for $Path"
        }
    }
    if ($platformIdentityRequired -and
        (Get-DefenseClawEvidenceCertificateIdentity $actual.observed.signer) -cne
            (Get-DefenseClawEvidenceCertificateIdentity $ExpectedEvidence.observed.signer)) {
        throw "Authenticode signer certificate mismatch for $Path"
    }
    # Full chains are retained for provenance, but are deliberately not an
    # equality key: path building can select a different root/intermediate as
    # the Windows root store evolves. Get-AuthenticodeSignature above is the
    # current platform trust decision; stable leaf and RFC3161 identities are
    # compared exactly.
    if ($platformIdentityRequired) {
        foreach ($field in @(
            'present', 'format', 'token_sha256', 'signing_time_utc', 'policy_oid',
            'message_imprint_algorithm_oid', 'message_imprint', 'serial_number'
        )) {
            if ((Get-DefenseClawEvidenceScalar $actual.observed.timestamp.$field) -cne
                (Get-DefenseClawEvidenceScalar $ExpectedEvidence.observed.timestamp.$field)) {
                throw "Authenticode timestamp $field mismatch for $Path"
            }
        }
        if ((Get-DefenseClawEvidenceCertificateIdentity $actual.observed.timestamp.certificate) -cne
            (Get-DefenseClawEvidenceCertificateIdentity $ExpectedEvidence.observed.timestamp.certificate)) {
            throw "Authenticode timestamp signer mismatch for $Path"
        }
    }
    $actualEmbedded = @($actual.observed.embedded_signatures | Where-Object { $null -ne $_ })
    $expectedEmbedded = @($ExpectedEvidence.observed.embedded_signatures | Where-Object { $null -ne $_ })
    if ($actualEmbedded.Count -ne $expectedEmbedded.Count) {
        throw "Authenticode embedded signature count mismatch for $Path"
    }
    for ($index = 0; $index -lt $actualEmbedded.Count; $index++) {
        if ((Get-DefenseClawEmbeddedSignatureIdentity $actualEmbedded[$index]) -cne
            (Get-DefenseClawEmbeddedSignatureIdentity $expectedEmbedded[$index])) {
            throw "Authenticode embedded signature identity mismatch for $Path"
        }
    }
    return $actual
}

function Assert-DefenseClawInstalledAuthenticodeInventory([string]$InstallRoot, [object]$Inventory) {
    if ($null -eq $Inventory -or [int]$Inventory.schema_version -ne 1) {
        throw 'Installed Authenticode inventory schema is missing or unsupported.'
    }
    $properties = @($Inventory.files.PSObject.Properties)
    if ($properties.Count -eq 0) {
        throw 'Installed Authenticode inventory contains no portable executables.'
    }
    foreach ($property in $properties) {
        $evidence = $property.Value
        if ([string]$property.Name -cne [string]$evidence.installed_path) {
            throw "Authenticode inventory key/path mismatch: $($property.Name)"
        }
        $relative = ([string]$evidence.installed_path).Replace('/', '\')
        $target = [IO.Path]::GetFullPath((Join-Path $InstallRoot $relative))
        $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
        if (-not $target.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Authenticode installed path escapes the install root: $relative"
        }
        Assert-DefenseClawAuthenticodeEvidence $target $evidence | Out-Null
    }
}
