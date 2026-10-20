# Certificate store scanner. Port of src/scanners/cert_store.rs.
#
# Certificates are decoded with a small DER reader instead of
# X509Certificate2, so the strings match what the Rust scanner gets from
# `x509-parser` 0.16:
#   * subject/issuer use x509-parser's `Display` for X509Name: RDNs in DER
#     order joined with ", ", multi-valued RDNs joined with " + ", the
#     attribute abbreviations CN/C/L/ST/O/OU/DC/Email, otherwise the
#     oid-registry short name (e.g. "serialNumber"), otherwise "OID(1.2.3)";
#     string values are UTF-8/BMP decoded, any other type is upper-case hex.
#   * validity is the Unix timestamp of UTCTime/GeneralizedTime.
#   * the fingerprint is SHA-256 over exactly the bytes handed to the parser:
#     the full PEM block contents, or the whole file for DER fallback.
# PKCS#12 files are read with System.Security.Cryptography.Pkcs.Pkcs12Info,
# and the certificates are chosen the way the Rust `p12-keystore` crate
# chooses them (see Get-BoabPkcs12CertificateDers).
#
# The DER/X.509 helpers here are also used by Tls.ps1.

# ----------------------------------------------------------------------------
# Minimal DER reader
# ----------------------------------------------------------------------------

function Read-BoabDerHeader {
    <#
    .SYNOPSIS
    Decode one DER TLV header at -Offset. Returns @{ Class; Constructed; Tag;
    Start; ContentStart; Length; End }. Throws on malformed or truncated input.
    #>
    param([byte[]] $Bytes, [int] $Offset, [int] $Limit = -1)
    if ($Limit -lt 0) { $Limit = $Bytes.Length }
    if ($Offset -ge $Limit) { throw 'DER: unexpected end of data' }
    $first = [int]$Bytes[$Offset]
    $class = $first -shr 6
    $constructed = ($first -band 0x20) -ne 0
    $tag = $first -band 0x1f
    $i = $Offset + 1
    if ($tag -eq 0x1f) {
        $tag = 0
        do {
            if ($i -ge $Limit) { throw 'DER: truncated tag' }
            $b = [int]$Bytes[$i]; $i++
            $tag = ($tag * 128) + ($b -band 0x7f)
            if ($tag -gt 0x7fffffff) { throw 'DER: tag too large' }
        } while (($b -band 0x80) -ne 0)
    }
    if ($i -ge $Limit) { throw 'DER: truncated length' }
    $lb = [int]$Bytes[$i]; $i++
    [long]$len = 0
    if ($lb -lt 0x80) {
        $len = $lb
    }
    elseif ($lb -eq 0x80) {
        throw 'DER: indefinite length'
    }
    else {
        $n = $lb -band 0x7f
        if ($n -gt 4) { throw 'DER: length too large' }
        for ($k = 0; $k -lt $n; $k++) {
            if ($i -ge $Limit) { throw 'DER: truncated length' }
            $len = ($len * 256) + [int]$Bytes[$i]; $i++
        }
    }
    if ($i + $len -gt $Limit) { throw 'DER: content exceeds buffer' }
    return @{
        Class        = $class
        Constructed  = $constructed
        Tag          = $tag
        Start        = $Offset
        ContentStart = $i
        Length       = [int]$len
        End          = [int]($i + $len)
    }
}

function Get-BoabDerChildren {
    <# Decode the TLVs inside a constructed element. #>
    param([byte[]] $Bytes, $Header)
    $out = [System.Collections.Generic.List[object]]::new()
    $p = $Header.ContentStart
    while ($p -lt $Header.End) {
        $h = Read-BoabDerHeader -Bytes $Bytes -Offset $p -Limit $Header.End
        $out.Add($h)
        $p = $h.End
    }
    return , $out
}

function Get-BoabDerContent {
    param([byte[]] $Bytes, $Header)
    $c = [byte[]]::new($Header.Length)
    if ($Header.Length -gt 0) { [Array]::Copy($Bytes, $Header.ContentStart, $c, 0, $Header.Length) }
    return , $c
}

function Assert-BoabDerTag {
    param($Header, [int] $Class, [int] $Tag, [string] $What)
    if ($Header.Class -ne $Class -or $Header.Tag -ne $Tag) { throw "DER: expected $What" }
}

function ConvertFrom-BoabDerOid {
    <# Dotted-decimal form of OID content bytes (asn1-rs `to_id_string`). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([byte[]] $Content)
    if ($Content.Length -eq 0) { throw 'DER: empty OID' }
    $arcs = [System.Collections.Generic.List[string]]::new()
    $v = [System.Numerics.BigInteger]::Zero
    $first = $true
    for ($i = 0; $i -lt $Content.Length; $i++) {
        $b = [int]$Content[$i]
        $v = ($v * 128) + ($b -band 0x7f)
        if (($b -band 0x80) -eq 0) {
            if ($first) {
                if ($v -lt 40) { $arcs.Add('0'); $arcs.Add($v.ToString()) }
                elseif ($v -lt 80) { $arcs.Add('1'); $arcs.Add(($v - 40).ToString()) }
                else { $arcs.Add('2'); $arcs.Add(($v - 80).ToString()) }
                $first = $false
            }
            else {
                $arcs.Add($v.ToString())
            }
            $v = [System.Numerics.BigInteger]::Zero
        }
    }
    if (($Content[$Content.Length - 1] -band 0x80) -ne 0) { throw 'DER: truncated OID' }
    return ($arcs -join '.')
}

function Read-BoabDerOid {
    param([byte[]] $Bytes, $Header)
    Assert-BoabDerTag -Header $Header -Class 0 -Tag 6 -What 'OBJECT IDENTIFIER'
    return ConvertFrom-BoabDerOid -Content (Get-BoabDerContent -Bytes $Bytes -Header $Header)
}

# ----------------------------------------------------------------------------
# X.509 names (x509-parser Display)
# ----------------------------------------------------------------------------

function Get-BoabOidShortNameTable {
    <#
    .SYNOPSIS
    The oid-registry 0.7.1 short names that x509-parser 0.16 loads
    (with_all_crypto + with_x509 + id-mgf1).
    #>
    return @{
        '1.2.840.113549.1.1.1' = 'rsaEncryption'
        '1.2.840.113549.1.1.2' = 'md2WithRSAEncryption'
        '1.2.840.113549.1.1.3' = 'md4WithRSAEncryption'
        '1.2.840.113549.1.1.4' = 'md5WithRSAEncryption'
        '1.2.840.113549.1.1.5' = 'sha1WithRSAEncryption'
        '1.2.840.113549.1.1.10' = 'rsassa-pss'
        '1.2.840.113549.1.1.11' = 'sha256WithRSAEncryption'
        '1.2.840.113549.1.1.12' = 'sha384WithRSAEncryption'
        '1.2.840.113549.1.1.13' = 'sha512WithRSAEncryption'
        '1.2.840.113549.1.1.14' = 'sha224WithRSAEncryption'
        '1.2.840.10045.2.1' = 'id-ecPublicKey'
        '1.2.840.10045.4.3.1' = 'ecdsa-with-SHA224'
        '1.2.840.10045.4.3.2' = 'ecdsa-with-SHA256'
        '1.2.840.10045.4.3.3' = 'ecdsa-with-SHA384'
        '1.2.840.10045.4.3.4' = 'ecdsa-with-SHA512'
        '1.2.840.10045.3.1.7' = 'prime256v1'
        '1.3.133.16.840.63.0.2' = 'dhSinglePass-stdDH-sha1kdf-scheme'
        '1.3.132.0.34' = 'secp384r1'
        '1.3.132.0.35' = 'secp521r1'
        '1.3.14.3.2.25' = 'md5WithRSASignature'
        '1.3.14.3.2.26' = 'id-SHA1'
        '1.3.14.3.2.29' = 'sha1WithRSAEncryption'
        '2.16.840.1.101.3.4.1.42' = 'aes-256-cbc'
        '2.16.840.1.101.3.4.2.1' = 'sha256'
        '2.16.840.1.101.3.4.2.2' = 'sha384'
        '2.16.840.1.101.3.4.2.3' = 'sha512'
        '1.2.840.113549.1.7.1' = 'pkcs7-data'
        '1.2.840.113549.1.7.2' = 'pkcs7-signedData'
        '1.2.840.113549.1.7.3' = 'pkcs7-envelopedData'
        '1.2.840.113549.1.7.4' = 'pkcs7-signedAndEnvelopedData'
        '1.2.840.113549.1.7.5' = 'pkcs7-digestedData'
        '1.2.840.113549.1.7.6' = 'pkcs7-encryptedData'
        '1.2.840.113549.1.9.1' = 'emailAddress'
        '1.2.840.113549.1.9.2' = 'unstructuredName'
        '1.2.840.113549.1.9.3' = 'contentType'
        '1.2.840.113549.1.9.4' = 'id-messageDigest'
        '1.2.840.113549.1.9.5' = 'signing-time'
        '1.2.840.113549.1.9.7' = 'challengePassword'
        '1.2.840.113549.1.9.14' = 'extensionRequest'
        '1.2.840.113549.1.9.15' = 'smimeCapabilities'
        '1.2.840.113549.1.9.20' = 'friendlyName'
        '1.2.840.113549.1.12' = 'pkcs-12'
        '1.2.840.113549.1.12.1' = 'pkcs-12PbeIds'
        '1.2.840.113549.1.12.1.1' = 'pbeWithSHAAnd128BitRC4'
        '1.2.840.113549.1.12.1.2' = 'pbeWithSHAAnd40BitRC4'
        '1.2.840.113549.1.12.1.3' = 'pbeWithSHAAnd3-KeyTripleDES-CBC'
        '1.2.840.113549.1.12.1.4' = 'pbeWithSHAAnd2-KeyTripleDES-CBC'
        '1.2.840.113549.1.12.1.5' = 'pbeWithSHAAnd128BitRC2-CBC'
        '1.2.840.113549.1.12.1.6' = 'pbeWithSHAAnd40BitRC2-CBC'
        '0.9.2342.19200300.100.1.1' = 'uid'
        '0.9.2342.19200300.100.1.25' = 'domainComponent'
        '1.2.643.2.2.3' = 'id-GostR3411-94-with-GostR3410-2001'
        '1.2.643.2.2.19' = 'gostR3410-2001'
        '1.2.643.7.1.1.1.1' = 'gost3410-2012-256'
        '1.2.643.7.1.1.1.2' = 'gost3410-2012-512'
        '1.2.643.7.1.1.3.2' = 'id-tc26-signwithdigest-gost3410-12-256'
        '1.2.643.7.1.1.3.3' = 'id-tc26-signwithdigest-gost3410-12-512'
        '1.2.840.10040.4.1' = 'id-dsa'
        '1.2.840.10040.4.3' = 'dsa-with-sha1'
        '1.3.36.3.3.1.2' = 'rsaSignatureWithripemd160'
        '1.3.101.112' = 'ed25519'
        '1.3.101.113' = 'ed448'
        '1.3.6.1.4.1.311.60.2.1.1' = 'msJurisdictionLocality'
        '1.3.6.1.4.1.311.60.2.1.2' = 'msJurisdictionStateOrProvince'
        '1.3.6.1.4.1.311.60.2.1.3' = 'msJurisdictionCountry'
        '1.3.6.1.4.1.11129.2.4.2' = 'ctSCTList'
        '1.3.6.1.5.5.7.1.1' = 'authorityInfoAccess'
        '1.3.6.1.5.5.7.48.1' = 'id-ad-ocsp'
        '1.3.6.1.5.5.7.48.2' = 'id-ad-caIssuers'
        '1.3.6.1.5.5.7.48.3' = 'id-ad-timestamping'
        '1.3.6.1.5.5.7.48.4' = 'id-ad-dvcs'
        '1.3.6.1.5.5.7.48.5' = 'id-ad-caRepository'
        '1.3.6.1.5.5.7.48.6' = 'id-ad-http-certs'
        '1.3.6.1.5.5.7.48.7' = 'id-ad-http-crls'
        '1.3.6.1.5.5.7.48.10' = 'id-ad-rpki-manifest'
        '1.3.6.1.5.5.7.48.11' = 'id-ad-signed-object'
        '1.3.6.1.5.5.7.48.12' = 'id-ad-cmc'
        '1.3.6.1.5.5.7.48.13' = 'id-ad-rpki-notify'
        '1.3.6.1.5.5.7.48.14' = 'id-ad-stirTNList'
        '2.5.4' = 'x509'
        '2.5.4.0' = 'objectClass'
        '2.5.4.1' = 'aliasedEntryName'
        '2.5.4.2' = 'knowledgeInformation'
        '2.5.4.3' = 'commonName'
        '2.5.4.4' = 'surname'
        '2.5.4.5' = 'serialNumber'
        '2.5.4.6' = 'countryName'
        '2.5.4.7' = 'localityName'
        '2.5.4.8' = 'stateOrProvinceName'
        '2.5.4.9' = 'streetAddress'
        '2.5.4.10' = 'organizationName'
        '2.5.4.11' = 'organizationalUnit'
        '2.5.4.12' = 'title'
        '2.5.4.13' = 'description'
        '2.5.4.14' = 'searchGuide'
        '2.5.4.15' = 'businessCategory'
        '2.5.4.16' = 'postalAddress'
        '2.5.4.17' = 'postalCode'
        '2.5.4.41' = 'name'
        '2.5.4.42' = 'givenName'
        '2.5.4.43' = 'initials'
        '2.5.4.44' = 'generationQualifier'
        '2.5.4.45' = 'uniqueIdentifier'
        '2.5.4.46' = 'dnQualifier'
        '2.5.29.1' = 'oldAuthorityKeyIdentifier'
        '2.5.29.2' = 'oldKeyAttributes'
        '2.5.29.3' = 'oldCertificatePolicies'
        '2.5.29.4' = 'oldKeyUsage'
        '2.5.29.5' = 'oldPolicyMapping'
        '2.5.29.6' = 'oldSubtreesConstraint'
        '2.5.29.7' = 'oldSubjectAltNAme'
        '2.5.29.8' = 'oldIssuerAltNAme'
        '2.5.29.14' = 'subjectKeyIdentifier'
        '2.5.29.15' = 'keyUsage'
        '2.5.29.16' = 'privateKeyUsagePeriod'
        '2.5.29.17' = 'subjectAltName'
        '2.5.29.18' = 'issuerAltName'
        '2.5.29.19' = 'basicConstraints'
        '2.5.29.20' = 'crlNumber'
        '2.5.29.21' = 'reasonCode'
        '2.5.29.23' = 'holdInstructionCode'
        '2.5.29.24' = 'invalidityDate'
        '2.5.29.27' = 'deltaCRLIndicator'
        '2.5.29.28' = 'issuerDistributionPoint'
        '2.5.29.29' = 'issuer'
        '2.5.29.30' = 'nameConstraints'
        '2.5.29.31' = 'crlDistributionPoints'
        '2.5.29.32' = 'certificatePolicies'
        '2.5.29.33' = 'policyMappings'
        '2.5.29.35' = 'authorityKeyIdentifier'
        '2.5.29.36' = 'policyConstraints'
        '2.5.29.37' = 'extendedKeyUsage'
        '2.5.29.46' = 'freshestCRL'
        '2.5.29.54' = 'inhibitantAnyPolicy'
        '2.16.840.1.113730.1.1' = 'nsCertType'
        '2.16.840.1.113730.1.2' = 'nsBaseURL'
        '2.16.840.1.113730.1.3' = 'nsRevocationURL'
        '2.16.840.1.113730.1.4' = 'nsCARevocationURL'
        '2.16.840.1.113730.1.5' = 'nsCACRLURL'
        '2.16.840.1.113730.1.6' = 'nsCACertURL'
        '2.16.840.1.113730.1.7' = 'nsRenewalURL'
        '2.16.840.1.113730.1.8' = 'nsCAPolicyURL'
        '2.16.840.1.113730.1.9' = 'nsHomepageURL'
        '2.16.840.1.113730.1.10' = 'nsEntityLogo'
        '2.16.840.1.113730.1.11' = 'nsUserPicture'
        '2.16.840.1.113730.1.12' = 'nsSSLServerName'
        '2.16.840.1.113730.1.13' = 'nsComment'
        '1.2.840.113549.1.1.8' = 'id-mgf1'
    }
}

function Get-BoabX509AttributeAbbrev {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Oid)
    switch -CaseSensitive ($Oid) {
        '2.5.4.3' { return 'CN' }
        '2.5.4.6' { return 'C' }
        '2.5.4.7' { return 'L' }
        '2.5.4.8' { return 'ST' }
        '2.5.4.10' { return 'O' }
        '2.5.4.11' { return 'OU' }
        '0.9.2342.19200300.100.1.25' { return 'DC' }
        '1.2.840.113549.1.9.1' { return 'Email' }
    }
    if ($null -eq (Get-Variable -Name BoabOidShortNames -Scope Script -ValueOnly -ErrorAction Ignore)) {
        $script:BoabOidShortNames = Get-BoabOidShortNameTable
    }
    if ($script:BoabOidShortNames.ContainsKey($Oid)) { return $script:BoabOidShortNames[$Oid] }
    return "OID($Oid)"
}

function ConvertFrom-BoabX509AttributeValue {
    <# Port of x509-parser's attribute_value_to_string. Throws when a string value is not decodable. #>
    param([byte[]] $Bytes, $Header)
    $content = Get-BoabDerContent -Bytes $Bytes -Header $Header
    # Only the tag number is consulted (asn1-rs `Any::tag()`), not the class.
    switch ($Header.Tag) {
        { $_ -in 18, 26, 19, 27, 7, 25, 20, 21, 12, 22 } {
            return [System.Text.UTF8Encoding]::new($false, $true).GetString($content)
        }
        30 {
            # BMPString: UTF-16BE; an odd trailing byte is taken as a code unit.
            $units = [System.Text.StringBuilder]::new()
            for ($i = 0; $i -lt $content.Length; $i += 2) {
                if ($i + 1 -lt $content.Length) {
                    [void]$units.Append([char](([int]$content[$i] -shl 8) -bor [int]$content[$i + 1]))
                }
                else {
                    [void]$units.Append([char][int]$content[$i])
                }
            }
            $s = $units.ToString()
            # String::from_utf16 rejects unpaired surrogates.
            for ($i = 0; $i -lt $s.Length; $i++) {
                if ([char]::IsHighSurrogate($s[$i])) {
                    if ($i + 1 -ge $s.Length -or -not [char]::IsLowSurrogate($s[$i + 1])) { throw 'invalid BMPString' }
                    $i++
                }
                elseif ([char]::IsLowSurrogate($s[$i])) { throw 'invalid BMPString' }
            }
            return $s
        }
        default {
            return [System.Convert]::ToHexString($content)
        }
    }
}

function ConvertFrom-BoabX509Name {
    <#
    .SYNOPSIS
    x509-parser `X509Name` Display for the Name SEQUENCE described by -Header.
    Returns "<X509Error: Invalid X.509 name>" when a value can't be decoded,
    like the Rust Display impl. Throws for structurally invalid DER (which
    makes x509-parser reject the whole certificate).
    #>
    param([byte[]] $Bytes, $Header)
    Assert-BoabDerTag -Header $Header -Class 0 -Tag 16 -What 'Name SEQUENCE'
    $rdns = [System.Collections.Generic.List[object]]::new()
    foreach ($rdn in (Get-BoabDerChildren -Bytes $Bytes -Header $Header)) {
        Assert-BoabDerTag -Header $rdn -Class 0 -Tag 17 -What 'RDN SET'
        $atvs = Get-BoabDerChildren -Bytes $Bytes -Header $rdn
        if ($atvs.Count -eq 0) { throw 'DER: empty RDN' }
        $parsed = [System.Collections.Generic.List[object]]::new()
        foreach ($atv in $atvs) {
            Assert-BoabDerTag -Header $atv -Class 0 -Tag 16 -What 'AttributeTypeAndValue'
            $parts = Get-BoabDerChildren -Bytes $Bytes -Header $atv
            if ($parts.Count -lt 2) { throw 'DER: bad AttributeTypeAndValue' }
            $oid = Read-BoabDerOid -Bytes $Bytes -Header $parts[0]
            $parsed.Add(@{ Oid = $oid; Value = $parts[1] })
        }
        $rdns.Add($parsed)
    }
    try {
        $acc = ''
        foreach ($rdn in $rdns) {
            $acc2 = ''
            foreach ($attr in $rdn) {
                $val = ConvertFrom-BoabX509AttributeValue -Bytes $Bytes -Header $attr.Value
                $one = (Get-BoabX509AttributeAbbrev -Oid $attr.Oid) + '=' + $val
                if ($acc2.Length -eq 0) { $acc2 = $one } else { $acc2 = $acc2 + ' + ' + $one }
            }
            if ($acc.Length -eq 0) { $acc = $acc2 } else { $acc = $acc + ', ' + $acc2 }
        }
        return $acc
    }
    catch {
        return '<X509Error: Invalid X.509 name>'
    }
}

# ----------------------------------------------------------------------------
# Time
# ----------------------------------------------------------------------------

function ConvertFrom-BoabAsn1Time {
    <#
    .SYNOPSIS
    UTCTime / GeneralizedTime to a Unix timestamp (x509-parser ASN1Time ->
    OffsetDateTime::unix_timestamp). UTCTime years below 50 are 20xx.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param([byte[]] $Bytes, $Header)
    if ($Header.Class -ne 0 -or ($Header.Tag -ne 23 -and $Header.Tag -ne 24)) { throw 'invalid date' }
    $s = [System.Text.Encoding]::ASCII.GetString((Get-BoabDerContent -Bytes $Bytes -Header $Header))
    if ($Header.Tag -eq 23) {
        $m = [regex]::Match($s, '^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$')
        if (-not $m.Success) { throw 'invalid date' }
        $yy = [int]$m.Groups[1].Value
        $year = if ($yy -ge 50) { 1900 + $yy } else { 2000 + $yy }
        $mon = [int]$m.Groups[2].Value; $day = [int]$m.Groups[3].Value
        $hh = [int]$m.Groups[4].Value; $mi = [int]$m.Groups[5].Value
        $ss = if ($m.Groups[6].Success) { [int]$m.Groups[6].Value } else { 0 }
        $tz = $m.Groups[7].Value
    }
    else {
        $m = [regex]::Match($s, '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,]\d+)?(Z|[+-]\d{4})?$')
        if (-not $m.Success) { throw 'invalid date' }
        $year = [int]$m.Groups[1].Value
        $mon = [int]$m.Groups[2].Value; $day = [int]$m.Groups[3].Value
        $hh = [int]$m.Groups[4].Value
        $mi = if ($m.Groups[5].Success) { [int]$m.Groups[5].Value } else { 0 }
        $ss = if ($m.Groups[6].Success) { [int]$m.Groups[6].Value } else { 0 }
        $tz = if ($m.Groups[7].Success) { $m.Groups[7].Value } else { 'Z' }
    }
    $offset = [TimeSpan]::Zero
    if ($tz -ne 'Z') {
        $sign = if ($tz[0] -eq [char]'-') { -1 } else { 1 }
        $offset = [TimeSpan]::new($sign * [int]$tz.Substring(1, 2), $sign * [int]$tz.Substring(3, 2), 0)
    }
    $dto = [DateTimeOffset]::new($year, $mon, $day, $hh, $mi, $ss, $offset)
    return $dto.ToUnixTimeSeconds()
}

# ----------------------------------------------------------------------------
# Certificate decoding
# ----------------------------------------------------------------------------

function ConvertFrom-BoabX509Der {
    <#
    .SYNOPSIS
    Decode the certificate fields Boab needs. Trailing bytes after the
    certificate are ignored (like `X509Certificate::from_der`). Throws if the
    input is not a certificate.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [byte[]] $Der)
    $cert = Read-BoabDerHeader -Bytes $Der -Offset 0
    Assert-BoabDerTag -Header $cert -Class 0 -Tag 16 -What 'Certificate SEQUENCE'
    $top = Get-BoabDerChildren -Bytes $Der -Header $cert
    if ($top.Count -lt 3) { throw 'x509: bad Certificate' }
    $tbs = $top[0]
    Assert-BoabDerTag -Header $tbs -Class 0 -Tag 16 -What 'TBSCertificate'
    $outerAlg = $top[1]
    Assert-BoabDerTag -Header $outerAlg -Class 0 -Tag 16 -What 'AlgorithmIdentifier'
    Assert-BoabDerTag -Header $top[2] -Class 0 -Tag 3 -What 'signature BIT STRING'

    $f = Get-BoabDerChildren -Bytes $Der -Header $tbs
    $i = 0
    if ($f.Count -gt 0 -and $f[0].Class -eq 2 -and $f[0].Tag -eq 0) {
        $verChildren = Get-BoabDerChildren -Bytes $Der -Header $f[0]
        if ($verChildren.Count -ne 1) { throw 'x509: bad version' }
        Assert-BoabDerTag -Header $verChildren[0] -Class 0 -Tag 2 -What 'version INTEGER'
        $vb = Get-BoabDerContent -Bytes $Der -Header $verChildren[0]
        if ($vb.Length -ne 1 -or $vb[0] -ge 3) { throw 'x509: invalid version' }
        $i = 1
    }
    if ($f.Count -lt $i + 6) { throw 'x509: truncated TBSCertificate' }
    Assert-BoabDerTag -Header $f[$i] -Class 0 -Tag 2 -What 'serial INTEGER'
    Assert-BoabDerTag -Header $f[$i + 1] -Class 0 -Tag 16 -What 'signature AlgorithmIdentifier'
    $issuerHdr = $f[$i + 2]
    $validityHdr = $f[$i + 3]
    $subjectHdr = $f[$i + 4]
    $spkiHdr = $f[$i + 5]

    $issuer = ConvertFrom-BoabX509Name -Bytes $Der -Header $issuerHdr
    Assert-BoabDerTag -Header $validityHdr -Class 0 -Tag 16 -What 'Validity'
    $times = Get-BoabDerChildren -Bytes $Der -Header $validityHdr
    if ($times.Count -lt 2) { throw 'x509: bad Validity' }
    $notBefore = ConvertFrom-BoabAsn1Time -Bytes $Der -Header $times[0]
    $notAfter = ConvertFrom-BoabAsn1Time -Bytes $Der -Header $times[1]
    $subject = ConvertFrom-BoabX509Name -Bytes $Der -Header $subjectHdr

    Assert-BoabDerTag -Header $spkiHdr -Class 0 -Tag 16 -What 'SubjectPublicKeyInfo'
    $spki = Get-BoabDerChildren -Bytes $Der -Header $spkiHdr
    if ($spki.Count -lt 2) { throw 'x509: bad SubjectPublicKeyInfo' }
    Assert-BoabDerTag -Header $spki[0] -Class 0 -Tag 16 -What 'SPKI AlgorithmIdentifier'
    $pkAlg = Get-BoabDerChildren -Bytes $Der -Header $spki[0]
    if ($pkAlg.Count -lt 1) { throw 'x509: bad SPKI algorithm' }
    $pkOid = Read-BoabDerOid -Bytes $Der -Header $pkAlg[0]
    $pkParamOid = $null
    if ($pkAlg.Count -ge 2 -and $pkAlg[1].Class -eq 0 -and $pkAlg[1].Tag -eq 6) {
        $pkParamOid = Read-BoabDerOid -Bytes $Der -Header $pkAlg[1]
    }
    Assert-BoabDerTag -Header $spki[1] -Class 0 -Tag 3 -What 'subjectPublicKey BIT STRING'
    $bits = Get-BoabDerContent -Bytes $Der -Header $spki[1]
    if ($bits.Length -lt 1) { throw 'x509: empty BIT STRING' }
    $keyData = [byte[]]::new($bits.Length - 1)
    if ($keyData.Length -gt 0) { [Array]::Copy($bits, 1, $keyData, 0, $keyData.Length) }

    $outerAlgChildren = Get-BoabDerChildren -Bytes $Der -Header $outerAlg
    if ($outerAlgChildren.Count -lt 1) { throw 'x509: bad signatureAlgorithm' }
    $sigOid = Read-BoabDerOid -Bytes $Der -Header $outerAlgChildren[0]

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $fp = [System.Convert]::ToHexString($sha.ComputeHash($Der)).ToLowerInvariant() } finally { $sha.Dispose() }

    return [pscustomobject]@{
        Subject              = $subject
        Issuer               = $issuer
        SignatureOid         = $sigOid
        PublicKeyOid         = $pkOid
        PublicKeyParamOid    = $pkParamOid
        PublicKeyData        = $keyData
        NotBeforeUnix        = [long]$notBefore
        NotAfterUnix         = [long]$notAfter
        FingerprintSha256    = $fp
    }
}

function Get-BoabApproximateKeyBits {
    <#
    .SYNOPSIS
    Port of tls.rs `approximate_key_bits`: RSA modulus size the way
    x509-parser's `RSAPublicKey::key_size` computes it (8 * (len - 1) when the
    first modulus byte has its top bit clear, else 0), EC point
    ((len - 1) * 8 / 2), $null for anything else or on parse failure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Cert)
    $data = [byte[]]$Cert.PublicKeyData
    if ($Cert.PublicKeyOid -eq '1.2.840.113549.1.1.1') {
        try {
            $seq = Read-BoabDerHeader -Bytes $data -Offset 0
            Assert-BoabDerTag -Header $seq -Class 0 -Tag 16 -What 'RSAPublicKey'
            $parts = Get-BoabDerChildren -Bytes $data -Header $seq
            if ($parts.Count -lt 2) { return $null }
            Assert-BoabDerTag -Header $parts[0] -Class 0 -Tag 2 -What 'modulus'
            Assert-BoabDerTag -Header $parts[1] -Class 0 -Tag 2 -What 'exponent'
            $mod = Get-BoabDerContent -Bytes $data -Header $parts[0]
            if ($mod.Length -gt 0 -and ($mod[0] -band 0x80) -eq 0) {
                return [long](8 * ($mod.Length - 1))
            }
            return [long]0
        }
        catch {
            return $null
        }
    }
    if ($Cert.PublicKeyOid -eq '1.2.840.10045.2.1') {
        $n = [Math]::Max($data.Length - 1, 0)
        return [long][Math]::Floor(($n * 8) / 2)
    }
    return $null
}

function Get-BoabFriendlySignatureName {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Oid)
    switch -CaseSensitive ($Oid) {
        '1.2.840.113549.1.1.5' { return 'sha1WithRSAEncryption' }
        '1.2.840.113549.1.1.11' { return 'sha256WithRSAEncryption' }
        '1.2.840.113549.1.1.12' { return 'sha384WithRSAEncryption' }
        '1.2.840.113549.1.1.13' { return 'sha512WithRSAEncryption' }
        '1.2.840.10045.4.3.2' { return 'ecdsa-with-SHA256' }
        '1.2.840.10045.4.3.3' { return 'ecdsa-with-SHA384' }
        '1.2.840.10045.4.3.4' { return 'ecdsa-with-SHA512' }
        '1.3.101.112' { return 'Ed25519' }
        '1.3.101.113' { return 'Ed448' }
    }
    return $Oid
}

function Get-BoabFriendlyPublicKeyName {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Oid)
    switch -CaseSensitive ($Oid) {
        '1.2.840.113549.1.1.1' { return 'RSA' }
        '1.2.840.10045.2.1' { return 'EC' }
        '1.3.101.112' { return 'Ed25519' }
        '1.3.101.113' { return 'Ed448' }
    }
    return $Oid
}

function Get-BoabSignaturePqcStatus {
    <# Port of `pqc_status_for_sig_alg`. Returns the serde string. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Name)
    $lower = $Name.ToLowerInvariant()
    if ($lower.Contains('sha1')) { return 'vulnerable' }
    if ($lower.Contains('rsa') -or $lower.Contains('ecdsa') -or $lower.Contains('ed25519') -or $lower.Contains('ed448')) {
        return 'vulnerable'
    }
    if ($lower.Contains('mldsa') -or $lower.Contains('ml-dsa') -or $lower.Contains('slhdsa')) {
        return 'resistant'
    }
    return 'unknown'
}

# ----------------------------------------------------------------------------
# PEM
# ----------------------------------------------------------------------------

function Test-BoabStrictBase64 {
    <# data_encoding::BASE64 rules: padded, canonical trailing bits, no whitespace. #>
    param([string] $Text)
    if (($Text.Length % 4) -ne 0) { return $false }
    if (-not [regex]::IsMatch($Text, '^[A-Za-z0-9+/]*={0,2}$')) { return $false }
    if ($Text.Length -eq 0) { return $true }
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    if ($Text.EndsWith('==')) {
        $v = $alphabet.IndexOf($Text[$Text.Length - 3])
        return (($v -band 0x0f) -eq 0)
    }
    if ($Text.EndsWith('=')) {
        $v = $alphabet.IndexOf($Text[$Text.Length - 2])
        return (($v -band 0x03) -eq 0)
    }
    return $true
}

function Get-BoabPemBlocks {
    <#
    .SYNOPSIS
    Port of x509-parser's `Pem::iter_from_buffer` as cert_store.rs uses it:
    returns the decoded contents of each PEM block, stopping at the first
    invalid block (bad header, missing END line, invalid base64, invalid UTF-8).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    $blocks = [System.Collections.Generic.List[object]]::new()
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $n = $Bytes.Length
    $state = @{ Pos = 0 }
    # Returns the next line including its '\n', $null at EOF; throws on invalid UTF-8.
    $readLine = {
        if ($state.Pos -ge $n) { return $null }
        $start = $state.Pos
        $end = [Array]::IndexOf($Bytes, [byte]10, $start)
        if ($end -lt 0) { $end = $n - 1 }
        $state.Pos = $end + 1
        return $utf8.GetString($Bytes, $start, $end - $start + 1)
    }
    while ($state.Pos -lt $n) {
        try {
            # Find the BEGIN line.
            $found = $false
            while ($true) {
                $line = & $readLine
                if ($null -eq $line) { break }
                if ($line.StartsWith('-----BEGIN ', [System.StringComparison]::Ordinal)) { $found = $true; break }
            }
            if (-not $found) { break } # MissingHeader: end of iteration
            $v = $line.Split([string[]]@('-----'), [System.StringSplitOptions]::None)
            if ($v.Length -lt 3 -or $v[0].Length -ne 0) { break } # InvalidHeader
            $sb = [System.Text.StringBuilder]::new()
            $complete = $false
            while ($true) {
                $l = & $readLine
                if ($null -eq $l) { break }
                if ($l.StartsWith('-----END ', [System.StringComparison]::Ordinal)) { $complete = $true; break }
                [void]$sb.Append($l.TrimEnd())
            }
            if (-not $complete) { break } # IncompletePEM
            $b64 = $sb.ToString()
            if (-not (Test-BoabStrictBase64 -Text $b64)) { break } # Base64DecodeError
            $blocks.Add([System.Convert]::FromBase64String($b64))
        }
        catch {
            break # I/O error (invalid UTF-8 line)
        }
    }
    return , $blocks
}

# ----------------------------------------------------------------------------
# PKCS#12
# ----------------------------------------------------------------------------

function Get-BoabBagAttributeDer {
    <# DER of the first value of a bag attribute, or $null (p12-keystore get_bag_attribute). #>
    param($Bag, [string] $Oid)
    foreach ($attr in $Bag.Attributes) {
        if ($attr.Oid.Value -eq $Oid) {
            foreach ($val in $attr.Values) { return , ([byte[]]$val.RawData) }
            return $null
        }
    }
    return $null
}

function Get-BoabPkcs12CertificateDers {
    <#
    .SYNOPSIS
    Certificates from a PKCS#12 file, chosen and ordered like Rust
    `p12_keystore::KeyStore::from_pkcs12` + `entries()`:
      * the MAC (if any) must verify with the password ('' when none given);
      * every PKCS#8 shrouded key bag with a localKeyId becomes an entry whose
        chain is the certificate with the same localKeyId, followed by issuers
        found by matching subject/issuer strings (not counting certs marked as
        Java "trusted"), stopping at a self-signed issuer;
      * certificates with no localKeyId that carry the Oracle trusted-key-usage
        attribute (Java truststores) become single-cert entries;
      * entries are keyed by friendlyName (else the subject string) and come
        out in ordinal key order; later entries with the same key replace
        earlier ones.
    A certificate-only PKCS#12 without the Oracle attribute therefore yields
    nothing, as in Rust. Throws on any parse or password error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [byte[]] $Bytes,
        [AllowNull()] [string] $Password
    )
    if ($null -eq $Password) { $Password = '' }
    $pkcs12InfoType = 'System.Security.Cryptography.Pkcs.Pkcs12Info' -as [type]
    if ($null -eq $pkcs12InfoType) {
        # Fallback without bag-level access: every certificate in file order.
        $coll = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $coll.Import($Bytes, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $coll) { $list.Add([byte[]]$c.RawData) }
        return , $list
    }

    $consumed = 0
    $info = $pkcs12InfoType::Decode([System.ReadOnlyMemory[byte]]::new($Bytes), [ref]$consumed, $false)
    if ($info.IntegrityMode -eq [System.Security.Cryptography.Pkcs.Pkcs12IntegrityMode]::Password) {
        if (-not $info.VerifyMac($Password)) { throw 'PKCS12 MAC verification failed' }
    }

    $keys = [System.Collections.Generic.List[object]]::new()
    $certs = [System.Collections.Generic.List[object]]::new()
    foreach ($sc in $info.AuthenticatedSafe) {
        switch ($sc.ConfidentialityMode) {
            ([System.Security.Cryptography.Pkcs.Pkcs12ConfidentialityMode]::None) { }
            ([System.Security.Cryptography.Pkcs.Pkcs12ConfidentialityMode]::Password) { $sc.Decrypt($Password) }
            default { throw 'PKCS12: unsupported content type' }
        }
        foreach ($bag in $sc.GetBags()) {
            $localKeyId = $null
            $lk = Get-BoabBagAttributeDer -Bag $bag -Oid '1.2.840.113549.1.9.21'
            if ($null -ne $lk) {
                try {
                    $h = Read-BoabDerHeader -Bytes $lk -Offset 0
                    if ($h.Class -eq 0 -and $h.Tag -eq 4) { $localKeyId = [System.Convert]::ToHexString((Get-BoabDerContent -Bytes $lk -Header $h)) }
                }
                catch { $localKeyId = $null }
            }
            $friendly = $null
            $fn = Get-BoabBagAttributeDer -Bag $bag -Oid '1.2.840.113549.1.9.20'
            if ($null -ne $fn) {
                try {
                    $h = Read-BoabDerHeader -Bytes $fn -Offset 0
                    if ($h.Class -eq 0 -and $h.Tag -eq 30) { $friendly = ConvertFrom-BoabX509AttributeValue -Bytes $fn -Header $h }
                }
                catch { $friendly = $null }
            }
            $trusted = $false
            $tr = Get-BoabBagAttributeDer -Bag $bag -Oid '2.16.840.1.113894.746875.1.1'
            if ($null -ne $tr) {
                try {
                    $h = Read-BoabDerHeader -Bytes $tr -Offset 0
                    $trusted = (Read-BoabDerOid -Bytes $tr -Header $h) -eq '2.5.29.37.0'
                }
                catch { $trusted = $false }
            }

            if ($bag -is [System.Security.Cryptography.Pkcs.Pkcs12CertBag]) {
                if (-not $bag.IsX509Certificate) { throw 'PKCS12: unsupported certificate type' }
                $der = [byte[]]$bag.GetCertificate().RawData
                $parsed = ConvertFrom-BoabX509Der -Der $der
                $certs.Add([pscustomobject]@{
                        Der        = $der
                        Subject    = $parsed.Subject
                        Issuer     = $parsed.Issuer
                        LocalKeyId = $localKeyId
                        Friendly   = $friendly
                        Trusted    = $trusted
                    })
            }
            elseif ($bag -is [System.Security.Cryptography.Pkcs.Pkcs12ShroudedKeyBag]) {
                if ($null -ne $localKeyId) {
                    $keys.Add([pscustomobject]@{ LocalKeyId = $localKeyId; Friendly = $friendly })
                }
            }
        }
    }

    $entries = [System.Collections.Generic.SortedDictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($key in $keys) {
        $entry = $null
        foreach ($c in $certs) { if ($null -ne $c.LocalKeyId -and $c.LocalKeyId -eq $key.LocalKeyId) { $entry = $c; break } }
        if ($null -eq $entry) { continue }
        $alias = if ($null -ne $key.Friendly) { $key.Friendly } else { $entry.Subject }
        $chain = [System.Collections.Generic.List[object]]::new()
        $chain.Add($entry.Der)
        $leafSubject = $entry.Subject
        for ($guard = 0; $guard -lt 64; $guard++) {
            $issuer = $null
            foreach ($c in $certs) { if ($c.Subject -ceq $entry.Issuer -and -not $c.Trusted) { $issuer = $c; break } }
            if ($null -eq $issuer) { break }
            if ($issuer.Subject -cne $leafSubject) { $chain.Add($issuer.Der) }
            if ($issuer.Issuer -ceq $issuer.Subject) { break }
            $entry = $issuer
        }
        $entries[$alias] = $chain
    }
    foreach ($c in $certs) {
        if ($null -eq $c.LocalKeyId -and $c.Trusted) {
            $alias = if ($null -ne $c.Friendly) { $c.Friendly } else { $c.Subject }
            $one = [System.Collections.Generic.List[object]]::new()
            $one.Add($c.Der)
            $entries[$alias] = $one
        }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($kv in $entries.GetEnumerator()) {
        foreach ($d in $kv.Value) { $out.Add($d) }
    }
    return , $out
}

# ----------------------------------------------------------------------------
# Certificate store scanner
# ----------------------------------------------------------------------------

function New-BoabCertStoreFinding {
    <# Port of cert_store.rs `finding_from_der`. Throws if -Der is not a certificate. #>
    param([string] $ScanId, [string] $FileDisplay, [byte[]] $Der)
    $c = ConvertFrom-BoabX509Der -Der $Der
    $sigName = Get-BoabFriendlySignatureName -Oid $c.SignatureOid
    $pkName = Get-BoabFriendlyPublicKeyName -Oid $c.PublicKeyOid
    $evidence = [ordered]@{
        kind                     = 'tls_certificate'
        target                   = $FileDisplay
        subject                  = $c.Subject
        issuer                   = $c.Issuer
        signature_algorithm      = $sigName
        signature_algorithm_oid  = $c.SignatureOid
        public_key_algorithm     = $pkName
        public_key_algorithm_oid = $c.PublicKeyOid
        not_before_unix          = [long]$c.NotBeforeUnix
        not_after_unix           = [long]$c.NotAfterUnix
        fingerprint_sha256       = $c.FingerprintSha256
        pqc_status               = Get-BoabSignaturePqcStatus -Name $sigName
    }
    return New-BoabFinding -ScanId $ScanId -SourceType 'cert_subject' -SourceLocation "$FileDisplay|$($c.Subject)" -Evidence $evidence -Confidence 'high'
}

function New-BoabKeystorePlaceholder {
    param([string] $ScanId, [string] $FileDisplay, [string] $Kind)
    $evidence = [ordered]@{
        kind       = 'cert_or_keystore_file'
        store_type = $Kind
    }
    return New-BoabFinding -ScanId $ScanId -SourceType 'file' -SourceLocation $FileDisplay -Evidence $evidence -Confidence 'low'
}

function Get-BoabCertFileFindings {
    <# Port of `parse_cert_file`. Throws on unreadable or unparseable files (the caller skips them). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ScanId,
        [Parameter(Mandatory)] [string] $File,
        [Parameter(Mandatory)] [string] $Extension,
        [AllowNull()] [string] $Password
    )
    $display = Get-BoabPathDisplay -Path $File
    $out = [System.Collections.Generic.List[object]]::new()
    $bytes = [System.IO.File]::ReadAllBytes($File)
    switch -CaseSensitive ($Extension) {
        { $_ -in 'pem', 'crt', 'cer', 'p7b' } {
            foreach ($block in (Get-BoabPemBlocks -Bytes $bytes)) {
                try { $out.Add((New-BoabCertStoreFinding -ScanId $ScanId -FileDisplay $display -Der $block)) } catch { $null = $_ }
            }
            if ($out.Count -eq 0) {
                # Best effort: try the whole file as DER.
                try { $out.Add((New-BoabCertStoreFinding -ScanId $ScanId -FileDisplay $display -Der $bytes)) } catch { $null = $_ }
            }
            break
        }
        'der' {
            $out.Add((New-BoabCertStoreFinding -ScanId $ScanId -FileDisplay $display -Der $bytes))
            break
        }
        { $_ -in 'p12', 'pfx' } {
            foreach ($der in (Get-BoabPkcs12CertificateDers -Bytes $bytes -Password $Password)) {
                try { $out.Add((New-BoabCertStoreFinding -ScanId $ScanId -FileDisplay $display -Der $der)) } catch { $null = $_ }
            }
            break
        }
        'jks' {
            $out.Add((New-BoabKeystorePlaceholder -ScanId $ScanId -FileDisplay $display -Kind 'JKS (convert to PKCS12 with keytool for full parsing)'))
            break
        }
    }
    return , $out
}

function Invoke-BoabCertStoreScan {
    <#
    .SYNOPSIS
    Scan a directory (or single file) for certificates and keystores. Port of
    `boab::scanners::cert_store::scan_path`.
    .DESCRIPTION
    Returns one Scan. Looks at *.pem, *.crt, *.cer, *.der, *.p7b, *.p12, *.pfx and *.jks
    (case-insensitive extension), skipping hidden entries. `.gitignore` files
    are not honoured; `.ignore` files, `.git/info/exclude` and the global git
    excludes file are (as with the Rust WalkBuilder settings).
    .PARAMETER PasswordFile
    File whose trimmed contents are the PKCS#12 password (CertStoreOptions.password_file).
    .PARAMETER Name
    Scan name. Defaults to "certs:<canonical path>".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $Path,
        [string] $PasswordFile,
        [string] $Name
    )
    try {
        $root = Resolve-BoabCanonicalPath -Path $Path
    }
    catch {
        throw "could not resolve cert store path ${Path}: $($_.Exception.Message)"
    }
    $display = Get-BoabPathDisplay -Path $root
    $scanName = if ($PSBoundParameters.ContainsKey('Name') -and $null -ne $Name) { $Name } else { "certs:$display" }
    $scan = New-BoabScan -Name $scanName -ScanType 'certificate_store' -Target $display
    $scan.status = 'running'
    $hasPasswordFile = $PSBoundParameters.ContainsKey('PasswordFile') -and -not [string]::IsNullOrEmpty($PasswordFile)
    $scan.config = [ordered]@{
        password_provided = [bool]$hasPasswordFile
    }

    $password = $null
    if ($hasPasswordFile) {
        try {
            $raw = [System.Text.UTF8Encoding]::new($false, $true).GetString([System.IO.File]::ReadAllBytes($PasswordFile))
        }
        catch {
            throw "read ${PasswordFile}: $($_.Exception.Message)"
        }
        $password = $raw.Trim()
    }

    $options = @{
        Hidden     = $true
        DotIgnore  = $true
        GitIgnore  = $false
        GitExclude = $true
        GitGlobal  = $true
        Parents    = $true
        Overrides  = $null
    }
    $supported = @('pem', 'crt', 'cer', 'der', 'p7b', 'p12', 'pfx', 'jks')
    foreach ($file in (Get-BoabWalkFiles -Root $root -Options $options)) {
        $ext = Get-BoabPathExtension -Path $file
        if ($null -eq $ext) { continue }
        $ext = $ext.ToLowerInvariant()
        if ($supported -cnotcontains $ext) { continue }
        try {
            $found = Get-BoabCertFileFindings -ScanId $scan.id -File $file -Extension $ext -Password $password
            $scan.findings.AddRange($found)
        }
        catch {
            Write-Debug "skip ${file}: $($_.Exception.Message)"
        }
    }

    $scan.status = 'completed'
    $scan.completed_at = Get-BoabUtcNow
    return $scan
}
