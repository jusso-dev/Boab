# TLS endpoint scanner. Port of src/scanners/tls.rs.
#
# The Rust scanner connects with rustls 0.23 (ring provider) and webpki-roots.
# .NET's SslStream can't report the negotiated cipher suite reliably on every
# platform, can't report the key-exchange group, and on macOS can't do TLS 1.3.
# So this port runs its own minimal TLS client over TcpClient:
#   * it sends a ClientHello with the cipher suites rustls/ring offers, in the
#     same order (TLS 1.3: AES-256-GCM, AES-128-GCM, CHACHA20; TLS 1.2:
#     ECDHE-ECDSA then ECDHE-RSA with AES-256-GCM, AES-128-GCM, CHACHA20),
#     the same groups (x25519, secp256r1, secp384r1) with an x25519 key share,
#     and the same signature schemes;
#   * it parses the ServerHello (version, cipher suite, key_share group) and
#     follows a HelloRetryRequest;
#   * TLS 1.2: it reads the plaintext Certificate message;
#     TLS 1.3: it does the (EC)DHE exchange (pure-PowerShell X25519, or .NET
#     ECDiffieHellman for P-256/P-384 after a retry), derives the handshake
#     keys (HKDF), decrypts EncryptedExtensions/Certificate, and reads the chain;
#   * it validates the chain roughly the way webpki does (see
#     Test-BoabTlsServerCertificate) so that hosts rustls rejects (expired,
#     self-signed, wrong name, SHA-1 or RSA < 2048 in the chain) also fail here.
# Once the certificate chain is in hand the client hangs up. It does not
# verify CertificateVerify or Finished, and it does not finish the handshake.
#
# Evidence and error strings match the Rust output. See the parity notes in
# Invoke-BoabTlsScan.

# ----------------------------------------------------------------------------
# Tables
# ----------------------------------------------------------------------------

function Get-BoabTlsGroupName {
    <# Port of `group_name`: TLS supported-group codepoint -> name. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [int] $Codepoint)
    switch ($Codepoint) {
        0x0017 { return 'secp256r1' }
        0x0018 { return 'secp384r1' }
        0x0019 { return 'secp521r1' }
        0x001D { return 'x25519' }
        0x001E { return 'x448' }
        0x0100 { return 'ffdhe2048' }
        0x0101 { return 'ffdhe3072' }
        0x0102 { return 'ffdhe4096' }
        0x11EC { return 'X25519MLKEM768' }
        0x6399 { return 'X25519Kyber768Draft00' }
    }
    return 'unknown'
}

function Test-BoabTlsHybridGroup {
    <# Port of `is_hybrid_group`. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [int] $Codepoint)
    return ($Codepoint -eq 0x11EC -or $Codepoint -eq 0x6399)
}

function Get-BoabTlsCipherSuiteName {
    <# rustls `CipherSuite` Debug names. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [int] $Code)
    switch ($Code) {
        0x1301 { return 'TLS13_AES_128_GCM_SHA256' }
        0x1302 { return 'TLS13_AES_256_GCM_SHA384' }
        0x1303 { return 'TLS13_CHACHA20_POLY1305_SHA256' }
        0xC02B { return 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' }
        0xC02C { return 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384' }
        0xCCA9 { return 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256' }
        0xC02F { return 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' }
        0xC030 { return 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }
        0xCCA8 { return 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256' }
    }
    return ('Unknown(0x{0:x4})' -f $Code)
}

# rustls 0.23 / ring offer order.
function Get-BoabTls13Suites { return , [int[]]@(0x1302, 0x1301, 0x1303) }
function Get-BoabTls12Suites { return , [int[]]@(0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8) }
function Get-BoabTlsOfferedGroups { return , [int[]]@(0x001D, 0x0017, 0x0018) }
function Get-BoabTlsSignatureSchemes { return , [int[]]@(0x0503, 0x0403, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401) }

# ----------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------

function ConvertFrom-BoabRateLimit {
    <#
    .SYNOPSIS
    Port of `parse_rate_limit`: "N/second|sec|s" or "N/minute|min" -> TimeSpan
    (integer milliseconds, like Rust), $null otherwise or when N is 0.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)
    $idx = $Value.IndexOf([char]'/')
    if ($idx -lt 0) { return $null }
    $nText = $Value.Substring(0, $idx).Trim()
    $unit = $Value.Substring($idx + 1).Trim()
    if ($nText -notmatch '^\+?[0-9]+$') { return $null }
    [System.Numerics.BigInteger]$big = [System.Numerics.BigInteger]::Parse($nText.TrimStart('+'))
    if ($big -gt [System.Numerics.BigInteger][UInt64]::MaxValue) { return $null }
    [UInt64]$n = [UInt64]$big
    if ($n -eq 0) { return $null }
    switch -CaseSensitive ($unit) {
        { $_ -in 'second', 'sec', 's' } { return [TimeSpan]::FromMilliseconds([Math]::Floor(1000 / $n)) }
        { $_ -in 'minute', 'min' } { return [TimeSpan]::FromMilliseconds([Math]::Floor(60000 / $n)) }
    }
    return $null
}

function Split-BoabTlsTarget {
    <#
    .SYNOPSIS
    Port of `parse_target`: split on the last ':' and parse a u16 port. Returns
    @(host, port). Throws with the Rust error text.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Target)
    $idx = $Target.LastIndexOf([char]':')
    if ($idx -lt 0) { throw "target must be host:port, got $Target" }
    $hostPart = $Target.Substring(0, $idx)
    $portText = $Target.Substring($idx + 1)
    if ($portText -notmatch '^\+?[0-9]+$') { throw "invalid port in target $Target" }
    $digits = $portText.TrimStart('+')
    if ($digits.Length -gt 5 -or [int]$digits -gt 65535) { throw "invalid port in target $Target" }
    return @($hostPart, [int]$digits)
}

function Test-BoabDnsName {
    <# rustls-pki-types DnsName validation. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()] [string] $Name)
    if ($Name.Length -eq 0 -or $Name.Length -gt 253) { return $false }
    $start = 0
    $state = 'Start'
    $idx = 0
    while ($true) {
        $ch = if ($idx -lt $Name.Length) { [int]$Name[$idx] } else { -1 }
        if (($ch -ge 0x61 -and $ch -le 0x7a) -or ($ch -ge 0x41 -and $ch -le 0x5a) -or $ch -eq 0x5f) {
            $state = 'HasLetter'
        }
        elseif ($ch -ge 0x30 -and $ch -le 0x39) {
            if ($state -eq 'Start' -or $state -eq 'AllNumeric') { $state = 'AllNumeric' } else { $state = 'HasLetter' }
        }
        elseif ($ch -eq 0x2e -or $ch -eq -1) {
            $len = $idx - $start
            if ($len -eq 0 -or $len -gt 63 -or $state -eq 'EndsInHyphen') { return $false }
            if ($idx + 1 -ge $Name.Length) { break }
            $idx++
            $start = $idx
            $state = 'Start'
            continue
        }
        elseif ($ch -eq 0x2d) {
            if ($idx -eq $start) { return $false }
            $state = 'EndsInHyphen'
        }
        else {
            return $false
        }
        $idx++
    }
    return ($state -ne 'AllNumeric')
}

function ConvertFrom-BoabIpLiteral {
    <# Strict IPv4 dotted-quad or IPv6 literal (no brackets, no zone) -> address bytes, else $null. #>
    param([string] $Text)
    if ($Text -match '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$') {
        return , ([System.Net.IPAddress]::Parse($Text).GetAddressBytes())
    }
    if ($Text.Contains(':') -and -not $Text.Contains('%') -and -not $Text.Contains('[')) {
        $addr = $null
        if ([System.Net.IPAddress]::TryParse($Text, [ref]$addr) -and $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return , ($addr.GetAddressBytes())
        }
    }
    return $null
}

# ----------------------------------------------------------------------------
# Byte helpers
# ----------------------------------------------------------------------------

function Add-BoabU8 {
    param([System.IO.MemoryStream] $S, [int] $V)
    $S.WriteByte([byte]($V -band 0xff))
}
function Add-BoabU16 {
    param([System.IO.MemoryStream] $S, [int] $V)
    $S.WriteByte([byte](($V -shr 8) -band 0xff)); $S.WriteByte([byte]($V -band 0xff))
}
function Add-BoabU24 {
    param([System.IO.MemoryStream] $S, [int] $V)
    $S.WriteByte([byte](($V -shr 16) -band 0xff)); $S.WriteByte([byte](($V -shr 8) -band 0xff)); $S.WriteByte([byte]($V -band 0xff))
}
function Add-BoabBytes {
    param([System.IO.MemoryStream] $S, [byte[]] $B)
    if ($null -ne $B -and $B.Length -gt 0) { $S.Write($B, 0, $B.Length) }
}

function Get-BoabU16 {
    param([byte[]] $B, [int] $O)
    if ($O + 2 -gt $B.Length) { throw 'TLS: truncated' }
    return ([int]$B[$O] -shl 8) -bor [int]$B[$O + 1]
}
function Get-BoabU24 {
    param([byte[]] $B, [int] $O)
    if ($O + 3 -gt $B.Length) { throw 'TLS: truncated' }
    return ([int]$B[$O] -shl 16) -bor ([int]$B[$O + 1] -shl 8) -bor [int]$B[$O + 2]
}

function Get-BoabSlice {
    param([byte[]] $B, [int] $Offset, [int] $Length)
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset + $Length -gt $B.Length) { throw 'TLS: truncated' }
    $r = [byte[]]::new($Length)
    if ($Length -gt 0) { [Array]::Copy($B, $Offset, $r, 0, $Length) }
    return , $r
}

function Join-BoabBytes {
    param([object[]] $Parts)
    $ms = [System.IO.MemoryStream]::new()
    foreach ($p in $Parts) { if ($null -ne $p) { Add-BoabBytes -S $ms -B ([byte[]]$p) } }
    return , $ms.ToArray()
}

function Test-BoabBytesEqual {
    param([byte[]] $A, [byte[]] $B)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
    return $true
}

function Get-BoabRandomBytes {
    param([int] $Count)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $b = [byte[]]::new($Count)
        $rng.GetBytes($b)
        return , $b
    }
    finally { $rng.Dispose() }
}

# ----------------------------------------------------------------------------
# Crypto primitives
# ----------------------------------------------------------------------------

function Invoke-BoabX25519 {
    <#
    .SYNOPSIS
    RFC 7748 X25519(k, u) with System.Numerics.BigInteger. Returns 32 bytes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [byte[]] $Scalar, [Parameter(Mandatory)] [byte[]] $U)
    $P = [System.Numerics.BigInteger]::Pow(2, 255) - 19
    $k = [byte[]]::new(33)
    [Array]::Copy($Scalar, $k, 32)
    $k[0] = $k[0] -band 248
    $k[31] = ($k[31] -band 127) -bor 64
    $kInt = [System.Numerics.BigInteger]::new($k)
    $uBuf = [byte[]]::new(33)
    [Array]::Copy($U, $uBuf, 32)
    $uBuf[31] = $uBuf[31] -band 127
    $x1 = [System.Numerics.BigInteger]::Remainder([System.Numerics.BigInteger]::new($uBuf), $P)
    $x2 = [System.Numerics.BigInteger]::One
    $z2 = [System.Numerics.BigInteger]::Zero
    $x3 = $x1
    $z3 = [System.Numerics.BigInteger]::One
    $swap = 0
    $a24 = [System.Numerics.BigInteger]::new(121665)
    for ($t = 254; $t -ge 0; $t--) {
        $kt = if (([System.Numerics.BigInteger]::op_RightShift($kInt, $t)).IsEven) { 0 } else { 1 }
        $swap = $swap -bxor $kt
        if ($swap -eq 1) {
            $tmp = $x2; $x2 = $x3; $x3 = $tmp
            $tmp = $z2; $z2 = $z3; $z3 = $tmp
        }
        $swap = $kt
        $A = ($x2 + $z2) % $P
        $AA = ($A * $A) % $P
        $B = ($x2 - $z2 + $P) % $P
        $BB = ($B * $B) % $P
        $E = ($AA - $BB + $P) % $P
        $C = ($x3 + $z3) % $P
        $D = ($x3 - $z3 + $P) % $P
        $DA = ($D * $A) % $P
        $CB = ($C * $B) % $P
        $s1 = ($DA + $CB) % $P
        $x3 = ($s1 * $s1) % $P
        $s2 = ($DA - $CB + $P) % $P
        $z3 = ($x1 * (($s2 * $s2) % $P)) % $P
        $x2 = ($AA * $BB) % $P
        $z2 = ($E * (($AA + ($a24 * $E)) % $P)) % $P
    }
    if ($swap -eq 1) {
        $tmp = $x2; $x2 = $x3; $x3 = $tmp
        $tmp = $z2; $z2 = $z3; $z3 = $tmp
    }
    $inv = [System.Numerics.BigInteger]::ModPow($z2, $P - 2, $P)
    $res = ($x2 * $inv) % $P
    $raw = $res.ToByteArray()
    $out = [byte[]]::new(32)
    [Array]::Copy($raw, $out, [Math]::Min(32, $raw.Length))
    return , $out
}

function New-BoabKeyShare {
    <# Create a key pair for a TLS group. Returns @{ Group; Public; Private }. #>
    param([int] $Group)
    switch ($Group) {
        0x001D {
            $priv = Get-BoabRandomBytes 32
            $base = [byte[]]::new(32); $base[0] = 9
            $pub = Invoke-BoabX25519 -Scalar $priv -U $base
            return @{ Group = $Group; Public = $pub; Private = $priv }
        }
        { $_ -in 0x0017, 0x0018 } {
            $curve = if ($Group -eq 0x0017) { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256 } else { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP384 }
            $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create($curve)
            $params = $ecdh.ExportParameters($false)
            $pub = Join-BoabBytes @([byte[]]@(4), $params.Q.X, $params.Q.Y)
            return @{ Group = $Group; Public = $pub; Private = $ecdh; Curve = $curve }
        }
    }
    throw "TLS: unsupported group $Group"
}

function Get-BoabSharedSecret {
    param($Share, [byte[]] $PeerPublic)
    if ($Share.Group -eq 0x001D) {
        if ($PeerPublic.Length -ne 32) { throw 'TLS: bad x25519 share' }
        $s = Invoke-BoabX25519 -Scalar $Share.Private -U $PeerPublic
        $allZero = $true
        foreach ($b in $s) { if ($b -ne 0) { $allZero = $false; break } }
        if ($allZero) { throw 'TLS: x25519 produced zero' }
        return , $s
    }
    $coord = ($PeerPublic.Length - 1) / 2
    if ($PeerPublic.Length -lt 3 -or $PeerPublic[0] -ne 4 -or $coord -ne [Math]::Floor($coord)) { throw 'TLS: bad EC share' }
    $p = [System.Security.Cryptography.ECParameters]::new()
    $p.Curve = $Share.Curve
    $q = [System.Security.Cryptography.ECPoint]::new()
    $q.X = Get-BoabSlice $PeerPublic 1 $coord
    $q.Y = Get-BoabSlice $PeerPublic (1 + $coord) $coord
    $p.Q = $q
    $peer = [System.Security.Cryptography.ECDiffieHellman]::Create($p)
    $m = $Share.Private.GetType().GetMethod('DeriveRawSecretAgreement')
    if ($null -eq $m) { throw 'TLS: raw ECDH not available on this .NET' }
    return , ([byte[]]$Share.Private.DeriveRawSecretAgreement($peer.PublicKey))
}

function Get-BoabDigest {
    param([string] $Alg, [byte[]] $Data)
    $h = if ($Alg -eq 'SHA384') { [System.Security.Cryptography.SHA384]::Create() } else { [System.Security.Cryptography.SHA256]::Create() }
    try { return , $h.ComputeHash($Data) } finally { $h.Dispose() }
}

function Get-BoabHmac {
    param([string] $Alg, [byte[]] $Key, [byte[]] $Data)
    $h = if ($Alg -eq 'SHA384') { [System.Security.Cryptography.HMACSHA384]::new($Key) } else { [System.Security.Cryptography.HMACSHA256]::new($Key) }
    try { return , $h.ComputeHash($Data) } finally { $h.Dispose() }
}

function Invoke-BoabHkdfExpandLabel {
    <# RFC 8446 HKDF-Expand-Label. #>
    param([string] $Alg, [byte[]] $Secret, [string] $Label, [byte[]] $Context, [int] $Length)
    $full = [System.Text.Encoding]::ASCII.GetBytes("tls13 $Label")
    $info = [System.IO.MemoryStream]::new()
    Add-BoabU16 $info $Length
    Add-BoabU8 $info $full.Length
    Add-BoabBytes $info $full
    Add-BoabU8 $info $Context.Length
    Add-BoabBytes $info $Context
    $infoBytes = $info.ToArray()
    $out = [System.IO.MemoryStream]::new()
    $t = [byte[]]::new(0)
    $i = 1
    while ($out.Length -lt $Length) {
        $t = Get-BoabHmac $Alg $Secret (Join-BoabBytes @($t, $infoBytes, [byte[]]@($i)))
        Add-BoabBytes $out $t
        $i++
    }
    return , (Get-BoabSlice $out.ToArray() 0 $Length)
}

function Get-BoabChaCha20Block {
    <# Pure PowerShell ChaCha20 block function (RFC 8439); fallback only. #>
    param([byte[]] $Key, [long] $Counter, [byte[]] $Nonce)
    $mask = 0xffffffffL
    $st = [long[]]::new(16)
    $st[0] = 0x61707865L; $st[1] = 0x3320646eL; $st[2] = 0x79622d32L; $st[3] = 0x6b206574L
    for ($i = 0; $i -lt 8; $i++) { $st[4 + $i] = [long][BitConverter]::ToUInt32($Key, $i * 4) }
    $st[12] = $Counter -band $mask
    for ($i = 0; $i -lt 3; $i++) { $st[13 + $i] = [long][BitConverter]::ToUInt32($Nonce, $i * 4) }
    $x = [long[]]$st.Clone()
    $qr = {
        param($a, $b, $c, $d)
        $x[$a] = ($x[$a] + $x[$b]) -band $mask; $v = $x[$d] -bxor $x[$a]; $x[$d] = (($v -shl 16) -bor ($v -shr 16)) -band $mask
        $x[$c] = ($x[$c] + $x[$d]) -band $mask; $v = $x[$b] -bxor $x[$c]; $x[$b] = (($v -shl 12) -bor ($v -shr 20)) -band $mask
        $x[$a] = ($x[$a] + $x[$b]) -band $mask; $v = $x[$d] -bxor $x[$a]; $x[$d] = (($v -shl 8) -bor ($v -shr 24)) -band $mask
        $x[$c] = ($x[$c] + $x[$d]) -band $mask; $v = $x[$b] -bxor $x[$c]; $x[$b] = (($v -shl 7) -bor ($v -shr 25)) -band $mask
    }
    for ($r = 0; $r -lt 10; $r++) {
        & $qr 0 4 8 12; & $qr 1 5 9 13; & $qr 2 6 10 14; & $qr 3 7 11 15
        & $qr 0 5 10 15; & $qr 1 6 11 12; & $qr 2 7 8 13; & $qr 3 4 9 14
    }
    $out = [byte[]]::new(64)
    for ($i = 0; $i -lt 16; $i++) {
        $w = [uint32](($x[$i] + $st[$i]) -band $mask)
        $bytes = [BitConverter]::GetBytes($w)
        if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        [Array]::Copy($bytes, 0, $out, $i * 4, 4)
    }
    return , $out
}

function Unprotect-BoabTlsRecord {
    <#
    .SYNOPSIS
    Decrypt a TLS 1.3 record. Uses .NET AesGcm/ChaCha20Poly1305 when the
    platform supports them (tag checked); otherwise decrypts with AES-CTR or
    pure-PowerShell ChaCha20 without checking the tag.
    Returns @(innerContentType, content).
    #>
    param([int] $Suite, [byte[]] $Key, [byte[]] $Iv, [long] $Seq, [byte[]] $Header, [byte[]] $Payload)
    if ($Payload.Length -lt 17) { throw 'TLS: record too short' }
    $nonce = [byte[]]$Iv.Clone()
    for ($i = 0; $i -lt 8; $i++) {
        $nonce[4 + $i] = $nonce[4 + $i] -bxor [byte](($Seq -shr (56 - 8 * $i)) -band 0xff)
    }
    $ctLen = $Payload.Length - 16
    $ct = Get-BoabSlice $Payload 0 $ctLen
    $tag = Get-BoabSlice $Payload $ctLen 16
    $pt = [byte[]]::new($ctLen)
    if ($Suite -eq 0x1303) {
        $chachaType = 'System.Security.Cryptography.ChaCha20Poly1305' -as [type]
        if ($null -ne $chachaType -and $chachaType::IsSupported) {
            $aead = $chachaType::new($Key)
            try { $aead.Decrypt($nonce, $ct, $tag, $pt, $Header) } finally { $aead.Dispose() }
        }
        else {
            for ($blk = 0; $blk * 64 -lt $ctLen; $blk++) {
                $ks = Get-BoabChaCha20Block -Key $Key -Counter ($blk + 1) -Nonce $nonce
                for ($j = 0; $j -lt 64 -and ($blk * 64 + $j) -lt $ctLen; $j++) {
                    $pt[$blk * 64 + $j] = $ct[$blk * 64 + $j] -bxor $ks[$j]
                }
            }
        }
    }
    else {
        $gcmType = 'System.Security.Cryptography.AesGcm' -as [type]
        if ($null -ne $gcmType -and $gcmType::IsSupported) {
            $aead = $null
            try { $aead = $gcmType::new($Key, 16) } catch { $aead = $gcmType::new($Key) }
            try { $aead.Decrypt($nonce, $ct, $tag, $pt, $Header) } finally { $aead.Dispose() }
        }
        else {
            $aes = [System.Security.Cryptography.Aes]::Create()
            try {
                $aes.Key = $Key
                $counter = [byte[]]::new(16)
                [Array]::Copy($nonce, $counter, 12)
                for ($blk = 0; $blk * 16 -lt $ctLen; $blk++) {
                    $c = $blk + 2
                    $counter[12] = [byte](($c -shr 24) -band 0xff); $counter[13] = [byte](($c -shr 16) -band 0xff)
                    $counter[14] = [byte](($c -shr 8) -band 0xff); $counter[15] = [byte]($c -band 0xff)
                    $ks = $aes.EncryptEcb($counter, [System.Security.Cryptography.PaddingMode]::None)
                    for ($j = 0; $j -lt 16 -and ($blk * 16 + $j) -lt $ctLen; $j++) {
                        $pt[$blk * 16 + $j] = $ct[$blk * 16 + $j] -bxor $ks[$j]
                    }
                }
            }
            finally { $aes.Dispose() }
        }
    }
    $end = $pt.Length - 1
    while ($end -ge 0 -and $pt[$end] -eq 0) { $end-- }
    if ($end -lt 0) { throw 'TLS: record without content type' }
    return @([int]$pt[$end], (Get-BoabSlice $pt 0 $end))
}

# ----------------------------------------------------------------------------
# Messages
# ----------------------------------------------------------------------------

function New-BoabTlsClientHello {
    <#
    .SYNOPSIS
    Build a ClientHello handshake message (with the 4-byte header) offering what
    rustls 0.23/ring offers for -OfferTls13 ($true = TLS 1.3 + 1.2, $false = 1.2 only).
    #>
    [CmdletBinding()]
    param(
        [bool] $OfferTls13,
        [AllowNull()] [string] $ServerName,
        [byte[]] $Random,
        [byte[]] $SessionId,
        [object[]] $KeyShares = @(),
        [AllowNull()] [byte[]] $Cookie
    )
    $suites = [System.Collections.Generic.List[int]]::new()
    if ($OfferTls13) { $suites.AddRange([int[]](Get-BoabTls13Suites)) }
    $suites.AddRange([int[]](Get-BoabTls12Suites))
    $suites.Add(0x00FF) # TLS_EMPTY_RENEGOTIATION_INFO_SCSV

    $ext = [System.IO.MemoryStream]::new()
    if ($OfferTls13) {
        Add-BoabU16 $ext 0x002B; Add-BoabU16 $ext 5; Add-BoabU8 $ext 4; Add-BoabU16 $ext 0x0304; Add-BoabU16 $ext 0x0303
    }
    Add-BoabU16 $ext 0x000B; Add-BoabU16 $ext 2; Add-BoabU8 $ext 1; Add-BoabU8 $ext 0
    if (-not [string]::IsNullOrEmpty($ServerName)) {
        $name = [System.Text.Encoding]::ASCII.GetBytes($ServerName.TrimEnd('.'))
        Add-BoabU16 $ext 0x0000; Add-BoabU16 $ext ($name.Length + 5); Add-BoabU16 $ext ($name.Length + 3)
        Add-BoabU8 $ext 0; Add-BoabU16 $ext $name.Length; Add-BoabBytes $ext $name
    }
    $schemes = Get-BoabTlsSignatureSchemes
    Add-BoabU16 $ext 0x000D; Add-BoabU16 $ext (2 + 2 * $schemes.Count); Add-BoabU16 $ext (2 * $schemes.Count)
    foreach ($s in $schemes) { Add-BoabU16 $ext $s }
    $groups = Get-BoabTlsOfferedGroups
    Add-BoabU16 $ext 0x000A; Add-BoabU16 $ext (2 + 2 * $groups.Count); Add-BoabU16 $ext (2 * $groups.Count)
    foreach ($g in $groups) { Add-BoabU16 $ext $g }
    Add-BoabU16 $ext 0x0017; Add-BoabU16 $ext 0 # extended_master_secret
    Add-BoabU16 $ext 0x0005; Add-BoabU16 $ext 5; Add-BoabU8 $ext 1; Add-BoabU16 $ext 0; Add-BoabU16 $ext 0 # status_request (OCSP)
    Add-BoabU16 $ext 0x0023; Add-BoabU16 $ext 0 # session_ticket
    if ($OfferTls13) {
        $ks = [System.IO.MemoryStream]::new()
        foreach ($share in $KeyShares) {
            Add-BoabU16 $ks $share.Group; Add-BoabU16 $ks $share.Public.Length; Add-BoabBytes $ks $share.Public
        }
        $ksb = $ks.ToArray()
        Add-BoabU16 $ext 0x0033; Add-BoabU16 $ext ($ksb.Length + 2); Add-BoabU16 $ext $ksb.Length; Add-BoabBytes $ext $ksb
        Add-BoabU16 $ext 0x002D; Add-BoabU16 $ext 2; Add-BoabU8 $ext 1; Add-BoabU8 $ext 1 # psk_dhe_ke
        if ($null -ne $Cookie -and $Cookie.Length -gt 0) {
            Add-BoabU16 $ext 0x002C; Add-BoabU16 $ext ($Cookie.Length + 2); Add-BoabU16 $ext $Cookie.Length; Add-BoabBytes $ext $Cookie
        }
    }
    $extBytes = $ext.ToArray()

    $body = [System.IO.MemoryStream]::new()
    Add-BoabU16 $body 0x0303
    Add-BoabBytes $body $Random
    Add-BoabU8 $body $SessionId.Length; Add-BoabBytes $body $SessionId
    Add-BoabU16 $body (2 * $suites.Count)
    foreach ($s in $suites) { Add-BoabU16 $body $s }
    Add-BoabU8 $body 1; Add-BoabU8 $body 0
    Add-BoabU16 $body $extBytes.Length; Add-BoabBytes $body $extBytes
    $b = $body.ToArray()

    $msg = [System.IO.MemoryStream]::new()
    Add-BoabU8 $msg 1; Add-BoabU24 $msg $b.Length; Add-BoabBytes $msg $b
    return , $msg.ToArray()
}

function ConvertFrom-BoabTlsServerHello {
    <#
    .SYNOPSIS
    Parse a ServerHello handshake message (with header). Returns LegacyVersion,
    Random, SessionId, CipherSuite, Extensions (code -> bytes), IsHelloRetry,
    SelectedVersion (supported_versions or legacy), KeyShareGroup and
    KeySharePublic (or $null), and Cookie.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [byte[]] $Message)
    if ($Message.Length -lt 4 -or $Message[0] -ne 2) { throw 'TLS: expected ServerHello' }
    $b = Get-BoabSlice $Message 4 ($Message.Length - 4)
    $o = 0
    $legacy = Get-BoabU16 $b $o; $o += 2
    $random = Get-BoabSlice $b $o 32; $o += 32
    if ($o -ge $b.Length) { throw 'TLS: truncated' }
    $sidLen = [int]$b[$o]; $o++
    $sid = Get-BoabSlice $b $o $sidLen; $o += $sidLen
    $suite = Get-BoabU16 $b $o; $o += 2
    if ($o -ge $b.Length) { throw 'TLS: truncated' }
    $o++ # compression
    $exts = [ordered]@{}
    if ($o + 2 -le $b.Length) {
        $extLen = Get-BoabU16 $b $o; $o += 2
        $end = $o + $extLen
        if ($end -gt $b.Length) { throw 'TLS: truncated' }
        while ($o -lt $end) {
            $type = Get-BoabU16 $b $o; $len = Get-BoabU16 $b ($o + 2); $o += 4
            $exts[[string]$type] = Get-BoabSlice $b $o $len
            $o += $len
        }
    }
    $hrrMagic = [byte[]](0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C)
    $isHrr = Test-BoabBytesEqual ([byte[]]$random) $hrrMagic
    $selected = $legacy
    if ($exts.Contains('43')) {
        $sv = [byte[]]$exts['43']
        if ($sv.Length -ne 2) { throw 'TLS: bad supported_versions' }
        $selected = Get-BoabU16 $sv 0
    }
    $ksGroup = $null; $ksPub = $null
    if ($exts.Contains('51')) {
        $ks = [byte[]]$exts['51']
        $ksGroup = Get-BoabU16 $ks 0
        if (-not $isHrr) {
            $kl = Get-BoabU16 $ks 2
            $ksPub = Get-BoabSlice $ks 4 $kl
        }
    }
    $cookie = $null
    if ($exts.Contains('44')) {
        $ck = [byte[]]$exts['44']
        $cookie = Get-BoabSlice $ck 2 (Get-BoabU16 $ck 0)
    }
    return [pscustomobject]@{
        LegacyVersion   = $legacy
        Random          = $random
        SessionId       = $sid
        CipherSuite     = $suite
        Extensions      = $exts
        IsHelloRetry    = $isHrr
        SelectedVersion = $selected
        KeyShareGroup   = $ksGroup
        KeySharePublic  = $ksPub
        Cookie          = $cookie
    }
}

function ConvertFrom-BoabTlsCertificateMessage {
    <# Parse a Certificate handshake message (with header) into a list of DER byte arrays. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [byte[]] $Message, [bool] $Tls13)
    if ($Message[0] -ne 11) { throw 'TLS: expected Certificate' }
    $b = Get-BoabSlice $Message 4 ($Message.Length - 4)
    $o = 0
    if ($Tls13) {
        $ctxLen = [int]$b[0]; $o = 1 + $ctxLen
    }
    $listLen = Get-BoabU24 $b $o; $o += 3
    $end = $o + $listLen
    if ($end -gt $b.Length) { throw 'TLS: truncated' }
    $certs = [System.Collections.Generic.List[object]]::new()
    while ($o -lt $end) {
        $cl = Get-BoabU24 $b $o; $o += 3
        $certs.Add((Get-BoabSlice $b $o $cl)); $o += $cl
        if ($Tls13) {
            $el = Get-BoabU16 $b $o; $o += 2 + $el
        }
    }
    return , $certs
}

# ----------------------------------------------------------------------------
# Record layer
# ----------------------------------------------------------------------------

function Read-BoabExact {
    param([System.IO.Stream] $Stream, [int] $Count, [datetime] $Deadline)
    $buf = [byte[]]::new($Count)
    $got = 0
    while ($got -lt $Count) {
        $remaining = [int]($Deadline - [datetime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0) { throw [System.TimeoutException]::new('TLS handshake timeout') }
        $Stream.ReadTimeout = [Math]::Max($remaining, 1)
        try {
            $n = $Stream.Read($buf, $got, $Count - $got)
        }
        catch {
            if ([datetime]::UtcNow -ge $Deadline) { throw [System.TimeoutException]::new('TLS handshake timeout') }
            $e = $_.Exception
            while ($null -ne $e) {
                if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                    throw [System.TimeoutException]::new('TLS handshake timeout')
                }
                $e = $e.InnerException
            }
            throw
        }
        if ($n -le 0) { throw 'TLS: connection closed' }
        $got += $n
    }
    return , $buf
}

function Read-BoabTlsRecord {
    param([System.IO.Stream] $Stream, [datetime] $Deadline)
    $hdr = Read-BoabExact -Stream $Stream -Count 5 -Deadline $Deadline
    $len = Get-BoabU16 $hdr 3
    if ($len -gt 18432) { throw 'TLS: record overflow' }
    $data = Read-BoabExact -Stream $Stream -Count $len -Deadline $Deadline
    return [pscustomobject]@{ Type = [int]$hdr[0]; Header = $hdr; Data = $data }
}

function Send-BoabTlsHandshakeRecord {
    param([System.IO.Stream] $Stream, [byte[]] $Message, [int] $RecordVersion = 0x0301)
    $ms = [System.IO.MemoryStream]::new()
    Add-BoabU8 $ms 22; Add-BoabU16 $ms $RecordVersion; Add-BoabU16 $ms $Message.Length; Add-BoabBytes $ms $Message
    $bytes = $ms.ToArray()
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Get-BoabNextHandshakeMessage {
    <# Pop one complete handshake message (with header) from the buffer, or $null. #>
    param([System.Collections.Generic.List[byte]] $Buffer)
    if ($Buffer.Count -lt 4) { return $null }
    $len = ([int]$Buffer[1] -shl 16) -bor ([int]$Buffer[2] -shl 8) -bor [int]$Buffer[3]
    if ($Buffer.Count -lt 4 + $len) { return $null }
    $msg = $Buffer.GetRange(0, 4 + $len).ToArray()
    $Buffer.RemoveRange(0, 4 + $len)
    return , $msg
}

# ----------------------------------------------------------------------------
# Certificate validation (webpki approximation)
# ----------------------------------------------------------------------------

function Get-BoabX509SubjectAltNames {
    <# dNSName and iPAddress entries of the subjectAltName extension. #>
    param([byte[]] $Der)
    $dns = [System.Collections.Generic.List[string]]::new()
    $ips = [System.Collections.Generic.List[object]]::new()
    $cert = Read-BoabDerHeader -Bytes $Der -Offset 0
    $top = Get-BoabDerChildren -Bytes $Der -Header $cert
    $tbsFields = Get-BoabDerChildren -Bytes $Der -Header $top[0]
    foreach ($f in $tbsFields) {
        if ($f.Class -ne 2 -or $f.Tag -ne 3) { continue }
        $extsSeq = (Get-BoabDerChildren -Bytes $Der -Header $f)[0]
        foreach ($ext in (Get-BoabDerChildren -Bytes $Der -Header $extsSeq)) {
            $parts = Get-BoabDerChildren -Bytes $Der -Header $ext
            if ((Read-BoabDerOid -Bytes $Der -Header $parts[0]) -ne '2.5.29.17') { continue }
            $os = $parts[$parts.Count - 1]
            $gnSeq = Read-BoabDerHeader -Bytes $Der -Offset $os.ContentStart -Limit $os.End
            foreach ($gn in (Get-BoabDerChildren -Bytes $Der -Header $gnSeq)) {
                if ($gn.Class -ne 2) { continue }
                if ($gn.Tag -eq 2) { $dns.Add([System.Text.Encoding]::ASCII.GetString((Get-BoabDerContent -Bytes $Der -Header $gn))) }
                elseif ($gn.Tag -eq 7) { $ips.Add((Get-BoabDerContent -Bytes $Der -Header $gn)) }
            }
        }
    }
    return [pscustomobject]@{ Dns = $dns; Ip = $ips }
}

function Test-BoabDnsNameMatch {
    <# webpki-style presented-vs-reference DNS name match (SAN only, leftmost-label wildcard). #>
    param([string] $Presented, [string] $Reference)
    $p = $Presented.ToLowerInvariant().TrimEnd('.')
    $r = $Reference.ToLowerInvariant().TrimEnd('.')
    if ($p -ceq $r) { return $true }
    if ($p.StartsWith('*.')) {
        $suffix = $p.Substring(1) # ".example.com"
        if ($suffix.IndexOf([char]'.', 1) -lt 0) { return $false } # no wildcard directly under a TLD
        $dot = $r.IndexOf([char]'.')
        if ($dot -le 0) { return $false }
        return ($r.Substring($dot) -ceq $suffix)
    }
    return $false
}

function Get-BoabCertKeyInfo {
    <# Key type/size of an X509Certificate2: @{ Type = 'RSA'|'EC'|'Ed25519'|'other'; Bits; Curve }. #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert)
    $oid = $Cert.PublicKey.Oid.Value
    if ($oid -eq '1.2.840.113549.1.1.1') {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)
        try { return @{ Type = 'RSA'; Bits = $rsa.KeySize; Curve = $null } } finally { if ($rsa) { $rsa.Dispose() } }
    }
    if ($oid -eq '1.2.840.10045.2.1') {
        $curve = $null
        try {
            $pd = $Cert.PublicKey.EncodedParameters.RawData
            $h = Read-BoabDerHeader -Bytes $pd -Offset 0
            $curve = Read-BoabDerOid -Bytes $pd -Header $h
        }
        catch { $curve = $null }
        return @{ Type = 'EC'; Bits = 0; Curve = $curve }
    }
    if ($oid -eq '1.3.101.112') { return @{ Type = 'Ed25519'; Bits = 255; Curve = $null } }
    return @{ Type = 'other'; Bits = 0; Curve = $null }
}

function Test-BoabWebpkiKeyOk {
    <# Can webpki/ring verify signatures made with this key? RSA 2048-8192, P-256/P-384, Ed25519. #>
    param($KeyInfo)
    switch ($KeyInfo.Type) {
        'RSA' { return ($KeyInfo.Bits -ge 2048 -and $KeyInfo.Bits -le 8192) }
        'EC' { return ($KeyInfo.Curve -in '1.2.840.10045.3.1.7', '1.3.132.0.34') }
        'Ed25519' { return $true }
    }
    return $false
}

function Test-BoabWebpkiSignatureOk {
    <# Is (signature algorithm, issuer key) a combination webpki accepts? #>
    param([string] $SigOid, $IssuerKey)
    switch ($SigOid) {
        { $_ -in '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13', '1.2.840.113549.1.1.10' } {
            return ($IssuerKey.Type -eq 'RSA' -and (Test-BoabWebpkiKeyOk $IssuerKey))
        }
        { $_ -in '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3' } {
            return ($IssuerKey.Type -eq 'EC' -and (Test-BoabWebpkiKeyOk $IssuerKey))
        }
        '1.3.101.112' { return ($IssuerKey.Type -eq 'Ed25519') }
    }
    return $false
}

function Test-BoabTlsServerCertificate {
    <#
    .SYNOPSIS
    Approximates rustls' WebPkiServerVerifier: the chain must build to a root in
    the OS trust store (Rust uses the Mozilla roots from webpki-roots) for
    serverAuth at the current time, no revocation checks; the name must match a
    SAN (the CN is ignored); every signature in the chain must use an algorithm
    webpki supports (no SHA-1, no ecdsa-with-SHA512, RSA keys 2048-8192 bits);
    and the leaf key must be usable for the handshake signature.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [System.Collections.Generic.List[object]] $Chain,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $ServerName,
        [AllowNull()] [byte[]] $IpBytes
    )
    if ($Chain.Count -eq 0) { return $false }
    $X509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $leaf = $X509::new([byte[]]$Chain[0])
    $chainObj = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chainObj.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void]$chainObj.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        for ($i = 1; $i -lt $Chain.Count; $i++) {
            try { [void]$chainObj.ChainPolicy.ExtraStore.Add($X509::new([byte[]]$Chain[$i])) } catch { $null = $_ }
        }
        if (-not $chainObj.Build($leaf)) { return $false }

        $san = Get-BoabX509SubjectAltNames -Der ([byte[]]$Chain[0])
        $nameOk = $false
        if ($null -ne $IpBytes) {
            foreach ($ip in $san.Ip) { if (Test-BoabBytesEqual ([byte[]]$ip) $IpBytes) { $nameOk = $true; break } }
        }
        else {
            foreach ($d in $san.Dns) { if (Test-BoabDnsNameMatch -Presented $d -Reference $ServerName) { $nameOk = $true; break } }
        }
        if (-not $nameOk) { return $false }

        $elements = @($chainObj.ChainElements | ForEach-Object { $_.Certificate })
        if (-not (Test-BoabWebpkiKeyOk (Get-BoabCertKeyInfo $elements[0]))) { return $false }
        for ($i = 0; $i -lt $elements.Count - 1; $i++) {
            $issuerKey = Get-BoabCertKeyInfo $elements[$i + 1]
            if (-not (Test-BoabWebpkiSignatureOk -SigOid $elements[$i].SignatureAlgorithm.Value -IssuerKey $issuerKey)) { return $false }
        }
        return $true
    }
    finally {
        $chainObj.Dispose()
    }
}

# ----------------------------------------------------------------------------
# Handshake
# ----------------------------------------------------------------------------

function Invoke-BoabTlsProtocol {
    <# The TLS part of the handshake over an open stream. Throws on any failure. #>
    param(
        [System.IO.Stream] $Stream,
        [string] $HostName,
        [bool] $IsDns,
        [bool] $OfferTls13,
        [datetime] $Deadline
    )
    $sni = if ($IsDns) { $HostName } else { $null }
    $random = Get-BoabRandomBytes 32
    $sessionId = if ($OfferTls13) { Get-BoabRandomBytes 32 } else { [byte[]]::new(0) }
    $shares = @()
    if ($OfferTls13) { $shares = @(New-BoabKeyShare -Group 0x001D) }
    $ch1 = New-BoabTlsClientHello -OfferTls13 $OfferTls13 -ServerName $sni -Random $random -SessionId $sessionId -KeyShares $shares -Cookie $null
    Send-BoabTlsHandshakeRecord -Stream $Stream -Message $ch1

    $hsBuf = [System.Collections.Generic.List[byte]]::new()
    $readPlainMessage = {
        while ($true) {
            $m = Get-BoabNextHandshakeMessage -Buffer $hsBuf
            if ($null -ne $m) { return , $m }
            $rec = Read-BoabTlsRecord -Stream $Stream -Deadline $Deadline
            if ($rec.Type -eq 22) { $hsBuf.AddRange([byte[]]$rec.Data) }
            elseif ($rec.Type -eq 21) { throw 'TLS: alert received' }
            elseif ($rec.Type -eq 20) { continue }
            else { throw 'TLS: unexpected record' }
        }
    }

    $shMsg = & $readPlainMessage
    $sh = ConvertFrom-BoabTlsServerHello -Message $shMsg
    $tls13Suites = Get-BoabTls13Suites
    $tls12Suites = Get-BoabTls12Suites
    $transcriptParts = [System.Collections.Generic.List[object]]::new()
    $transcriptParts.Add($ch1)
    $share = if ($shares.Count -gt 0) { $shares[0] } else { $null }

    if ($sh.IsHelloRetry) {
        if (-not $OfferTls13 -or $sh.SelectedVersion -ne 0x0304) { throw 'TLS: bad HelloRetryRequest' }
        if ($tls13Suites -notcontains $sh.CipherSuite) { throw 'TLS: bad cipher suite' }
        if ($null -eq $sh.KeyShareGroup -or (Get-BoabTlsOfferedGroups) -notcontains $sh.KeyShareGroup -or $sh.KeyShareGroup -eq $share.Group) {
            throw 'TLS: bad HelloRetryRequest group'
        }
        $hashAlg = if ($sh.CipherSuite -eq 0x1302) { 'SHA384' } else { 'SHA256' }
        $ch1Hash = Get-BoabDigest $hashAlg $ch1
        $synthetic = Join-BoabBytes @([byte[]]@(254, 0, 0, $ch1Hash.Length), $ch1Hash)
        $share = New-BoabKeyShare -Group $sh.KeyShareGroup
        $ch2 = New-BoabTlsClientHello -OfferTls13 $true -ServerName $sni -Random $random -SessionId $sessionId -KeyShares @($share) -Cookie $sh.Cookie
        Send-BoabTlsHandshakeRecord -Stream $Stream -Message $ch2 -RecordVersion 0x0303
        $transcriptParts.Clear()
        $transcriptParts.Add($synthetic); $transcriptParts.Add($shMsg); $transcriptParts.Add($ch2)
        $shMsg = & $readPlainMessage
        $sh = ConvertFrom-BoabTlsServerHello -Message $shMsg
        if ($sh.IsHelloRetry) { throw 'TLS: second HelloRetryRequest' }
    }
    $transcriptParts.Add($shMsg)

    $certs = $null
    $version = $null
    if ($sh.SelectedVersion -eq 0x0304) {
        if (-not $OfferTls13) { throw 'TLS: unexpected TLS 1.3' }
        if ($tls13Suites -notcontains $sh.CipherSuite) { throw 'TLS: bad cipher suite' }
        if ($null -eq $sh.KeySharePublic -or $sh.KeyShareGroup -ne $share.Group) { throw 'TLS: bad key share' }
        if ($hsBuf.Count -ne 0) { throw 'TLS: data after ServerHello' }
        $version = 'TLSv1.3'
        $hashAlg = if ($sh.CipherSuite -eq 0x1302) { 'SHA384' } else { 'SHA256' }
        $hashLen = if ($hashAlg -eq 'SHA384') { 48 } else { 32 }
        $keyLen = if ($sh.CipherSuite -eq 0x1301) { 16 } else { 32 }
        $shared = Get-BoabSharedSecret -Share $share -PeerPublic $sh.KeySharePublic
        $zeros = [byte[]]::new($hashLen)
        $early = Get-BoabHmac $hashAlg $zeros $zeros
        $derived = Invoke-BoabHkdfExpandLabel $hashAlg $early 'derived' (Get-BoabDigest $hashAlg ([byte[]]::new(0))) $hashLen
        $hsSecret = Get-BoabHmac $hashAlg $derived $shared
        $thash = Get-BoabDigest $hashAlg (Join-BoabBytes $transcriptParts.ToArray())
        $sHs = Invoke-BoabHkdfExpandLabel $hashAlg $hsSecret 's hs traffic' $thash $hashLen
        $key = Invoke-BoabHkdfExpandLabel $hashAlg $sHs 'key' ([byte[]]::new(0)) $keyLen
        $iv = Invoke-BoabHkdfExpandLabel $hashAlg $sHs 'iv' ([byte[]]::new(0)) 12
        [long]$seq = 0
        while ($null -eq $certs) {
            $m = Get-BoabNextHandshakeMessage -Buffer $hsBuf
            if ($null -ne $m) {
                switch ([int]$m[0]) {
                    8 { }  # EncryptedExtensions
                    13 { } # CertificateRequest
                    11 { $certs = ConvertFrom-BoabTlsCertificateMessage -Message $m -Tls13 $true }
                    default { throw 'TLS: unexpected handshake message' }
                }
                continue
            }
            $rec = Read-BoabTlsRecord -Stream $Stream -Deadline $Deadline
            if ($rec.Type -eq 20) { continue }
            if ($rec.Type -eq 21) { throw 'TLS: alert received' }
            if ($rec.Type -ne 23) { throw 'TLS: unexpected record' }
            $inner = Unprotect-BoabTlsRecord -Suite $sh.CipherSuite -Key $key -Iv $iv -Seq $seq -Header $rec.Header -Payload $rec.Data
            $seq++
            if ($inner[0] -eq 22) { $hsBuf.AddRange([byte[]]$inner[1]) }
            elseif ($inner[0] -eq 21) { throw 'TLS: alert received' }
            else { throw 'TLS: unexpected record' }
        }
    }
    elseif ($sh.SelectedVersion -eq 0x0303) {
        if ($sh.Extensions.Contains('43')) { throw 'TLS: supported_versions in TLS 1.2 ServerHello' }
        if ($tls12Suites -notcontains $sh.CipherSuite) { throw 'TLS: bad cipher suite' }
        if ($OfferTls13) {
            $tail = Get-BoabSlice $sh.Random 24 8
            $sentinel = [byte[]](0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01)
            if (Test-BoabBytesEqual ([byte[]]$tail) $sentinel) { throw 'TLS: downgrade detected' }
        }
        $version = 'TLSv1.2'
        while ($null -eq $certs) {
            $m = & $readPlainMessage
            switch ([int]$m[0]) {
                11 { $certs = ConvertFrom-BoabTlsCertificateMessage -Message $m -Tls13 $false }
                default { throw 'TLS: expected Certificate' }
            }
        }
    }
    else {
        throw 'TLS: unsupported protocol version'
    }

    $group = $null
    if ($version -eq 'TLSv1.3') { $group = $sh.KeyShareGroup }
    return [pscustomobject]@{
        NegotiatedVersion = $version
        CipherSuiteCode   = $sh.CipherSuite
        CipherSuite       = (Get-BoabTlsCipherSuiteName -Code $sh.CipherSuite)
        CertChain         = $certs
        Alpn              = $null
        KeyExchangeGroup  = $group
    }
}

function Invoke-BoabTlsHandshake {
    <#
    .SYNOPSIS
    Port of tls.rs `handshake`. Returns NegotiatedVersion ('TLSv1.3' or
    'TLSv1.2'), CipherSuite (rustls name), CertChain (DER list as the server
    sent it), Alpn ($null; Boab offers no ALPN) and KeyExchangeGroup (TLS 1.3
    group codepoint; informational only).
    .DESCRIPTION
    Throws an exception whose message is exactly what the Rust error displays:
    "target must be host:port, got <t>", "invalid port in target <t>",
    "invalid server name: <host>", "TCP connect timeout", "TCP connect",
    "TLS handshake timeout" or "TLS handshake". The real cause is kept in
    InnerException.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Target,
        [UInt64] $TimeoutSeconds = 10,
        [ValidateSet('PreferTls13', 'Tls12Only')] [string] $Policy = 'PreferTls13'
    )
    $hp = Split-BoabTlsTarget -Target $Target
    $hostName = [string]$hp[0]
    $port = [int]$hp[1]
    $isDns = Test-BoabDnsName -Name $hostName
    $ipBytes = $null
    if (-not $isDns) {
        $ipBytes = ConvertFrom-BoabIpLiteral -Text $hostName
        if ($null -eq $ipBytes) { throw "invalid server name: $hostName" }
    }
    $timeoutMs = [int][Math]::Min([double]$TimeoutSeconds * 1000, [int]::MaxValue)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $done = $false
        try {
            $connect = $client.ConnectAsync($hostName, $port)
            $done = $connect.Wait($timeoutMs)
        }
        catch {
            throw [System.Exception]::new('TCP connect', $_.Exception)
        }
        if (-not $done) { throw [System.Exception]::new('TCP connect timeout') }

        $deadline = [datetime]::UtcNow.AddMilliseconds($timeoutMs)
        try {
            $result = Invoke-BoabTlsProtocol -Stream $client.GetStream() -HostName $hostName -IsDns $isDns -OfferTls13 ($Policy -eq 'PreferTls13') -Deadline $deadline
            $sn = if ($isDns) { $hostName } else { '' }
            if (-not (Test-BoabTlsServerCertificate -Chain $result.CertChain -ServerName $sn -IpBytes $ipBytes)) {
                throw 'TLS: certificate not trusted'
            }
            return $result
        }
        catch {
            $isTimeout = $false
            $ex = $_.Exception
            while ($null -ne $ex) {
                if ($ex -is [System.TimeoutException]) { $isTimeout = $true; break }
                $ex = $ex.InnerException
            }
            if ($isTimeout -or [datetime]::UtcNow -ge $deadline) {
                throw [System.Exception]::new('TLS handshake timeout', $_.Exception)
            }
            throw [System.Exception]::new('TLS handshake', $_.Exception)
        }
    }
    finally {
        $client.Dispose()
    }
}

# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------

function Get-BoabTlsPopulatedFindings {
    <# Port of `populate_findings` + `cert_finding_from_der`. #>
    param([string] $ScanId, [string] $Target, $Result)
    $out = [System.Collections.Generic.List[object]]::new()
    $lower = $Result.CipherSuite.ToLowerInvariant()
    $endpointPqc = if ($lower.Contains('aes') -or $lower.Contains('chacha20')) { 'symmetric_ok' } else { 'unknown' }
    $endpoint = [ordered]@{
        kind         = 'tls_endpoint'
        target       = $Target
        tls_version  = $Result.NegotiatedVersion
        cipher_suite = $Result.CipherSuite
        alpn         = $Result.Alpn
        pqc_status   = $endpointPqc
    }
    $out.Add((New-BoabFinding -ScanId $ScanId -SourceType 'host' -SourceLocation $Target -Evidence $endpoint -Confidence 'high'))
    foreach ($der in $Result.CertChain) {
        try {
            $c = ConvertFrom-BoabX509Der -Der ([byte[]]$der)
        }
        catch {
            Write-Debug "could not parse cert from ${Target}: $($_.Exception.Message)"
            continue
        }
        $sigName = Get-BoabFriendlySignatureName -Oid $c.SignatureOid
        $pkName = Get-BoabFriendlyPublicKeyName -Oid $c.PublicKeyOid
        $ev = [ordered]@{
            kind                     = 'tls_certificate'
            target                   = $Target
            subject                  = $c.Subject
            issuer                   = $c.Issuer
            signature_algorithm      = $sigName
            signature_algorithm_oid  = $c.SignatureOid
            public_key_algorithm     = $pkName
            public_key_algorithm_oid = $c.PublicKeyOid
            public_key_bits          = Get-BoabApproximateKeyBits -Cert $c
            not_before_unix          = [long]$c.NotBeforeUnix
            not_after_unix           = [long]$c.NotAfterUnix
            fingerprint_sha256       = $c.FingerprintSha256
            pqc_status               = Get-BoabSignaturePqcStatus -Name $sigName
        }
        $out.Add((New-BoabFinding -ScanId $ScanId -SourceType 'cert_subject' -SourceLocation "$Target|$($c.Subject)" -Evidence $ev -Confidence 'high'))
    }
    return , $out
}

function Invoke-BoabTlsScan {
    <#
    .SYNOPSIS
    Scan TLS endpoints one after another. Port of `boab::scanners::tls::scan_targets`.
    .DESCRIPTION
    Returns an object[] (emitted as a single object, not unrolled) with one Scan
    per target that is not in -Exclude. A target whose handshake fails both with
    TLS 1.3+1.2 and with TLS 1.2 only gets status 'failed' and error_message
    "TLS handshake failed: tls13=<err> tls12=<err>"; scanning carries on.
    After each target it sleeps for the -RateLimit interval, or 1 second when
    -RateLimit is not given (an unparseable -RateLimit means no sleep, as in Rust).
    Throws "--probe-hsts is not allowed in air-gapped mode" when -ProbeHsts is
    set while -AirGapped is $true.

    Parity notes: the evidence fields are the same as Rust's. Results can still
    differ where the trust decision differs: the OS trust store vs
    webpki-roots, and .NET chain building vs webpki path building.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [AllowEmptyCollection()] [string[]] $Targets,
        [string] $RateLimit,
        [UInt64] $TimeoutSeconds = 10,
        [switch] $ProbeHsts,
        [string[]] $Exclude = @(),
        [string] $Name,
        [bool] $AirGapped = $true
    )
    if ($ProbeHsts -and $AirGapped) {
        throw '--probe-hsts is not allowed in air-gapped mode'
    }
    if ($null -eq $Exclude) { $Exclude = @() }
    $hasName = $PSBoundParameters.ContainsKey('Name') -and $null -ne $Name
    $hasRate = $PSBoundParameters.ContainsKey('RateLimit') -and $null -ne $RateLimit
    $scans = [System.Collections.Generic.List[object]]::new()
    foreach ($target in $Targets) {
        if ($Exclude -ccontains $target) { continue }
        $scanName = if ($hasName) { $Name } else { "tls:$target" }
        $scan = New-BoabScan -Name $scanName -ScanType 'tls_endpoint' -Target $target
        $scan.status = 'running'
        $result = $null
        $err13 = $null
        try {
            $result = Invoke-BoabTlsHandshake -Target $target -TimeoutSeconds $TimeoutSeconds -Policy 'PreferTls13'
        }
        catch {
            $err13 = $_.Exception.Message
        }
        if ($null -eq $result) {
            try {
                $result = Invoke-BoabTlsHandshake -Target $target -TimeoutSeconds $TimeoutSeconds -Policy 'Tls12Only'
            }
            catch {
                $scan.status = 'failed'
                $scan.error_message = "TLS handshake failed: tls13=$err13 tls12=$($_.Exception.Message)"
            }
        }
        if ($null -ne $result) {
            $scan.findings.AddRange((Get-BoabTlsPopulatedFindings -ScanId $scan.id -Target $target -Result $result))
            $scan.status = 'completed'
        }
        $scan.completed_at = Get-BoabUtcNow
        $scans.Add($scan)

        if ($hasRate) {
            $delay = ConvertFrom-BoabRateLimit -Value $RateLimit
            if ($null -ne $delay) { Start-Sleep -Milliseconds ([int]$delay.TotalMilliseconds) }
        }
        else {
            Start-Sleep -Seconds 1
        }
    }
    return , ([object[]]$scans.ToArray())
}
