# Per-language regex packs for the codebase scanner.
# Port of src/scanners/codebase/patterns/mod.rs.
#
# Regexes are copied from the Rust source as-is. Rust `regex` and .NET regex
# read every construct used here the same way: inline (?i)/(?m) flags, \b, \s,
# character classes and alternation. Both use Unicode-aware \b and \s.
# CultureInvariant keeps (?i) from depending on the current culture.

function New-BoabPatternRegex {
    [CmdletBinding()]
    [OutputType([regex])]
    param([Parameter(Mandatory)] [string] $Pattern)
    $opts = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant -bor
        [System.Text.RegularExpressions.RegexOptions]::Compiled
    return [regex]::new($Pattern, $opts)
}

function New-BoabAlgorithmPattern {
    param(
        [string] $Regex,
        [string] $AlgorithmName,
        [string] $PqcStatus,
        [string] $Confidence,
        [AllowNull()] $Primitive,
        [AllowNull()] $KeySizeBits
    )
    return [pscustomobject]@{
        Regex         = New-BoabPatternRegex -Pattern $Regex
        AlgorithmName = $AlgorithmName
        PqcStatus     = $PqcStatus
        Confidence    = $Confidence
        Primitive     = $Primitive
        KeySizeBits   = $KeySizeBits
    }
}

function New-BoabLibraryPattern {
    param(
        [string] $Regex,
        [string] $LibraryName,
        [string] $Language,
        [string] $Confidence
    )
    return [pscustomobject]@{
        Regex       = New-BoabPatternRegex -Pattern $Regex
        LibraryName = $LibraryName
        Language    = $Language
        Confidence  = $Confidence
    }
}

# Language names are the Rust `{:?}` (Debug) rendering of the `Language` enum,
# which is what ends up in the evidence `language` field.
#
# Tables are built inside functions (and cached lazily) rather than at file
# scope, so the functions work no matter which scope the file was dot-sourced into.
function Get-BoabLanguageTable {
    return @{
    'rs'   = 'Rust'
    'go'   = 'Go'
    'py'   = 'Python'
    'js'   = 'JavaScript'
    'mjs'  = 'JavaScript'
    'cjs'  = 'JavaScript'
    'ts'   = 'JavaScript'
    'tsx'  = 'JavaScript'
    'jsx'  = 'JavaScript'
    'java' = 'Java'
    'kt'   = 'Java'
    'kts'  = 'Java'
    'cs'   = 'DotNet'
    'vb'   = 'DotNet'
    'fs'   = 'DotNet'
    'toml' = 'Generic'
    'yaml' = 'Generic'
    'yml'  = 'Generic'
    'json' = 'Generic'
    'xml'  = 'Generic'
    'conf' = 'Generic'
    'ini'  = 'Generic'
    }
}

function Get-BoabPathExtension {
    <#
    .SYNOPSIS
    Port of Rust's `Path::extension()` (not .NET's GetExtension).
    .DESCRIPTION
    Returns $null when the file name has no dot, or when its only dot is the
    leading one (".gitignore"). "foo." gives an empty string. The extension is
    returned as-is; callers lowercase it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Path)
    $name = [System.IO.Path]::GetFileName($Path.TrimEnd('/', '\'))
    if ([string]::IsNullOrEmpty($name) -or $name -eq '..') { return $null }
    $idx = $name.LastIndexOf('.')
    if ($idx -lt 0) { return $null }
    if ($idx -eq 0) { return $null }
    return $name.Substring($idx + 1)
}

function Get-BoabLanguage {
    <#
    .SYNOPSIS
    Port of `Language::from_path(..).unwrap_or(Language::Generic)`. Returns the
    Debug name of the language.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    $ext = Get-BoabPathExtension -Path $Path
    if ($null -eq $ext) { return 'Generic' }
    $lower = $ext.ToLowerInvariant()
    $table = Get-BoabLanguageTable
    if ($table.ContainsKey($lower)) {
        return $table[$lower]
    }
    return 'Generic'
}

# Patterns shared across every language (algorithm names in literal strings).
# Order matters: findings are emitted pattern-by-pattern in this order.
function New-BoabGenericPatternTable {
    return @(
    # Broken hashes.
    (New-BoabAlgorithmPattern '(?i)\bMD5\b' 'MD5' 'vulnerable' 'high' 'hash' $null)
    (New-BoabAlgorithmPattern '(?i)\bSHA[-_]?1\b' 'SHA-1' 'vulnerable' 'high' 'hash' $null)
    # RSA sizes.
    (New-BoabAlgorithmPattern '(?i)\bRSA[-_]?1024\b' 'RSA' 'vulnerable' 'high' 'signature' 1024)
    (New-BoabAlgorithmPattern '(?i)\bRSA[-_]?2048\b' 'RSA' 'vulnerable' 'high' 'signature' 2048)
    (New-BoabAlgorithmPattern '(?i)\bRSA[-_]?3072\b' 'RSA' 'vulnerable' 'high' 'signature' 3072)
    (New-BoabAlgorithmPattern '(?i)\bRSA[-_]?4096\b' 'RSA' 'vulnerable' 'high' 'signature' 4096)
    # Elliptic.
    (New-BoabAlgorithmPattern '(?i)\bECDSA[-_]?P[-_]?256\b' 'ECDSA-P-256' 'vulnerable' 'high' 'signature' 256)
    (New-BoabAlgorithmPattern '(?i)\bECDSA[-_]?P[-_]?384\b' 'ECDSA-P-384' 'vulnerable' 'high' 'signature' 384)
    (New-BoabAlgorithmPattern '(?i)\bED25519\b' 'Ed25519' 'vulnerable' 'high' 'signature' 255)
    (New-BoabAlgorithmPattern '(?i)\bX25519\b' 'X25519' 'vulnerable' 'high' 'key_agreement' 255)
    # Symmetric ok.
    (New-BoabAlgorithmPattern '(?i)\bAES[-_]?256(?:[-_]?(?:GCM|CBC|CCM|CTR))?\b' 'AES-256' 'symmetric_ok' 'high' 'block_cipher' 256)
    (New-BoabAlgorithmPattern '(?i)\bAES[-_]?128(?:[-_]?(?:GCM|CBC|CCM|CTR))?\b' 'AES-128' 'symmetric_ok' 'high' 'block_cipher' 128)
    (New-BoabAlgorithmPattern '(?i)\bChaCha20(?:[-_]?Poly1305)?\b' 'ChaCha20-Poly1305' 'symmetric_ok' 'high' 'stream_cipher' 256)
    (New-BoabAlgorithmPattern '(?i)\bSHA[-_]?256\b' 'SHA-256' 'symmetric_ok' 'high' 'hash' $null)
    (New-BoabAlgorithmPattern '(?i)\bSHA[-_]?384\b' 'SHA-384' 'symmetric_ok' 'high' 'hash' $null)
    (New-BoabAlgorithmPattern '(?i)\bSHA[-_]?512\b' 'SHA-512' 'symmetric_ok' 'high' 'hash' $null)
    # PQC.
    (New-BoabAlgorithmPattern '(?i)\bML[-_]?KEM[-_]?(?:512|768|1024)?\b' 'ML-KEM' 'resistant' 'high' 'kem' $null)
    (New-BoabAlgorithmPattern '(?i)\bML[-_]?DSA[-_]?(?:44|65|87)?\b' 'ML-DSA' 'resistant' 'high' 'signature' $null)
    (New-BoabAlgorithmPattern '(?i)\bSLH[-_]?DSA\b' 'SLH-DSA' 'resistant' 'high' 'signature' $null)
    (New-BoabAlgorithmPattern '(?i)\bKyber(?:512|768|1024)?\b' 'Kyber' 'resistant' 'high' 'kem' $null)
    (New-BoabAlgorithmPattern '(?i)\bDilithium[2-5]?\b' 'Dilithium' 'resistant' 'high' 'signature' $null)
    # Hybrid signal.
    (New-BoabAlgorithmPattern '(?i)\bX25519MLKEM768\b' 'X25519MLKEM768' 'hybrid' 'high' 'kem' $null)
    # Other broken or weak primitives.
    (New-BoabAlgorithmPattern '(?i)\b3DES\b|\bTripleDES\b|\bDES[-_]EDE3?\b' '3DES' 'vulnerable' 'high' 'block_cipher' 168)
    (New-BoabAlgorithmPattern '(?i)\bRC4\b' 'RC4' 'vulnerable' 'high' 'stream_cipher' $null)
    # JWT alg tokens (often appear inside JSON or code).
    (New-BoabAlgorithmPattern '"alg"\s*:\s*"RS256"' 'RSA' 'vulnerable' 'high' 'signature' 2048)
    (New-BoabAlgorithmPattern '"alg"\s*:\s*"ES256"' 'ECDSA-P-256' 'vulnerable' 'high' 'signature' 256)
    (New-BoabAlgorithmPattern '"alg"\s*:\s*"EdDSA"' 'Ed25519' 'vulnerable' 'high' 'signature' 255)
    (New-BoabAlgorithmPattern '"alg"\s*:\s*"HS256"' 'HMAC-SHA256' 'symmetric_ok' 'high' 'mac' $null)
    )
}

# Lower-confidence library import patterns. They show that crypto is in use
# even when the algorithm can't be inferred. Only applied to files of the
# matching language.
function New-BoabLibraryPatternTable {
    return @(
    # Rust.
    (New-BoabLibraryPattern '\buse\s+ring(?:::|;)' 'ring' 'Rust' 'medium')
    (New-BoabLibraryPattern '\buse\s+rustls(?:::|;)' 'rustls' 'Rust' 'medium')
    (New-BoabLibraryPattern '\buse\s+openssl(?:::|;)' 'openssl' 'Rust' 'medium')
    (New-BoabLibraryPattern '\buse\s+sha2(?:::|;)' 'sha2' 'Rust' 'medium')
    # Go.
    (New-BoabLibraryPattern '"crypto/[a-z0-9]+"' 'stdlib crypto' 'Go' 'medium')
    (New-BoabLibraryPattern '"golang\.org/x/crypto/[a-z0-9]+"' 'x/crypto' 'Go' 'medium')
    # Python.
    (New-BoabLibraryPattern '(?m)^\s*(?:from|import)\s+cryptography(?:\.|\s|$)' 'cryptography' 'Python' 'medium')
    (New-BoabLibraryPattern '(?m)^\s*(?:from|import)\s+Crypto(?:\.|\s|$)' 'pycryptodome' 'Python' 'medium')
    (New-BoabLibraryPattern '(?m)^\s*(?:from|import)\s+hashlib' 'hashlib' 'Python' 'medium')
    (New-BoabLibraryPattern '(?m)^\s*(?:from|import)\s+ssl' 'ssl' 'Python' 'medium')
    (New-BoabLibraryPattern '(?m)^\s*(?:from|import)\s+jwt' 'pyjwt' 'Python' 'medium')
    # JavaScript.
    (New-BoabLibraryPattern 'require\(\s*["'']crypto["'']\s*\)' 'node:crypto' 'JavaScript' 'medium')
    (New-BoabLibraryPattern 'from\s+["'']crypto["'']' 'node:crypto' 'JavaScript' 'medium')
    (New-BoabLibraryPattern 'require\(\s*["'']node-forge["'']\s*\)' 'node-forge' 'JavaScript' 'medium')
    (New-BoabLibraryPattern 'require\(\s*["'']tweetnacl["'']\s*\)' 'tweetnacl' 'JavaScript' 'medium')
    (New-BoabLibraryPattern 'require\(\s*["'']jsonwebtoken["'']\s*\)' 'jsonwebtoken' 'JavaScript' 'medium')
    # Java.
    (New-BoabLibraryPattern '\bimport\s+javax\.crypto\.' 'javax.crypto' 'Java' 'medium')
    (New-BoabLibraryPattern '\bimport\s+java\.security\.' 'java.security' 'Java' 'medium')
    (New-BoabLibraryPattern '\bimport\s+org\.bouncycastle\.' 'BouncyCastle' 'Java' 'medium')
    # .NET.
    (New-BoabLibraryPattern '\busing\s+System\.Security\.Cryptography\b' 'System.Security.Cryptography' 'DotNet' 'medium')
    )
}

function Get-BoabGenericPatterns {
    <# .SYNOPSIS The GENERIC pattern pack, in Rust order (compiled once, then cached). #>
    [CmdletBinding()]
    param()
    if ($null -eq (Get-Variable -Name BoabGenericPatternCache -Scope Script -ValueOnly -ErrorAction Ignore)) {
        $script:BoabGenericPatternCache = New-BoabGenericPatternTable
    }
    return , $script:BoabGenericPatternCache
}

function Get-BoabLibraryPatterns {
    <# .SYNOPSIS The LIBRARIES pattern pack, in Rust order (compiled once, then cached). #>
    [CmdletBinding()]
    param()
    if ($null -eq (Get-Variable -Name BoabLibraryPatternCache -Scope Script -ValueOnly -ErrorAction Ignore)) {
        $script:BoabLibraryPatternCache = New-BoabLibraryPatternTable
    }
    return , $script:BoabLibraryPatternCache
}
