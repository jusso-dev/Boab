#Requires -Version 7.2
<#
    Pester 5 tests for the Boab PowerShell scanners (codebase, certificate
    store, TLS).

    The parity tests compare scanner output with real output from the Rust
    `boab` 0.1.0 binary, recorded in this file as $script:RustReference
    (finding ids, scan ids and timestamps removed; the scanned root replaced
    by "<ROOT>"). examples/demo/.boab is not committed, so the reference was
    produced by running the Rust binary on:
      * examples/demo/app, examples/demo/certs  (the demo inputs)
      * tests/fixtures/codebase, tests/fixtures/certs
      * an edge-case tree ($script:EdgeTreeFiles) and a certificate tree
        ($script:CertTreeFiles) that the tests recreate under TestDrive.
    Findings are compared as sorted sets: Rust walks directories in OS order,
    the port walks them in ordinal name order.

    Optional:
      $env:BOAB_RUST_BIN = path to a built `boab` binary also runs a live
        diff against it on the fixtures.
      $env:BOAB_NETWORK_TESTS = '1' runs the 'Network'-tagged live TLS checks
        against badssl.com (skipped by default).
#>

BeforeDiscovery {
    $script:HasRustBinary = -not [string]::IsNullOrEmpty($env:BOAB_RUST_BIN) -and (Test-Path -LiteralPath $env:BOAB_RUST_BIN)
    $script:RunNetworkTests = $env:BOAB_NETWORK_TESTS -eq '1'
}

BeforeAll {
    Set-StrictMode -Version Latest
    $script:RepoRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', '..'))
    . ([System.IO.Path]::Combine($script:RepoRoot, 'powershell', 'Boab', 'Private', 'ScanModel.ps1'))
    foreach ($file in (Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($script:RepoRoot, 'powershell', 'Boab', 'Private', 'Scanners')) -Filter '*.ps1' | Sort-Object Name)) {
        . $file.FullName
    }

    function ConvertTo-TestJson {
        param($InputObject)
        return (ConvertTo-Json -InputObject $InputObject -Depth 32 -Compress)
    }

    function Get-NormalizedJson {
        param([string] $Json, [string] $Root)
        $escRoot = (ConvertTo-TestJson $Root).Trim('"')
        $j = $Json.Replace($escRoot, '<ROOT>')
        if ($IsWindows) { $j = $j.Replace('\\', '/') }
        return $j
    }

    function Get-NormalizedScan {
        <# Header JSON + sorted finding JSON for a PowerShell scan. #>
        param($Scan, [string] $Root, [string[]] $DropLocationsLike = @())
        $hdr = [ordered]@{
            name          = $Scan.name
            scan_type     = $Scan.scan_type
            status        = $Scan.status
            target        = $Scan.target
            config        = $Scan.config
            error_message = $Scan.error_message
        }
        $findings = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $Scan.findings) {
            $o = [ordered]@{
                source_type     = $f.source_type
                source_location = $f.source_location
                evidence        = $f.evidence
                confidence      = $f.confidence
                status          = $f.status
            }
            $j = Get-NormalizedJson -Json (ConvertTo-TestJson $o) -Root $Root
            $skip = $false
            foreach ($pattern in $DropLocationsLike) { if ($j -like "*""source_location"":""$pattern*") { $skip = $true } }
            if (-not $skip) { $findings.Add($j) }
        }
        $arr = $findings.ToArray()
        [Array]::Sort($arr, [System.StringComparer]::Ordinal)
        return [pscustomobject]@{
            Header   = Get-NormalizedJson -Json (ConvertTo-TestJson $hdr) -Root $Root
            Findings = $arr
        }
    }

    function Get-ExpectedScan {
        <# Header JSON + sorted finding JSON for a recorded Rust scan. #>
        param([string] $Key, [string[]] $DropLocationsLike = @())
        $d = $script:RustReference[$Key] | ConvertFrom-Json
        $findings = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $d.findings) {
            $j = ConvertTo-TestJson $f
            $skip = $false
            foreach ($pattern in $DropLocationsLike) { if ($j -like "*""source_location"":""$pattern*") { $skip = $true } }
            if (-not $skip) { $findings.Add($j) }
        }
        $arr = $findings.ToArray()
        [Array]::Sort($arr, [System.StringComparer]::Ordinal)
        return [pscustomobject]@{
            Header   = ConvertTo-TestJson $d.scan
            Findings = $arr
        }
    }

    function Assert-ScanMatchesReference {
        param($Actual, $Expected)
        $Actual.Header | Should -BeExactly $Expected.Header
        $missing = @($Expected.Findings | Where-Object { $Actual.Findings -cnotcontains $_ })
        $extra = @($Actual.Findings | Where-Object { $Expected.Findings -cnotcontains $_ })
        ($missing -join "`n") | Should -BeExactly '' -Because 'every Rust finding must be produced'
        ($extra -join "`n") | Should -BeExactly '' -Because 'no finding beyond Rust''s may be produced'
        $Actual.Findings.Count | Should -Be $Expected.Findings.Count
    }

    function Write-TreeFromTable {
        param($Table, [string] $Root, [string[]] $Skip = @())
        foreach ($rel in $Table.Keys) {
            if ($Skip -contains $rel) { continue }
            $path = [System.IO.Path]::Combine($Root, $rel)
            $dir = [System.IO.Path]::GetDirectoryName($path)
            [void][System.IO.Directory]::CreateDirectory($dir)
            [System.IO.File]::WriteAllBytes($path, [System.Convert]::FromBase64String($Table[$rel]))
        }
    }

    function ConvertFrom-TestHex {
        param([string] $Hex)
        $h = $Hex -replace '\s', ''
        return , [System.Convert]::FromHexString($h)
    }

# --- Generated reference data (Rust boab 0.1.0 output). Do not edit by hand. ---
$script:RustReference = @{
    'demo_app' = @'
{"scan":{"name":"codebase:<ROOT>","scan_type":"codebase","status":"completed","target":"<ROOT>","config":{"include":[],"exclude":[],"default_excludes":["node_modules","vendor",".venv","venv","target","dist","build",".git"]},"error_message":null},"findings":[{"source_type":"file","source_location":"crypto.py:1","evidence":{"kind":"library_import","library_name":"hashlib","language":"Python","match":"import hashlib","line":1,"snippet":"import hashlib\nfrom Crypto.PublicKey import RSA, DSA"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"crypto.py:10","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-1","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"sha1","line":10,"snippet":"def sha1_digest(data: bytes) -> str:\n    return hashlib.sha1(data).hexdigest()\n"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"crypto.py:2","evidence":{"kind":"library_import","library_name":"pycryptodome","language":"Python","match":"from Crypto.","line":2,"snippet":"import hashlib\nfrom Crypto.PublicKey import RSA, DSA\nfrom Crypto.Cipher import DES, AES"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"crypto.py:3","evidence":{"kind":"library_import","library_name":"pycryptodome","language":"Python","match":"from Crypto.","line":3,"snippet":"from Crypto.PublicKey import RSA, DSA\nfrom Crypto.Cipher import DES, AES\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"crypto.py:5","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"MD5","line":5,"snippet":"\n# legacy MD5 fingerprint\ndef fingerprint(data: bytes) -> str:"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"crypto.py:7","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"md5","line":7,"snippet":"def fingerprint(data: bytes) -> str:\n    return hashlib.md5(data).hexdigest()\n"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"handshake.go:21","evidence":{"kind":"algorithm_match","algorithm_name":"X25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"key_agreement"},"language":"Go","match":"X25519","line":21,"snippet":"    return &tls.Config{\n        CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},\n        MinVersion:       tls.VersionTLS12,"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"handshake.go:4","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/ecdsa\"","line":4,"snippet":"import (\n    \"crypto/ecdsa\"\n    \"crypto/elliptic\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"handshake.go:5","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/elliptic\"","line":5,"snippet":"    \"crypto/ecdsa\"\n    \"crypto/elliptic\"\n    \"crypto/rand\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"handshake.go:6","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/rand\"","line":6,"snippet":"    \"crypto/elliptic\"\n    \"crypto/rand\"\n    \"crypto/rsa\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"handshake.go:7","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/rsa\"","line":7,"snippet":"    \"crypto/rand\"\n    \"crypto/rsa\"\n    \"crypto/tls\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"handshake.go:8","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/tls\"","line":8,"snippet":"    \"crypto/rsa\"\n    \"crypto/tls\"\n)"},"confidence":"medium","status":"new"}]}
'@
    'demo_certs' = @'
{"scan":{"name":"certs:<ROOT>","scan_type":"certificate_store","status":"completed","target":"<ROOT>","config":{"password_provided":false},"error_message":null},"findings":[{"source_type":"cert_subject","source_location":"<ROOT>/ecdsa-p256.crt|CN=ecdsa-p256.example, O=Boab Demo, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/ecdsa-p256.crt","subject":"CN=ecdsa-p256.example, O=Boab Demo, C=AU","issuer":"CN=ecdsa-p256.example, O=Boab Demo, C=AU","signature_algorithm":"ecdsa-with-SHA256","signature_algorithm_oid":"1.2.840.10045.4.3.2","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1779154843,"not_after_unix":1810690843,"fingerprint_sha256":"feb838c7343f8a70b439e4c1d553d9d16df2c83d002de19ac41e43e62d06c340","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/expired.crt|CN=expired.example, O=Boab Demo, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/expired.crt","subject":"CN=expired.example, O=Boab Demo, C=AU","issuer":"CN=expired.example, O=Boab Demo, C=AU","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1704067200,"not_after_unix":1717200000,"fingerprint_sha256":"e6cd82b78dc009b04e7eb0f816dba0a6b5969780b910d7c7b3fac2ce924f57a9","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/rsa1024.crt|CN=weak-rsa1024.example, O=Boab Demo, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/rsa1024.crt","subject":"CN=weak-rsa1024.example, O=Boab Demo, C=AU","issuer":"CN=weak-rsa1024.example, O=Boab Demo, C=AU","signature_algorithm":"sha1WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.5","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1779154842,"not_after_unix":1810690842,"fingerprint_sha256":"51a7143127e25ec628a634364083d4beac86cda2c08e23681e7dad7880b9b0b6","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/rsa2048.crt|CN=rsa2048.example, O=Boab Demo, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/rsa2048.crt","subject":"CN=rsa2048.example, O=Boab Demo, C=AU","issuer":"CN=rsa2048.example, O=Boab Demo, C=AU","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1779154842,"not_after_unix":1810690842,"fingerprint_sha256":"4b9aaeda695de97bc1734caf27c53f39a5c08397692284892894cdd4705d97e2","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/rsa4096.crt|CN=long-lived-rsa4096.example, O=Boab Demo, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/rsa4096.crt","subject":"CN=long-lived-rsa4096.example, O=Boab Demo, C=AU","issuer":"CN=long-lived-rsa4096.example, O=Boab Demo, C=AU","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1779154843,"not_after_unix":2409874843,"fingerprint_sha256":"2315e518344eecdd494735e1bab3474daa67e7a7440a60f16db7e2091d58bee6","pqc_status":"vulnerable"},"confidence":"high","status":"new"}]}
'@
    'fixtures_codebase' = @'
{"scan":{"name":"codebase:<ROOT>","scan_type":"codebase","status":"completed","target":"<ROOT>","config":{"include":[],"exclude":[],"default_excludes":["node_modules","vendor",".venv","venv","target","dist","build",".git"]},"error_message":null},"findings":[{"source_type":"file","source_location":"dotnet/Example.cs:1","evidence":{"kind":"library_import","library_name":"System.Security.Cryptography","language":"DotNet","match":"using System.Security.Cryptography","line":1,"snippet":"using System.Security.Cryptography;\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"dotnet/Example.cs:3","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-384","pqc_status":"vulnerable","parameter_set":{"key_size_bits":384,"primitive":"signature"},"language":"DotNet","match":"ECDSA-P-384","line":3,"snippet":"\n// SHA-384 hashes and ECDSA-P-384 signatures.\npublic static class Example"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"dotnet/Example.cs:3","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-384","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"DotNet","match":"SHA-384","line":3,"snippet":"\n// SHA-384 hashes and ECDSA-P-384 signatures.\npublic static class Example"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"dotnet/Example.cs:6","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-384","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"DotNet","match":"SHA-384","line":6,"snippet":"{\n    public const string Hash = \"SHA-384\";\n    public const string Sig = \"ECDSA-P-384\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"dotnet/Example.cs:7","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-384","pqc_status":"vulnerable","parameter_set":{"key_size_bits":384,"primitive":"signature"},"language":"DotNet","match":"ECDSA-P-384","line":7,"snippet":"    public const string Hash = \"SHA-384\";\n    public const string Sig = \"ECDSA-P-384\";\n}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:10","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-256","pqc_status":"vulnerable","parameter_set":{"key_size_bits":256,"primitive":"signature"},"language":"Go","match":"ECDSA-P-256","line":10,"snippet":"// Cipher suites observed: AES-256-GCM, ChaCha20-Poly1305.\n// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon.\n// X25519 and Ed25519 remain in use for short-term keys."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:10","evidence":{"kind":"algorithm_match","algorithm_name":"Kyber","pqc_status":"resistant","parameter_set":{"primitive":"kem"},"language":"Go","match":"Kyber768","line":10,"snippet":"// Cipher suites observed: AES-256-GCM, ChaCha20-Poly1305.\n// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon.\n// X25519 and Ed25519 remain in use for short-term keys."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:11","evidence":{"kind":"algorithm_match","algorithm_name":"Ed25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"signature"},"language":"Go","match":"Ed25519","line":11,"snippet":"// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon.\n// X25519 and Ed25519 remain in use for short-term keys.\nconst Note = \"RC4 must not be used\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:11","evidence":{"kind":"algorithm_match","algorithm_name":"X25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"key_agreement"},"language":"Go","match":"X25519","line":11,"snippet":"// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon.\n// X25519 and Ed25519 remain in use for short-term keys.\nconst Note = \"RC4 must not be used\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:12","evidence":{"kind":"algorithm_match","algorithm_name":"RC4","pqc_status":"vulnerable","parameter_set":{"primitive":"stream_cipher"},"language":"Go","match":"RC4","line":12,"snippet":"// X25519 and Ed25519 remain in use for short-term keys.\nconst Note = \"RC4 must not be used\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:4","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/ecdsa\"","line":4,"snippet":"import (\n\t\"crypto/ecdsa\"\n\t\"crypto/sha256\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"go/example.go:5","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Go","match":"sha256","line":5,"snippet":"\t\"crypto/ecdsa\"\n\t\"crypto/sha256\"\n\t\"golang.org/x/crypto/chacha20poly1305\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:5","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/sha256\"","line":5,"snippet":"\t\"crypto/ecdsa\"\n\t\"crypto/sha256\"\n\t\"golang.org/x/crypto/chacha20poly1305\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"go/example.go:6","evidence":{"kind":"algorithm_match","algorithm_name":"ChaCha20-Poly1305","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"stream_cipher"},"language":"Go","match":"chacha20poly1305","line":6,"snippet":"\t\"crypto/sha256\"\n\t\"golang.org/x/crypto/chacha20poly1305\"\n)"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:6","evidence":{"kind":"library_import","library_name":"x/crypto","language":"Go","match":"\"golang.org/x/crypto/chacha20poly1305\"","line":6,"snippet":"\t\"crypto/sha256\"\n\t\"golang.org/x/crypto/chacha20poly1305\"\n)"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"go/example.go:9","evidence":{"kind":"algorithm_match","algorithm_name":"AES-256","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"block_cipher"},"language":"Go","match":"AES-256-GCM","line":9,"snippet":"\n// Cipher suites observed: AES-256-GCM, ChaCha20-Poly1305.\n// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"go/example.go:9","evidence":{"kind":"algorithm_match","algorithm_name":"ChaCha20-Poly1305","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"stream_cipher"},"language":"Go","match":"ChaCha20-Poly1305","line":9,"snippet":"\n// Cipher suites observed: AES-256-GCM, ChaCha20-Poly1305.\n// Curves: ECDSA-P-256 today, target Kyber768 hybrid soon."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"java/Example.java:1","evidence":{"kind":"library_import","library_name":"javax.crypto","language":"Java","match":"import javax.crypto.","line":1,"snippet":"import javax.crypto.Cipher;\nimport java.security.MessageDigest;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"java/Example.java:2","evidence":{"kind":"library_import","library_name":"java.security","language":"Java","match":"import java.security.","line":2,"snippet":"import javax.crypto.Cipher;\nimport java.security.MessageDigest;\nimport org.bouncycastle.crypto.engines.AESEngine;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"java/Example.java:3","evidence":{"kind":"library_import","library_name":"BouncyCastle","language":"Java","match":"import org.bouncycastle.","line":3,"snippet":"import java.security.MessageDigest;\nimport org.bouncycastle.crypto.engines.AESEngine;\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"java/Example.java:6","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":4096,"primitive":"signature"},"language":"Java","match":"RSA-4096","line":6,"snippet":"public class Example {\n    // RSA-4096 legacy chain, target SLH-DSA.\n    static final String LEGACY = \"RSA-4096\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"java/Example.java:6","evidence":{"kind":"algorithm_match","algorithm_name":"SLH-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Java","match":"SLH-DSA","line":6,"snippet":"public class Example {\n    // RSA-4096 legacy chain, target SLH-DSA.\n    static final String LEGACY = \"RSA-4096\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"java/Example.java:7","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":4096,"primitive":"signature"},"language":"Java","match":"RSA-4096","line":7,"snippet":"    // RSA-4096 legacy chain, target SLH-DSA.\n    static final String LEGACY = \"RSA-4096\";\n    static final String TARGET = \"SLH-DSA\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"java/Example.java:8","evidence":{"kind":"algorithm_match","algorithm_name":"SLH-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Java","match":"SLH-DSA","line":8,"snippet":"    static final String LEGACY = \"RSA-4096\";\n    static final String TARGET = \"SLH-DSA\";\n    static final String HASH = \"SHA-512\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"java/Example.java:9","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-512","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Java","match":"SHA-512","line":9,"snippet":"    static final String TARGET = \"SLH-DSA\";\n    static final String HASH = \"SHA-512\";\n}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"js/example.js:1","evidence":{"kind":"library_import","library_name":"node:crypto","language":"JavaScript","match":"require('crypto')","line":1,"snippet":"const crypto = require('crypto');\nconst forge = require('node-forge');"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"js/example.js:10","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"JavaScript","match":"3DES","line":10,"snippet":"\n// Banned 3DES legacy.\nconst banned = \"3DES\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"js/example.js:11","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"JavaScript","match":"3DES","line":11,"snippet":"// Banned 3DES legacy.\nconst banned = \"3DES\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"js/example.js:2","evidence":{"kind":"library_import","library_name":"node-forge","language":"JavaScript","match":"require('node-forge')","line":2,"snippet":"const crypto = require('crypto');\nconst forge = require('node-forge');\nconst jwt = require('jsonwebtoken');"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"js/example.js:3","evidence":{"kind":"library_import","library_name":"jsonwebtoken","language":"JavaScript","match":"require('jsonwebtoken')","line":3,"snippet":"const forge = require('node-forge');\nconst jwt = require('jsonwebtoken');\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"js/example.js:6","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":2048,"primitive":"signature"},"language":"JavaScript","match":"\"alg\":\"RS256\"","line":6,"snippet":"// JWT alg patterns appear in literal strings.\nconst token = {\"alg\":\"RS256\"};\nconst e = {\"alg\":\"ES256\"};"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"js/example.js:7","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-256","pqc_status":"vulnerable","parameter_set":{"key_size_bits":256,"primitive":"signature"},"language":"JavaScript","match":"\"alg\":\"ES256\"","line":7,"snippet":"const token = {\"alg\":\"RS256\"};\nconst e = {\"alg\":\"ES256\"};\nconst h = {\"alg\":\"HS256\"};"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"js/example.js:8","evidence":{"kind":"algorithm_match","algorithm_name":"HMAC-SHA256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"mac"},"language":"JavaScript","match":"\"alg\":\"HS256\"","line":8,"snippet":"const e = {\"alg\":\"ES256\"};\nconst h = {\"alg\":\"HS256\"};\n"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:1","evidence":{"kind":"library_import","library_name":"cryptography","language":"Python","match":"from cryptography.","line":1,"snippet":"from cryptography.hazmat.primitives import hashes\nimport hashlib"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"python/example.py:10","evidence":{"kind":"algorithm_match","algorithm_name":"ML-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Python","match":"ML-DSA-65","line":10,"snippet":"# Plan: ML-DSA-65 signatures.\nSIG = \"ML-DSA-65\"\n# Legacy."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:12","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":1024,"primitive":"signature"},"language":"Python","match":"RSA-1024","line":12,"snippet":"# Legacy.\nLEGACY_RSA = \"RSA-1024\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:2","evidence":{"kind":"library_import","library_name":"hashlib","language":"Python","match":"import hashlib","line":2,"snippet":"from cryptography.hazmat.primitives import hashes\nimport hashlib\nimport ssl"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"python/example.py:3","evidence":{"kind":"library_import","library_name":"ssl","language":"Python","match":"import ssl","line":3,"snippet":"import hashlib\nimport ssl\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"python/example.py:5","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-1","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"SHA-1","line":5,"snippet":"\n# SHA-1 fingerprints are deprecated.\nH = \"SHA-1\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:6","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-1","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"SHA-1","line":6,"snippet":"# SHA-1 fingerprints are deprecated.\nH = \"SHA-1\"\n# AES-128 GCM session keys."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:7","evidence":{"kind":"algorithm_match","algorithm_name":"AES-128","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":128,"primitive":"block_cipher"},"language":"Python","match":"AES-128","line":7,"snippet":"H = \"SHA-1\"\n# AES-128 GCM session keys.\nCIPHER = \"AES-128-GCM\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:8","evidence":{"kind":"algorithm_match","algorithm_name":"AES-128","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":128,"primitive":"block_cipher"},"language":"Python","match":"AES-128-GCM","line":8,"snippet":"# AES-128 GCM session keys.\nCIPHER = \"AES-128-GCM\"\n# Plan: ML-DSA-65 signatures."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"python/example.py:9","evidence":{"kind":"algorithm_match","algorithm_name":"ML-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Python","match":"ML-DSA-65","line":9,"snippet":"CIPHER = \"AES-128-GCM\"\n# Plan: ML-DSA-65 signatures.\nSIG = \"ML-DSA-65\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:10","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Rust","match":"MD5","line":10,"snippet":"    // MD5 must be banned.\n    let _ = \"MD5\";\n    // We are migrating to ML-KEM-768."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:11","evidence":{"kind":"algorithm_match","algorithm_name":"ML-KEM","pqc_status":"resistant","parameter_set":{"primitive":"kem"},"language":"Rust","match":"ML-KEM-768","line":11,"snippet":"    let _ = \"MD5\";\n    // We are migrating to ML-KEM-768.\n    let _ = \"ML-KEM-768\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:12","evidence":{"kind":"algorithm_match","algorithm_name":"ML-KEM","pqc_status":"resistant","parameter_set":{"primitive":"kem"},"language":"Rust","match":"ML-KEM-768","line":12,"snippet":"    // We are migrating to ML-KEM-768.\n    let _ = \"ML-KEM-768\";\n    // SHA-256 is safe symmetrically."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:13","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Rust","match":"SHA-256","line":13,"snippet":"    let _ = \"ML-KEM-768\";\n    // SHA-256 is safe symmetrically.\n    let _ = \"SHA-256\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:14","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Rust","match":"SHA-256","line":14,"snippet":"    // SHA-256 is safe symmetrically.\n    let _ = \"SHA-256\";\n}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:2","evidence":{"kind":"library_import","library_name":"ring","language":"Rust","match":"use ring;","line":2,"snippet":"// Boab test fixture - Rust.\nuse ring;\nuse rustls;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"rust/example.rs:3","evidence":{"kind":"library_import","library_name":"rustls","language":"Rust","match":"use rustls;","line":3,"snippet":"use ring;\nuse rustls;\nuse sha2::Sha256;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"rust/example.rs:4","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Rust","match":"Sha256","line":4,"snippet":"use rustls;\nuse sha2::Sha256;\n"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:4","evidence":{"kind":"library_import","library_name":"sha2","language":"Rust","match":"use sha2::","line":4,"snippet":"use rustls;\nuse sha2::Sha256;\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"rust/example.rs:7","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":2048,"primitive":"signature"},"language":"Rust","match":"RSA-2048","line":7,"snippet":"fn legacy() {\n    // RSA-2048 keys are quantum-vulnerable.\n    let _ = \"RSA-2048\";"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:8","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":2048,"primitive":"signature"},"language":"Rust","match":"RSA-2048","line":8,"snippet":"    // RSA-2048 keys are quantum-vulnerable.\n    let _ = \"RSA-2048\";\n    // MD5 must be banned."},"confidence":"high","status":"new"},{"source_type":"file","source_location":"rust/example.rs:9","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Rust","match":"MD5","line":9,"snippet":"    let _ = \"RSA-2048\";\n    // MD5 must be banned.\n    let _ = \"MD5\";"},"confidence":"high","status":"new"}]}
'@
    'fixtures_certs' = @'
{"scan":{"name":"certs:<ROOT>","scan_type":"certificate_store","status":"completed","target":"<ROOT>","config":{"password_provided":false},"error_message":null},"findings":[{"source_type":"cert_subject","source_location":"<ROOT>/rsa2048-selfsigned.pem|CN=boab-test, O=Boab, C=AU","evidence":{"kind":"tls_certificate","target":"<ROOT>/rsa2048-selfsigned.pem","subject":"CN=boab-test, O=Boab, C=AU","issuer":"CN=boab-test, O=Boab, C=AU","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1779144968,"not_after_unix":2094504968,"fingerprint_sha256":"a1d6a45c575e4b17b11f371e570e92316037041c755c4eff1d46e0e4eb29325e","pqc_status":"vulnerable"},"confidence":"high","status":"new"}]}
'@
    'edge' = @'
{"scan":{"name":"codebase:<ROOT>","scan_type":"codebase","status":"completed","target":"<ROOT>","config":{"include":[],"exclude":[],"default_excludes":["node_modules","vendor",".venv","venv","target","dist","build",".git"]},"error_message":null},"findings":[{"source_type":"file","source_location":"Example.java:1","evidence":{"kind":"library_import","library_name":"javax.crypto","language":"Java","match":"import javax.crypto.","line":1,"snippet":"import javax.crypto.Cipher;\nimport java.security.KeyPair;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"Example.java:2","evidence":{"kind":"library_import","library_name":"java.security","language":"Java","match":"import java.security.","line":2,"snippet":"import javax.crypto.Cipher;\nimport java.security.KeyPair;\nimport org.bouncycastle.jce.X;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"Example.java:3","evidence":{"kind":"library_import","library_name":"BouncyCastle","language":"Java","match":"import org.bouncycastle.","line":3,"snippet":"import java.security.KeyPair;\nimport org.bouncycastle.jce.X;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"KEY.KEY","evidence":{"kind":"cert_or_keystore_file","extension":"key","size_bytes":1},"confidence":"low","status":"new"},{"source_type":"file","source_location":"Prog.cs:1","evidence":{"kind":"library_import","library_name":"System.Security.Cryptography","language":"DotNet","match":"using System.Security.Cryptography","line":1,"snippet":"using System.Security.Cryptography;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"a.py:1","evidence":{"kind":"library_import","library_name":"hashlib","language":"Python","match":"import hashlib","line":1,"snippet":"import hashlib\nh = hashlib.md5()"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"a.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"md5","line":2,"snippet":"import hashlib\nh = hashlib.md5()"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"bom.txt:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Generic","match":"MD5","line":1,"snippet":"\ufeffMD5 bom"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:1","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":2048,"primitive":"signature"},"language":"Generic","match":"\"alg\": \"RS256\"","line":1,"snippet":"{\"alg\": \"RS256\"}\n{\"alg\":\"ES256\"}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:2","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-256","pqc_status":"vulnerable","parameter_set":{"key_size_bits":256,"primitive":"signature"},"language":"Generic","match":"\"alg\":\"ES256\"","line":2,"snippet":"{\"alg\": \"RS256\"}\n{\"alg\":\"ES256\"}\n{\"alg\" : \"EdDSA\"}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:3","evidence":{"kind":"algorithm_match","algorithm_name":"Ed25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"signature"},"language":"Generic","match":"\"alg\" : \"EdDSA\"","line":3,"snippet":"{\"alg\":\"ES256\"}\n{\"alg\" : \"EdDSA\"}\n{\"alg\":\"HS256\"}"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:4","evidence":{"kind":"algorithm_match","algorithm_name":"HMAC-SHA256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"mac"},"language":"Generic","match":"\"alg\":\"HS256\"","line":4,"snippet":"{\"alg\" : \"EdDSA\"}\n{\"alg\":\"HS256\"}\nKyber768 Dilithium3"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:5","evidence":{"kind":"algorithm_match","algorithm_name":"Dilithium","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Generic","match":"Dilithium3","line":5,"snippet":"{\"alg\":\"HS256\"}\nKyber768 Dilithium3"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"conf.yaml:5","evidence":{"kind":"algorithm_match","algorithm_name":"Kyber","pqc_status":"resistant","parameter_set":{"primitive":"kem"},"language":"Generic","match":"Kyber768","line":5,"snippet":"{\"alg\":\"HS256\"}\nKyber768 Dilithium3"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"crlf.txt:2","evidence":{"kind":"algorithm_match","algorithm_name":"AES-256","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"block_cipher"},"language":"Generic","match":"AES-256-GCM","line":2,"snippet":"line1\nAES-256-GCM here\nline3"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"deep.txt:4","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Generic","match":"MD5","line":4,"snippet":"c\nd MD5"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"emptyline.py:1","evidence":{"kind":"library_import","library_name":"ssl","language":"Python","match":"\n\nimport ssl","line":1,"snippet":"\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:4","evidence":{"kind":"library_import","library_name":"cryptography","language":"Python","match":"from cryptography.","line":4,"snippet":"import ssl\nfrom cryptography.hazmat import x\nimport Crypto.Cipher"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:5","evidence":{"kind":"library_import","library_name":"pycryptodome","language":"Python","match":"import Crypto.","line":5,"snippet":"from cryptography.hazmat import x\nimport Crypto.Cipher\nimport jwt"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:6","evidence":{"kind":"library_import","library_name":"pyjwt","language":"Python","match":"import jwt","line":6,"snippet":"import Crypto.Cipher\nimport jwt"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"keep.log:1","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-1","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Generic","match":"SHA1","line":1,"snippet":"SHA1 here"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"multi.ts:1","evidence":{"kind":"library_import","library_name":"node:crypto","language":"JavaScript","match":"require( 'crypto' )","line":1,"snippet":"const c = require( 'crypto' );\nimport x from \"crypto\";"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"multi.ts:2","evidence":{"kind":"library_import","library_name":"node:crypto","language":"JavaScript","match":"from \"crypto\"","line":2,"snippet":"const c = require( 'crypto' );\nimport x from \"crypto\";\nrequire('node-forge')"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"multi.ts:3","evidence":{"kind":"library_import","library_name":"node-forge","language":"JavaScript","match":"require('node-forge')","line":3,"snippet":"import x from \"crypto\";\nrequire('node-forge')\nrequire(\"tweetnacl\")"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"multi.ts:4","evidence":{"kind":"library_import","library_name":"tweetnacl","language":"JavaScript","match":"require(\"tweetnacl\")","line":4,"snippet":"require('node-forge')\nrequire(\"tweetnacl\")\nrequire('jsonwebtoken')"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"multi.ts:5","evidence":{"kind":"library_import","library_name":"jsonwebtoken","language":"JavaScript","match":"require('jsonwebtoken')","line":5,"snippet":"require(\"tweetnacl\")\nrequire('jsonwebtoken')"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"noext:1","evidence":{"kind":"algorithm_match","algorithm_name":"ML-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Generic","match":"ML_DSA_65","line":1,"snippet":"ML-KEM-768 and ML_DSA_65 and SLH-DSA"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"noext:1","evidence":{"kind":"algorithm_match","algorithm_name":"ML-KEM","pqc_status":"resistant","parameter_set":{"primitive":"kem"},"language":"Generic","match":"ML-KEM-768","line":1,"snippet":"ML-KEM-768 and ML_DSA_65 and SLH-DSA"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"noext:1","evidence":{"kind":"algorithm_match","algorithm_name":"SLH-DSA","pqc_status":"resistant","parameter_set":{"primitive":"signature"},"language":"Generic","match":"SLH-DSA","line":1,"snippet":"ML-KEM-768 and ML_DSA_65 and SLH-DSA"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"server.pem","evidence":{"kind":"cert_or_keystore_file","extension":"pem","size_bytes":28},"confidence":"low","status":"new"},{"source_type":"file","source_location":"src/build:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Generic","match":"md5","line":1,"snippet":"md5"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/anchored.txt:1","evidence":{"kind":"algorithm_match","algorithm_name":"RC4","pqc_status":"vulnerable","parameter_set":{"primitive":"stream_cipher"},"language":"Generic","match":"RC4","line":1,"snippet":"RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/deep/y.md:1","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"Generic","match":"3DES","line":1,"snippet":"RC4 and 3DES"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/deep/y.md:1","evidence":{"kind":"algorithm_match","algorithm_name":"RC4","pqc_status":"vulnerable","parameter_set":{"primitive":"stream_cipher"},"language":"Generic","match":"RC4","line":1,"snippet":"RC4 and 3DES"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/keep.go:2","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Go","match":"sha256","line":2,"snippet":"import (\n  \"crypto/sha256\"\n  \"golang.org/x/crypto/chacha20poly1305\""},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/keep.go:2","evidence":{"kind":"library_import","library_name":"stdlib crypto","language":"Go","match":"\"crypto/sha256\"","line":2,"snippet":"import (\n  \"crypto/sha256\"\n  \"golang.org/x/crypto/chacha20poly1305\""},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/keep.go:3","evidence":{"kind":"algorithm_match","algorithm_name":"ChaCha20-Poly1305","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"stream_cipher"},"language":"Go","match":"chacha20poly1305","line":3,"snippet":"  \"crypto/sha256\"\n  \"golang.org/x/crypto/chacha20poly1305\"\n)"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/keep.go:3","evidence":{"kind":"library_import","library_name":"x/crypto","language":"Go","match":"\"golang.org/x/crypto/chacha20poly1305\"","line":3,"snippet":"  \"crypto/sha256\"\n  \"golang.org/x/crypto/chacha20poly1305\"\n)"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:1","evidence":{"kind":"library_import","library_name":"ring","language":"Rust","match":"use ring;","line":1,"snippet":"use ring;\nuse rustls::ClientConfig;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:2","evidence":{"kind":"library_import","library_name":"rustls","language":"Rust","match":"use rustls::","line":2,"snippet":"use ring;\nuse rustls::ClientConfig;\nuse openssl::ssl;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:3","evidence":{"kind":"library_import","library_name":"openssl","language":"Rust","match":"use openssl::","line":3,"snippet":"use rustls::ClientConfig;\nuse openssl::ssl;\nuse sha2::Sha256;"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:4","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Rust","match":"Sha256","line":4,"snippet":"use openssl::ssl;\nuse sha2::Sha256;\n// x25519 ed25519 X25519MLKEM768"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:4","evidence":{"kind":"library_import","library_name":"sha2","language":"Rust","match":"use sha2::","line":4,"snippet":"use openssl::ssl;\nuse sha2::Sha256;\n// x25519 ed25519 X25519MLKEM768"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:5","evidence":{"kind":"algorithm_match","algorithm_name":"Ed25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"signature"},"language":"Rust","match":"ed25519","line":5,"snippet":"use sha2::Sha256;\n// x25519 ed25519 X25519MLKEM768"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:5","evidence":{"kind":"algorithm_match","algorithm_name":"X25519","pqc_status":"vulnerable","parameter_set":{"key_size_bits":255,"primitive":"key_agreement"},"language":"Rust","match":"x25519","line":5,"snippet":"use sha2::Sha256;\n// x25519 ed25519 X25519MLKEM768"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"sub/sub2/nested.rs:5","evidence":{"kind":"algorithm_match","algorithm_name":"X25519MLKEM768","pqc_status":"hybrid","parameter_set":{"primitive":"kem"},"language":"Rust","match":"X25519MLKEM768","line":5,"snippet":"use sha2::Sha256;\n// x25519 ed25519 X25519MLKEM768"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"trail.:1","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":1024,"primitive":"signature"},"language":"Generic","match":"rsa-1024","line":1,"snippet":"RSA-2048 rsa_4096 RSA3072 rsa-1024"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"trail.:1","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":2048,"primitive":"signature"},"language":"Generic","match":"RSA-2048","line":1,"snippet":"RSA-2048 rsa_4096 RSA3072 rsa-1024"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"trail.:1","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":3072,"primitive":"signature"},"language":"Generic","match":"RSA3072","line":1,"snippet":"RSA-2048 rsa_4096 RSA3072 rsa-1024"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"trail.:1","evidence":{"kind":"algorithm_match","algorithm_name":"RSA","pqc_status":"vulnerable","parameter_set":{"key_size_bits":4096,"primitive":"signature"},"language":"Generic","match":"rsa_4096","line":1,"snippet":"RSA-2048 rsa_4096 RSA3072 rsa-1024"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"MD5","line":1,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"Python","match":"DES-EDE3","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"Python","match":"TripleDES","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"AES-128","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":128,"primitive":"block_cipher"},"language":"Python","match":"AES128-CBC","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ChaCha20-Poly1305","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"stream_cipher"},"language":"Python","match":"ChaCha20-Poly1305","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-256","pqc_status":"vulnerable","parameter_set":{"key_size_bits":256,"primitive":"signature"},"language":"Python","match":"ECDSA-P-256","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-384","pqc_status":"vulnerable","parameter_set":{"key_size_bits":384,"primitive":"signature"},"language":"Python","match":"ecdsa_p384","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"RC4","pqc_status":"vulnerable","parameter_set":{"primitive":"stream_cipher"},"language":"Python","match":"RC4","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-384","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Python","match":"sha-384","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-512","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Python","match":"SHA_512","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"web.config.xml:1","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-256","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Generic","match":"SHA256","line":1,"snippet":"<x>SHA256</x>"},"confidence":"high","status":"new"}]}
'@
    'edge_inc' = @'
{"scan":{"name":"edge-inc","scan_type":"codebase","status":"completed","target":"<ROOT>","config":{"include":["*.py"],"exclude":["sub"],"default_excludes":["node_modules","vendor",".venv","venv","target","dist","build",".git"]},"error_message":null},"findings":[{"source_type":"file","source_location":".hidden.py:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"md5","line":1,"snippet":"md5"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"a.py:1","evidence":{"kind":"library_import","library_name":"hashlib","language":"Python","match":"import hashlib","line":1,"snippet":"import hashlib\nh = hashlib.md5()"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"a.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"md5","line":2,"snippet":"import hashlib\nh = hashlib.md5()"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"emptyline.py:1","evidence":{"kind":"library_import","library_name":"ssl","language":"Python","match":"\n\nimport ssl","line":1,"snippet":"\n"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:4","evidence":{"kind":"library_import","library_name":"cryptography","language":"Python","match":"from cryptography.","line":4,"snippet":"import ssl\nfrom cryptography.hazmat import x\nimport Crypto.Cipher"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:5","evidence":{"kind":"library_import","library_name":"pycryptodome","language":"Python","match":"import Crypto.","line":5,"snippet":"from cryptography.hazmat import x\nimport Crypto.Cipher\nimport jwt"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"emptyline.py:6","evidence":{"kind":"library_import","library_name":"pyjwt","language":"Python","match":"import jwt","line":6,"snippet":"import Crypto.Cipher\nimport jwt"},"confidence":"medium","status":"new"},{"source_type":"file","source_location":"ignored_by_dotignore.py:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"md5","line":1,"snippet":"md5"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:1","evidence":{"kind":"algorithm_match","algorithm_name":"MD5","pqc_status":"vulnerable","parameter_set":{"primitive":"hash"},"language":"Python","match":"MD5","line":1,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"Python","match":"DES-EDE3","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"3DES","pqc_status":"vulnerable","parameter_set":{"key_size_bits":168,"primitive":"block_cipher"},"language":"Python","match":"TripleDES","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"AES-128","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":128,"primitive":"block_cipher"},"language":"Python","match":"AES128-CBC","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ChaCha20-Poly1305","pqc_status":"symmetric_ok","parameter_set":{"key_size_bits":256,"primitive":"stream_cipher"},"language":"Python","match":"ChaCha20-Poly1305","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-256","pqc_status":"vulnerable","parameter_set":{"key_size_bits":256,"primitive":"signature"},"language":"Python","match":"ECDSA-P-256","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"ECDSA-P-384","pqc_status":"vulnerable","parameter_set":{"key_size_bits":384,"primitive":"signature"},"language":"Python","match":"ecdsa_p384","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"RC4","pqc_status":"vulnerable","parameter_set":{"primitive":"stream_cipher"},"language":"Python","match":"RC4","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-384","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Python","match":"sha-384","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"uni.py:2","evidence":{"kind":"algorithm_match","algorithm_name":"SHA-512","pqc_status":"symmetric_ok","parameter_set":{"primitive":"hash"},"language":"Python","match":"SHA_512","line":2,"snippet":"\u00e9 MD5 \u00fc\nnext ECDSA-P-256 ecdsa_p384 AES128-CBC ChaCha20-Poly1305 sha-384 SHA_512 TripleDES DES-EDE3 RC4"},"confidence":"high","status":"new"}]}
'@
    'certs_nopw' = @'
{"scan":{"name":"certs-nopw","scan_type":"certificate_store","status":"completed","target":"<ROOT>","config":{"password_provided":false},"error_message":null},"findings":[{"source_type":"cert_subject","source_location":"<ROOT>/bundle.pem|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/bundle.pem","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/bundle.pem|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/bundle.pem","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/crlf.crt|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/crlf.crt","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/leaf.der|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/leaf.der","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/nopass.pfx|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/nopass.pfx","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/sub/ca-der.cer|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/sub/ca-der.cer","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/sub/ed25519.crt|CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","evidence":{"kind":"tls_certificate","target":"<ROOT>/sub/ed25519.crt","subject":"CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","issuer":"CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","signature_algorithm":"Ed25519","signature_algorithm_oid":"1.3.101.112","public_key_algorithm":"Ed25519","public_key_algorithm_oid":"1.3.101.112","not_before_unix":0,"not_after_unix":2556144000,"fingerprint_sha256":"021bab2bc128288acad6249ca1d34730fc3e83947c6af69f5988f90b1d938cdb","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"<ROOT>/store.jks","evidence":{"kind":"cert_or_keystore_file","store_type":"JKS (convert to PKCS12 with keytool for full parsing)"},"confidence":"low","status":"new"}]}
'@
    'certs_pw' = @'
{"scan":{"name":"certs-pw","scan_type":"certificate_store","status":"completed","target":"<ROOT>","config":{"password_provided":true},"error_message":null},"findings":[{"source_type":"cert_subject","source_location":"<ROOT>/bundle.pem|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/bundle.pem","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/bundle.pem|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/bundle.pem","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/chain.p12|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/chain.p12","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/chain.p12|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/chain.p12","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/crlf.crt|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/crlf.crt","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/leaf.der|CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","evidence":{"kind":"tls_certificate","target":"<ROOT>/leaf.der","subject":"CN=leaf.example, OU=Eng + OU=Ops, Email=ops@example.com, serialNumber=1234","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha384WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.12","public_key_algorithm":"EC","public_key_algorithm_oid":"1.2.840.10045.2.1","not_before_unix":1792485762,"not_after_unix":1827045762,"fingerprint_sha256":"5214a25900f9c2049577b8031f2929b9497a425b4bc4b9040c143a1886ce786c","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/sub/ca-der.cer|C=AU, O=Boab Test CA, CN=Boab Root","evidence":{"kind":"tls_certificate","target":"<ROOT>/sub/ca-der.cer","subject":"C=AU, O=Boab Test CA, CN=Boab Root","issuer":"C=AU, O=Boab Test CA, CN=Boab Root","signature_algorithm":"sha256WithRSAEncryption","signature_algorithm_oid":"1.2.840.113549.1.1.11","public_key_algorithm":"RSA","public_key_algorithm_oid":"1.2.840.113549.1.1.1","not_before_unix":1792485762,"not_after_unix":2107845762,"fingerprint_sha256":"90777c9e6cad2da5012e86064cc82ad08c26f070078db7a2eb67e048a4b48b45","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"cert_subject","source_location":"<ROOT>/sub/ed25519.crt|CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","evidence":{"kind":"tls_certificate","target":"<ROOT>/sub/ed25519.crt","subject":"CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","issuer":"CN=ed.example, O=\u00c3\u009cn\u00c3\u00afcode Org","signature_algorithm":"Ed25519","signature_algorithm_oid":"1.3.101.112","public_key_algorithm":"Ed25519","public_key_algorithm_oid":"1.3.101.112","not_before_unix":0,"not_after_unix":2556144000,"fingerprint_sha256":"021bab2bc128288acad6249ca1d34730fc3e83947c6af69f5988f90b1d938cdb","pqc_status":"vulnerable"},"confidence":"high","status":"new"},{"source_type":"file","source_location":"<ROOT>/store.jks","evidence":{"kind":"cert_or_keystore_file","store_type":"JKS (convert to PKCS12 with keytool for full parsing)"},"confidence":"low","status":"new"}]}
'@
}
$script:EdgeTreeFiles = [ordered]@{
    '.gitignore' = 'aWdub3JlZF9kaXIvCioubG9nCiFrZWVwLmxvZwovYW5jaG9yZWQudHh0CnN1Yi9kZWVwLyoudHh0Cg=='
    '.hidden.py' = 'bWQ1Cg=='
    '.hiddendir/h.py' = 'bWQ1Cg=='
    '.ignore' = 'aWdub3JlZF9ieV9kb3RpZ25vcmUucHkK'
    'Example.java' = 'aW1wb3J0IGphdmF4LmNyeXB0by5DaXBoZXI7CmltcG9ydCBqYXZhLnNlY3VyaXR5LktleVBhaXI7CmltcG9ydCBvcmcuYm91bmN5Y2FzdGxlLmpjZS5YOwo='
    'KEY.KEY' = 'eA=='
    'Prog.cs' = 'dXNpbmcgU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeTsK'
    'a.py' = 'aW1wb3J0IGhhc2hsaWIKaCA9IGhhc2hsaWIubWQ1KCkK'
    'anchored.txt' = 'UkM0Cg=='
    'bom.txt' = '77u/TUQ1IGJvbQo='
    'build/out.js' = 'bWQ1Cg=='
    'conf.yaml' = 'eyJhbGciOiAiUlMyNTYifQp7ImFsZyI6IkVTMjU2In0KeyJhbGciIDogIkVkRFNBIn0KeyJhbGciOiJIUzI1NiJ9Ckt5YmVyNzY4IERpbGl0aGl1bTMK'
    'crlf.txt' = 'bGluZTENCkFFUy0yNTYtR0NNIGhlcmUNCmxpbmUzDQo='
    'deep.txt' = 'YQpiCmMKZCBNRDUK'
    'drop.log' = 'U0hBMSBoZXJlCg=='
    'emptyline.py' = 'CgppbXBvcnQgc3NsCmZyb20gY3J5cHRvZ3JhcGh5Lmhhem1hdCBpbXBvcnQgeAppbXBvcnQgQ3J5cHRvLkNpcGhlcgppbXBvcnQgand0Cg=='
    'ignored_by_dotignore.py' = 'bWQ1Cg=='
    'ignored_dir/z.py' = 'bWQ1Cg=='
    'keep.log' = 'U0hBMSBoZXJlCg=='
    'latin1.txt' = 'TUQ1IOkK'
    'multi.ts' = 'Y29uc3QgYyA9IHJlcXVpcmUoICdjcnlwdG8nICk7CmltcG9ydCB4IGZyb20gImNyeXB0byI7CnJlcXVpcmUoJ25vZGUtZm9yZ2UnKQpyZXF1aXJlKCJ0d2VldG5hY2wiKQpyZXF1aXJlKCdqc29ud2VidG9rZW4nKQo='
    'node_modules/x/index.js' = 'bWQ1Cg=='
    'noext' = 'TUwtS0VNLTc2OCBhbmQgTUxfRFNBXzY1IGFuZCBTTEgtRFNB'
    'server.pem' = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg=='
    'src/build' = 'bWQ1Cg=='
    'sub/.gitignore' = 'Ki5nbwoha2VlcC5nbwo='
    'sub/a.go' = 'aW1wb3J0ICJjcnlwdG8vc2hhMjU2Igo='
    'sub/anchored.txt' = 'UkM0Cg=='
    'sub/deep/x.txt' = 'UkM0Cg=='
    'sub/deep/y.md' = 'UkM0IGFuZCAzREVTCg=='
    'sub/keep.go' = 'aW1wb3J0ICgKICAiY3J5cHRvL3NoYTI1NiIKICAiZ29sYW5nLm9yZy94L2NyeXB0by9jaGFjaGEyMHBvbHkxMzA1IgopCg=='
    'sub/sub2/nested.rs' = 'dXNlIHJpbmc7CnVzZSBydXN0bHM6OkNsaWVudENvbmZpZzsKdXNlIG9wZW5zc2w6OnNzbDsKdXNlIHNoYTI6OlNoYTI1NjsKLy8geDI1NTE5IGVkMjU1MTkgWDI1NTE5TUxLRU03NjgK'
    'trail.' = 'UlNBLTIwNDggcnNhXzQwOTYgUlNBMzA3MiByc2EtMTAyNAo='
    'uni.py' = 'w6kgTUQ1IMO8Cm5leHQgRUNEU0EtUC0yNTYgZWNkc2FfcDM4NCBBRVMxMjgtQ0JDIENoYUNoYTIwLVBvbHkxMzA1IHNoYS0zODQgU0hBXzUxMiBUcmlwbGVERVMgREVTLUVERTMgUkM0Cg=='
    'vendor/v.go' = 'bWQ1Cg=='
    'web.config.xml' = 'PHg+U0hBMjU2PC94Pg=='
}
$script:CertTreeFiles = [ordered]@{
    '.hid/hidden.crt' = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNRENDQWhpZ0F3SUJBZ0lVU0w0bEtHVWE5alFwSGNFL3J3aWJBWTdja3F3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd09ERUxNQWtHQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRQpBd3dKUW05aFlpQlNiMjkwTUI0WERUSTJNVEF5TURBNE5ESTBNbG9YRFRNMk1UQXhOekE0TkRJME1sb3dPREVMCk1Ba0dBMVVFQmhNQ1FWVXhGVEFUQmdOVkJBb01ERUp2WVdJZ1ZHVnpkQ0JEUVRFU01CQUdBMVVFQXd3SlFtOWgKWWlCU2IyOTBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWpQeU1wYk4wWGc0bQpGMmdFeW5kd2grS0VmeVBNQnZDQ0FPOWhwZkRLbVNEWmVDblJFT1VOc1dpSnVnbW9zWU9tN0IxSy9tcmd2Q1NHCnBFU2k3OGpMajJPcVY3RHVSQW9RK085QW1FNDFXTlF3VzJjSXA3ZllNK1FJZHB6RUk2Zmp5a1diMWRkNHJ6VUUKQVpDdDNIWklNM0MrNEcya2Q1cGQydi8ycDNKdTV6RVdnYitiSnlQNWlnNmYyWk8vellaVlUvdXJZQzVNREcrSQpGWDZLNWNodWdzeW5SSjlsUjNXZzVGaFlHd05icWtLS3dFM1RDblJycW9SK0ZhckROclJtZTBEZlpyU0d0Q1c1CjdnTkM4VEJWV3ExOHB2NktwNGh2aHJJM2FjbkI3VnNtbmRhTWY5Z29vS2FQRGxWZTE1cTBkdEJaS3piL1hGNlgKcmZnSEpZaUFyUUlEQVFBQm96SXdNREFkQmdOVkhRNEVGZ1FVVVFNSEdSTTMrSTR2dDNMaDRnS0lQRnp6VndZdwpEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFNOUJoSnBnV0hiZGRIbzU0CmRUbVBnWHRTZHFCT0d4T1Mrd0VYZndMVEo1WHJCeStwZEx0Qi9UbUdtbDJXNEk0TEdCKzI4YmJmWkUzY0RqckIKdGMzWTBzM1RCNmNGY2pmTEV1WXBrendXUmIwTWd3SDYzWEtpQ3BSR0ZPaDdFQTRaRnFvcmN0QkwrVGxzN0dsaApCMnRsRzN6U0wybWhPYXVKK1I1RnZWOU9EMjZzWnExWjNhMEkxcmpDM21TdmdFcUNwL2VHbkVQR0t1U05mb2FsCmtwNEVRc1lrd29IR2Y4TTliajdmZDZ2aHVTUzhUSHF6RTExMmtBaTdadERjUzJIWTQrSUphZElXdzNCWVppSHIKaVVGSklMYjJleis3MFh0QUIzalFoWDBQYjhEZDltK0VUUnR2WW84VCtJejNaS2FJaTRVaFZXMmN1ZFVNUE1oUgp2bHBLVUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
    '.hidden.crt' = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNRENDQWhpZ0F3SUJBZ0lVU0w0bEtHVWE5alFwSGNFL3J3aWJBWTdja3F3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd09ERUxNQWtHQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRQpBd3dKUW05aFlpQlNiMjkwTUI0WERUSTJNVEF5TURBNE5ESTBNbG9YRFRNMk1UQXhOekE0TkRJME1sb3dPREVMCk1Ba0dBMVVFQmhNQ1FWVXhGVEFUQmdOVkJBb01ERUp2WVdJZ1ZHVnpkQ0JEUVRFU01CQUdBMVVFQXd3SlFtOWgKWWlCU2IyOTBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWpQeU1wYk4wWGc0bQpGMmdFeW5kd2grS0VmeVBNQnZDQ0FPOWhwZkRLbVNEWmVDblJFT1VOc1dpSnVnbW9zWU9tN0IxSy9tcmd2Q1NHCnBFU2k3OGpMajJPcVY3RHVSQW9RK085QW1FNDFXTlF3VzJjSXA3ZllNK1FJZHB6RUk2Zmp5a1diMWRkNHJ6VUUKQVpDdDNIWklNM0MrNEcya2Q1cGQydi8ycDNKdTV6RVdnYitiSnlQNWlnNmYyWk8vellaVlUvdXJZQzVNREcrSQpGWDZLNWNodWdzeW5SSjlsUjNXZzVGaFlHd05icWtLS3dFM1RDblJycW9SK0ZhckROclJtZTBEZlpyU0d0Q1c1CjdnTkM4VEJWV3ExOHB2NktwNGh2aHJJM2FjbkI3VnNtbmRhTWY5Z29vS2FQRGxWZTE1cTBkdEJaS3piL1hGNlgKcmZnSEpZaUFyUUlEQVFBQm96SXdNREFkQmdOVkhRNEVGZ1FVVVFNSEdSTTMrSTR2dDNMaDRnS0lQRnp6VndZdwpEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFNOUJoSnBnV0hiZGRIbzU0CmRUbVBnWHRTZHFCT0d4T1Mrd0VYZndMVEo1WHJCeStwZEx0Qi9UbUdtbDJXNEk0TEdCKzI4YmJmWkUzY0RqckIKdGMzWTBzM1RCNmNGY2pmTEV1WXBrendXUmIwTWd3SDYzWEtpQ3BSR0ZPaDdFQTRaRnFvcmN0QkwrVGxzN0dsaApCMnRsRzN6U0wybWhPYXVKK1I1RnZWOU9EMjZzWnExWjNhMEkxcmpDM21TdmdFcUNwL2VHbkVQR0t1U05mb2FsCmtwNEVRc1lrd29IR2Y4TTliajdmZDZ2aHVTUzhUSHF6RTExMmtBaTdadERjUzJIWTQrSUphZElXdzNCWVppSHIKaVVGSklMYjJleis3MFh0QUIzalFoWDBQYjhEZDltK0VUUnR2WW84VCtJejNaS2FJaTRVaFZXMmN1ZFVNUE1oUgp2bHBLVUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
    'bundle.pem' = 'LS0tLS1CRUdJTiBOT1QgQSBDRVJULS0tLS0KQUFBQQotLS0tLUVORCBOT1QgQSBDRVJULS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN1akNDQWFLZ0F3SUJBZ0lVVmtFcEdNbWZaN1Z2R2xxVW5ENDNOVTdrTGJJd0RRWUpLb1pJaHZjTkFRRU0KQlFBd09ERUxNQWtHQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRQpBd3dKUW05aFlpQlNiMjkwTUI0WERUSTJNVEF5TURBNE5ESTBNbG9YRFRJM01URXlOREE0TkRJME1sb3dZREVWCk1CTUdBMVVFQXd3TWJHVmhaaTVsZUdGdGNHeGxNUmd3Q2dZRFZRUUxEQU5GYm1jd0NnWURWUVFMREFOUGNITXgKSGpBY0Jna3Foa2lHOXcwQkNRRVdEMjl3YzBCbGVHRnRjR3hsTG1OdmJURU5NQXNHQTFVRUJSTUVNVEl6TkRCMgpNQkFHQnlxR1NNNDlBZ0VHQlN1QkJBQWlBMklBQkkrd29adWxBWmZTcHdDRDFkcFcveWVKeGNKZ3J3TVlVZVh1CndwKzdTanBTSmxhTmxLMFgrRXBPbVJzRDJwUk9TUTZ1K3A1b2h0emdDWnM3Sy9vVHNjTFBrWDJSVDlqd3pOT1gKcUxhZGw3UHdiTVdOdXd3L0hMYXFyZit2Q3JZczdLTkNNRUF3SFFZRFZSME9CQllFRkErSXJTZVRjVktSUjY5dwphU3dvRjh6b0Q3aEpNQjhHQTFVZEl3UVlNQmFBRkZFREJ4a1ROL2lPTDdkeTRlSUNpRHhjODFjR01BMEdDU3FHClNJYjNEUUVCREFVQUE0SUJBUUJXM0ROaXBtQ2xXNjJJK0VraWFzak1SMUNDZ0VEdzBlaityQ3htd2o4MGVjSkoKZUVtRGtrY1ZvWE5DV2pTbFY5bDg2b0hGRkZna3FQYWpNU0dNSlFINWYvUjNvSzEvRHA2U1RPL2h3Wk0wVm83ZApJbHgxbE1VL3VPZlRNZEJIRmppREJWemJudHgrVGx2b1RqZ1psQ3AvanNBNnVEeXYyOHc4ZDZGeTNUNzFQa2xSCjhha0U3UGMzdmdqc29NMkRaU2FkZnhjaGZDMEZ4ZnJEdW1IU3ROTGxnOHJFZlgzVnNqWnlpcEhaNkcweW1sZ3QKUkxwRUVlWHdqQmhidXYzbm9TZjl5bWdnZ0tKaGc2U2NiQk1WSlFvTXFKZjkxRjdiMWhOeGttVGI0Z0k5dGpvSQoxMXE3eWdPMkRHL210RkNzZmtSem4xMDBUT3piNW44a3FwYmJYZk0zCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNRENDQWhpZ0F3SUJBZ0lVU0w0bEtHVWE5alFwSGNFL3J3aWJBWTdja3F3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd09ERUxNQWtHQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRQpBd3dKUW05aFlpQlNiMjkwTUI0WERUSTJNVEF5TURBNE5ESTBNbG9YRFRNMk1UQXhOekE0TkRJME1sb3dPREVMCk1Ba0dBMVVFQmhNQ1FWVXhGVEFUQmdOVkJBb01ERUp2WVdJZ1ZHVnpkQ0JEUVRFU01CQUdBMVVFQXd3SlFtOWgKWWlCU2IyOTBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQWpQeU1wYk4wWGc0bQpGMmdFeW5kd2grS0VmeVBNQnZDQ0FPOWhwZkRLbVNEWmVDblJFT1VOc1dpSnVnbW9zWU9tN0IxSy9tcmd2Q1NHCnBFU2k3OGpMajJPcVY3RHVSQW9RK085QW1FNDFXTlF3VzJjSXA3ZllNK1FJZHB6RUk2Zmp5a1diMWRkNHJ6VUUKQVpDdDNIWklNM0MrNEcya2Q1cGQydi8ycDNKdTV6RVdnYitiSnlQNWlnNmYyWk8vellaVlUvdXJZQzVNREcrSQpGWDZLNWNodWdzeW5SSjlsUjNXZzVGaFlHd05icWtLS3dFM1RDblJycW9SK0ZhckROclJtZTBEZlpyU0d0Q1c1CjdnTkM4VEJWV3ExOHB2NktwNGh2aHJJM2FjbkI3VnNtbmRhTWY5Z29vS2FQRGxWZTE1cTBkdEJaS3piL1hGNlgKcmZnSEpZaUFyUUlEQVFBQm96SXdNREFkQmdOVkhRNEVGZ1FVVVFNSEdSTTMrSTR2dDNMaDRnS0lQRnp6VndZdwpEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFNOUJoSnBnV0hiZGRIbzU0CmRUbVBnWHRTZHFCT0d4T1Mrd0VYZndMVEo1WHJCeStwZEx0Qi9UbUdtbDJXNEk0TEdCKzI4YmJmWkUzY0RqckIKdGMzWTBzM1RCNmNGY2pmTEV1WXBrendXUmIwTWd3SDYzWEtpQ3BSR0ZPaDdFQTRaRnFvcmN0QkwrVGxzN0dsaApCMnRsRzN6U0wybWhPYXVKK1I1RnZWOU9EMjZzWnExWjNhMEkxcmpDM21TdmdFcUNwL2VHbkVQR0t1U05mb2FsCmtwNEVRc1lrd29IR2Y4TTliajdmZDZ2aHVTUzhUSHF6RTExMmtBaTdadERjUzJIWTQrSUphZElXdzNCWVppSHIKaVVGSklMYjJleis3MFh0QUIzalFoWDBQYjhEZDltK0VUUnR2WW84VCtJejNaS2FJaTRVaFZXMmN1ZFVNUE1oUgp2bHBLVUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
    'certonly.p12' = 'MIIEZwIBAzCCBBUGCSqGSIb3DQEHAaCCBAYEggQCMIID/jCCA/oGCSqGSIb3DQEHBqCCA+swggPnAgEAMIID4AYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBA8TBfbGBobg3TTGoldjMtnAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQyTXvPzIMs1UFLZjioqZpaYCCA3Cl9AmprXukuB4QwZ8BOJaLRiSD+lu5A3Shns/GD4ETs9WKZi4a5gny87wmG23m3tHJfkcLzRY7X35j19tsmknBb2i3TSiYmbwRJpX2GUp4+360AGdoAFO/thpuwkXZ117mybivXcbRHmezMCRkAG8kPXAt2A8OplXa3mfsd5j3LUBYVdc4FXGTGvbhdrpiNuMuUPYvJ3Qwqsm7hfVS2KMTV/fELIa6zhM5tDpGrTi5Q2fDrSSpyU+gANbJ0bWdiYb+b3wZz0y/47YeWAzBnCpsI3g68KyuDsFUC0Iue77hnYYsYy/6KBSVayHrcP9ajedyd5MwKDUS5SN4+Y/kRuCtcXK1/dz0OKp3tNr0NKh6/PUy1hNG7ASNtmFAI/ftzPDmIOaUglPI7Vy4MQ90x9EcLQypblXN6ARGFVPTMang9lg7zxmxflLY2TpVUIijh8WMmCNEclgKFrIpPwsV8Jmclri1Nnv3vG5KuuWWUH9jKw5GpZ22LA69kXYtWR5gJiRrmjcYJgF238gXh4i8/ERg16cdhMlUYgd87+RGwoswDQ9nkvSxKzgUZHsCkoyAQLm7saBE9QTA/hYfSQhnz4k0cF5Loz08ueX3LwZPbJaGZGScKDeM2CfVySokr2p9OniR3Rigzz0CBS/Gahkr931H7HucZlj5wJoGWZBNiHYKFaVXJvb64vNRmeTcaqHtBQ9ZFpg/Sp5BWcr7TFJFsZkpRvyfH3J23qiNc4KR82PSpCOf5o3i/zDtev/wAtM+oKo740BDBK9CdUfVSV3KbKMdz/CiIJ0jSV1Q58Cr/9NAF3pllbO8H9j3b9wK42ak4UycisYoGOYUaPgBVlgiIecsxZZcW3+S/Z2Z1fhkeThtTAxXncidt3eSH4DUylQihyp+yjFwhH4jRU/UJhnHjy61lFE74O5pcO61Jz5PLvT34GybzVDlsAPcv/cITJ04y3RWVSE28qYvsbBpd5bFRDt0ohm2Iwn2ONa++57Hsmowa4vLfw2I66W7ZAQaIPtzc/OpJ6U18JIwpaETvtZL7qQdcXDQjJG1Ic1QtJS9LYdY0oPMsYqGDQpCd2zaJ6pWJVel2m4e2frNQl+aCq4oMVJVJxyMK8TZ+E/09ltubK6XFyY/ZKQZNPklFfAX0V5fAcNiRrcKgPF7yJzQm6cfVtRdMEkwMTANBglghkgBZQMEAgEFAAQgoFKSFeUaCZtC2fMLe0CY3bVpF2D2ZlHWQ7M9bsvPRl8EEMXCPfaZHKfP127I9JtrIq4CAggA'
    'chain.p12' = 'MIIJNQIBAzCCCOMGCSqGSIb3DQEHAaCCCNQEggjQMIIIzDCCByoGCSqGSIb3DQEHBqCCBxswggcXAgEAMIIHEAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDnlea3SRr1ey8fez1OAN7pAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ92GYAOlsjisK1xm1wh/OloCCBqCDLs027tTx3TQ25Be70Lcw7ic6WG4PpDYIrD44/mw85bhe1le9IzevhCw5Ru4IicQShyOrszySRZUqB0FQVy6YftNNUqCX184NGys7DIeaJubLTWynRvciRo9eiIyvJSP5m7jltBneDBupR5EOHyuHewR5bM2ZmwfJY7NPPjojrQcIyc668146G2QZ37OvNLIjWa0X91teUn4y2lPTEY23AzFQbZuNuwIHTn4O3hGyKYw53HhgEQ1GsYaX10cIpMg8bqysILwtq8Y+t9Q+3VQwf5U9Ehek1WqHzdVt9KKdPBv6ZuXjN/BgiLabH+w41vHgAl9LeZ7vR4smHZnIzZPUY/Xm5v0zwPlQCFbriGamBt76oB8JjVqmFp2aKV8f6UXLA1ZVM5io8+okOIExkV733Y1WWk2HcX2NfjXGvieZXZSG46aVvbUS0FuZaT49LbpF2rv4McX+/WSPZ/oUykjbs11szAXyCqH44LkFyX1BQNZiKhqYWyrapF2fcOORnC/OyX+70WOeOTRTTWZpkq4tH1qugwzEgOCEYkQIwZibmGDajeb1iXvJy1NQqLjncMe3eI3Igr4DdjeHDw0R8f7/azRB+CAGjPAxgTOmADTSrlFY8zMHyabwRfKbSNjyOva4A+aRIz4oB043TkNyGvVJaAOsHBj3t0PyXU0EVrAj7JI9jzxXVisn39LBSrlAHIMCC4WDwtfdNRTB4/h8ePYFGOlC3vhok0YKTVGQe/GjbW3V5yQzRWHakhAalqMesILVXCjMJuAqY3MPnBNqeyLXBkOHluwYDop7CGRHarIdrQYzmzuvyUsMjjN4YAy54wBB5GXAiM4wgoAond3TTYOBZvGJ3vxqJU0z/A563yXvLcQA/df94Znth8OW5ZCepAqFFzdPjSvKo6pE2weRrDpkfiQGHFc9T1rJauQHtqzYliPhyAySxlIjoKKbvxXkkkzcuMihRPXvBkXsDXAwbNT1Os5ac3gwdjgHKc+M5NtSecfK/47qB0mE/GfJ75MWHA/AuU5bc3KRuHCUIcSf+V7OUmNlD8xzkpXVjxfzZbadq+NVOyDhYommN6V1O4qu33mrGfBsxDJm18jaMXNIjYUGqAKz6r2qY+oOLT8sRYAlQGKxYJjMDg75JxxKAQAlcJoeaKwon8c3gQQYAJCBzRN1/djXBSR+xKHSSNg3cVCYzzoXs1bgnIPtr4JPB4eqrJbjlw7CpoyJIwkGnGtXhcapmmT/W8FnOJ0a1K+l9NU3tud5SwdSZNu+nybiILH7JBqlzJGd4Rwf4Xthc6+pnYIUcjGWBSd8J7xXgdc0r79q61cgcG+RgwFTZIurJuHuj0onFfxFMGu0j3DIZeIdZ6BfZ4RO7bVxzr6vHA28DRrEZ4QzqgSCyshtnD1YUeVly6SzSKGUJBlfQVQlRqyxRVvdhy/ymkLjfdPgtTYrAsmxd+HFph3zFQgkKrJNQHfwVXCKk5LSNlrSODsrQi1pdoJTzzTkakDGUUOgwG9fdJPF1RgRkN37ZtH3oBFRtMV/G91QoUkyFtsDwGJ9TFxLqp3iOmwY1BQs7CMcJFyChXgCOF3z7zeifyaFdQMaWElo9F0f3ZmlKf6hT6GCEAB3Yy09vwxhXbCrych2dkyVmiGSA5xJlFYmPwJNV5pX3ms88pV6EqU/zsC9Ylztz/gj/1i05aQ+Q6/tMtsjWDnV/uSfMsQnTD3UYoX2+jmfLu4xvWnmBo4Am3Um2Ht5OI8xyeYU3Inn5/sTp/vgaqAWjtQcOsXIsAjYX/sTRpCj4cLqS0xC7sJ5IqnYi4CmqAFPwmA/jja+sz2TftYtLH2bfxpU9rFTA5TEC6q+YukblA2GTbTHlyFsjDtVH9U/RLlUPJNC9154c3aYAojzJcNsOzE37mQodA+tkH4XN3oUdwGOqKC9lStZg862LDQh613J0c+fJMTNGm3nn/BPsyBv8sN3H3ygnTENy1nOETgHDjZmzCIa+sEIqQFHUnWoEHoj0KMelc0r2/detDnrg+1VHPO6e1ckBKEf3UcrUeAcAfKAfuMwfPzFA8rpbhHDxfQP8RujljKHhPqfeAI4ypiBgNCcr7YhjuRuFQ6hXV2zJEHJtz+dHZ1FXAJOsYxvuGeCG1Q7kOJP4fA/BYdQc7+9Av1n6MbfpuYRawaciGJAiCfmzWaTxP9vb6cGNEbpzGHfLCkeryqb6C7zAuiPNaXxbUJuJpmKfZD0mpxe3NYHFjJdAiMqmJlm+ZVL4W/RbQpOSGGNMIIBmgYJKoZIhvcNAQcBoIIBiwSCAYcwggGDMIIBfwYLKoZIhvcNAQwKAQKgggEoMIIBJDBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ7Dd+FfNeaLI32pWn7DQs3wICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEH/QDG8nnVhDJL9beZRelZkEgcBiKbNH6X60gUQ5Szv7LFbASAKOWagicPRTDIJaBZC0vtChayPjVfJeSsCUQsu5ZgNHkkjuAnw6kFVJoiim8WdesuDPa1xTGU5qC9N1CUWrGifGObzt2+2Myc6cFxYZgRKjbZ030o7M/qpnPOD3PdCOpPGJ8cdCQAqZk0GyxmKzdxoGkIZzuKlWAz1nx/b/atWUXAbtqt1UOg6tUg+7b3bIMumZ+jcAtrE/azfFoIDgz+mGz7wY3WG2153R6yUeSPAxRDAdBgkqhkiG9w0BCRQxEB4OAG0AeQAgAGwAZQBhAGYwIwYJKoZIhvcNAQkVMRYEFB6iL7sNMBQa+ffkj1s23KKDeTNNMEkwMTANBglghkgBZQMEAgEFAAQguY/AhPtNwlO4b+5SARLbeTOiKz19feVj7NZhhROcyKYEEOJIFXowTT91Y9heJwAPfagCAggA'
    'chain.p7b' = 'LS0tLS1CRUdJTiBQS0NTNy0tLS0tCk1JSURYd1lKS29aSWh2Y05BUWNDb0lJRFVEQ0NBMHdDQVFFeEFEQUxCZ2txaGtpRzl3MEJCd0dnZ2dNME1JSUQKTURDQ0FoaWdBd0lCQWdJVVNMNGxLR1VhOWpRcEhjRS9yd2liQVk3Y2txd3dEUVlKS29aSWh2Y05BUUVMQlFBdwpPREVMTUFrR0ExVUVCaE1DUVZVeEZUQVRCZ05WQkFvTURFSnZZV0lnVkdWemRDQkRRVEVTTUJBR0ExVUVBd3dKClFtOWhZaUJTYjI5ME1CNFhEVEkyTVRBeU1EQTROREkwTWxvWERUTTJNVEF4TnpBNE5ESTBNbG93T0RFTE1Ba0cKQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRUF3d0pRbTloWWlCUwpiMjkwTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFqUHlNcGJOMFhnNG1GMmdFCnluZHdoK0tFZnlQTUJ2Q0NBTzlocGZES21TRFplQ25SRU9VTnNXaUp1Z21vc1lPbTdCMUsvbXJndkNTR3BFU2kKNzhqTGoyT3FWN0R1UkFvUStPOUFtRTQxV05Rd1cyY0lwN2ZZTStRSWRwekVJNmZqeWtXYjFkZDRyelVFQVpDdAozSFpJTTNDKzRHMmtkNXBkMnYvMnAzSnU1ekVXZ2IrYkp5UDVpZzZmMlpPL3pZWlZVL3VyWUM1TURHK0lGWDZLCjVjaHVnc3luUko5bFIzV2c1RmhZR3dOYnFrS0t3RTNUQ25ScnFvUitGYXJETnJSbWUwRGZaclNHdENXNTdnTkMKOFRCVldxMThwdjZLcDRodmhySTNhY25CN1ZzbW5kYU1mOWdvb0thUERsVmUxNXEwZHRCWkt6Yi9YRjZYcmZnSApKWWlBclFJREFRQUJvekl3TURBZEJnTlZIUTRFRmdRVVVRTUhHUk0zK0k0dnQzTGg0Z0tJUEZ6elZ3WXdEd1lEClZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBTTlCaEpwZ1dIYmRkSG81NGRUbVAKZ1h0U2RxQk9HeE9TK3dFWGZ3TFRKNVhyQnkrcGRMdEIvVG1HbWwyVzRJNExHQisyOGJiZlpFM2NEanJCdGMzWQowczNUQjZjRmNqZkxFdVlwa3p3V1JiME1nd0g2M1hLaUNwUkdGT2g3RUE0WkZxb3JjdEJMK1RsczdHbGhCMnRsCkczelNMMm1oT2F1SitSNUZ2VjlPRDI2c1pxMVozYTBJMXJqQzNtU3ZnRXFDcC9lR25FUEdLdVNOZm9hbGtwNEUKUXNZa3dvSEdmOE05Ymo3ZmQ2dmh1U1M4VEhxekUxMTJrQWk3WnREY1MySFk0K0lKYWRJV3czQllaaUhyaVVGSgpJTGIyZXorNzBYdEFCM2pRaFgwUGI4RGQ5bStFVFJ0dllvOFQrSXozWkthSWk0VWhWVzJjdWRVTVBNaFJ2bHBLClVERUEKLS0tLS1FTkQgUEtDUzctLS0tLQo='
    'crlf.crt' = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlETURDQ0FoaWdBd0lCQWdJVVNMNGxLR1VhOWpRcEhjRS9yd2liQVk3Y2txd3dEUVlKS29aSWh2Y05BUUVMDQpCUUF3T0RFTE1Ba0dBMVVFQmhNQ1FWVXhGVEFUQmdOVkJBb01ERUp2WVdJZ1ZHVnpkQ0JEUVRFU01CQUdBMVVFDQpBd3dKUW05aFlpQlNiMjkwTUI0WERUSTJNVEF5TURBNE5ESTBNbG9YRFRNMk1UQXhOekE0TkRJME1sb3dPREVMDQpNQWtHQTFVRUJoTUNRVlV4RlRBVEJnTlZCQW9NREVKdllXSWdWR1Z6ZENCRFFURVNNQkFHQTFVRUF3d0pRbTloDQpZaUJTYjI5ME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBalB5TXBiTjBYZzRtDQpGMmdFeW5kd2grS0VmeVBNQnZDQ0FPOWhwZkRLbVNEWmVDblJFT1VOc1dpSnVnbW9zWU9tN0IxSy9tcmd2Q1NHDQpwRVNpNzhqTGoyT3FWN0R1UkFvUStPOUFtRTQxV05Rd1cyY0lwN2ZZTStRSWRwekVJNmZqeWtXYjFkZDRyelVFDQpBWkN0M0haSU0zQys0RzJrZDVwZDJ2LzJwM0p1NXpFV2diK2JKeVA1aWc2ZjJaTy96WVpWVS91cllDNU1ERytJDQpGWDZLNWNodWdzeW5SSjlsUjNXZzVGaFlHd05icWtLS3dFM1RDblJycW9SK0ZhckROclJtZTBEZlpyU0d0Q1c1DQo3Z05DOFRCVldxMThwdjZLcDRodmhySTNhY25CN1ZzbW5kYU1mOWdvb0thUERsVmUxNXEwZHRCWkt6Yi9YRjZYDQpyZmdISllpQXJRSURBUUFCb3pJd01EQWRCZ05WSFE0RUZnUVVVUU1IR1JNMytJNHZ0M0xoNGdLSVBGenpWd1l3DQpEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFNOUJoSnBnV0hiZGRIbzU0DQpkVG1QZ1h0U2RxQk9HeE9TK3dFWGZ3TFRKNVhyQnkrcGRMdEIvVG1HbWwyVzRJNExHQisyOGJiZlpFM2NEanJCDQp0YzNZMHMzVEI2Y0ZjamZMRXVZcGt6d1dSYjBNZ3dINjNYS2lDcFJHRk9oN0VBNFpGcW9yY3RCTCtUbHM3R2xoDQpCMnRsRzN6U0wybWhPYXVKK1I1RnZWOU9EMjZzWnExWjNhMEkxcmpDM21TdmdFcUNwL2VHbkVQR0t1U05mb2FsDQprcDRFUXNZa3dvSEdmOE05Ymo3ZmQ2dmh1U1M4VEhxekUxMTJrQWk3WnREY1MySFk0K0lKYWRJV3czQllaaUhyDQppVUZKSUxiMmV6KzcwWHRBQjNqUWhYMFBiOERkOW0rRVRSdHZZbzhUK0l6M1pLYUlpNFVoVlcyY3VkVU1QTWhSDQp2bHBLVUE9PQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0K'
    'junk.crt' = 'Z2FyYmFnZQo='
    'leaf.der' = 'MIICujCCAaKgAwIBAgIUVkEpGMmfZ7VvGlqUnD43NU7kLbIwDQYJKoZIhvcNAQEMBQAwODELMAkGA1UEBhMCQVUxFTATBgNVBAoMDEJvYWIgVGVzdCBDQTESMBAGA1UEAwwJQm9hYiBSb290MB4XDTI2MTAyMDA4NDI0MloXDTI3MTEyNDA4NDI0MlowYDEVMBMGA1UEAwwMbGVhZi5leGFtcGxlMRgwCgYDVQQLDANFbmcwCgYDVQQLDANPcHMxHjAcBgkqhkiG9w0BCQEWD29wc0BleGFtcGxlLmNvbTENMAsGA1UEBRMEMTIzNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABI+woZulAZfSpwCD1dpW/yeJxcJgrwMYUeXuwp+7SjpSJlaNlK0X+EpOmRsD2pROSQ6u+p5ohtzgCZs7K/oTscLPkX2RT9jwzNOXqLadl7PwbMWNuww/HLaqrf+vCrYs7KNCMEAwHQYDVR0OBBYEFA+IrSeTcVKRR69waSwoF8zoD7hJMB8GA1UdIwQYMBaAFFEDBxkTN/iOL7dy4eICiDxc81cGMA0GCSqGSIb3DQEBDAUAA4IBAQBW3DNipmClW62I+EkiasjMR1CCgEDw0ej+rCxmwj80ecJJeEmDkkcVoXNCWjSlV9l86oHFFFgkqPajMSGMJQH5f/R3oK1/Dp6STO/hwZM0Vo7dIlx1lMU/uOfTMdBHFjiDBVzbntx+TlvoTjgZlCp/jsA6uDyv28w8d6Fy3T71PklR8akE7Pc3vgjsoM2DZSadfxchfC0FxfrDumHStNLlg8rEfX3VsjZyipHZ6G0ymlgtRLpEEeXwjBhbuv3noSf9ymgggKJhg6ScbBMVJQoMqJf91F7b1hNxkmTb4gI9tjoI11q7ygO2DG/mtFCsfkRzn100TOzb5n8kqpbbXfM3'
    'nopass.pfx' = 'MIIFlgIBAzCCBUQGCSqGSIb3DQEHAaCCBTUEggUxMIIFLTCCA6oGCSqGSIb3DQEHBqCCA5swggOXAgEAMIIDkAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDzyuySnGEXChN8uGMbBSDXAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQjTRS40s1hQhyqAYmSOCcr4CCAyBp7OUgeuQGzGe66vqvCbRiCvNVaW7HqSl0FAmXkb0OBH6GCF7YAW4kaw6IXIPROT8Fy/1Wp7ej3MuLD34fCR3abvhPziuRuZPBFDERhNPPJMWR1o3nWs/D+0nrkAua4uMZa83GtZzWvnA2aV/16T5CFt8x6A0ld1baR74YkLBbHwZ9VYTDNzhDE1Bf5GG3Ri4KisPIuzU47si8bnFLtO/KsXrslMkrNINaolkdj5mBW0hNSu0FDt/L73G1kOUv5ciVIIboVfivbosX5pEDWbpmFZzR218HaMXVX8W5xvkG6AoifEAsDAOOptbffqQ08AIJemdK98O+CzKLB0fyAzXYAlXs5fCoZ/Nvcu/bsf8yPJWE43FHCoDPBGi9bNrbqu2V3bWwVdRiclHj9mCSKOJRHBliFvML23Ie6HhKH7T9nEl2/ZoBy7lPOJtp2VtFlu60ieRWHd461KecQDExpu77J6/NIB6azrelStg0wllJVXWooJr7FDtSKB1bE+/rQAADKW9QqAgj7RYUKGG0NOttQ0L16OviPlkcEACp0duAGCKiQdh9cWJiQMBv3uy5KWRL9vgAGSlriY+JGXmBLOGmnXiBit4Rvcc+qcHAQOnPxFiG+uYUdLjBcJ8XVYdoGY6JsrZ3qmHO8BNg/Ihk6hFZb1pLKcGzq/uKvCY8BkprMfCx5t3YFTj3w/wIwR8vKohQ1AcvdPhCL8zPZ3xbuez3UP3RuycIy+I+JD774DV8HdkYOpAQIFinVgsPNWLqJ1ZeHj4in01qv4fcCwyAaqe0kntmLWwcvPZAmTH6+QfSz3I/cI5Y7gdp//0QOiLYj7udZ9RQcHsvrYUbn/d8WXH3DtriZtiI66+UCwAt+IIMYWwY9uS2LFd4thOFFKHj/hLVJYv7bxwqOYrhxr7nTQAnz61G10iJba9OYgP4/HeS9zYndoOsjPUYFC1Sxvl/5g58WcexlvwZb5FQo/oYmOpn4pJ3BAEVED1AqQmT0LVVKxIcM9wIdM6gmivEFNCo+9s7klC2QAW/P6MgDJsNAxoaCuIkHU+EJU0Zzv6tHj6qGTCCAXsGCSqGSIb3DQEHAaCCAWwEggFoMIIBZDCCAWAGCyqGSIb3DQEMCgECoIIBKDCCASQwXwYJKoZIhvcNAQUNMFIwMQYJKoZIhvcNAQUMMCQEEEOSZ311Z53Cnq8E0dbtB6sCAggAMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBE4hYx99re59dOadvEZ95YBIHAeQ3s35OWQUjaSSl4HByQ6seUCn4dXxP3kuc2TyIZclVV97hJ1ISzZXTmjyhWa4XGPUh+4OYufys8GcCF9q+KEmihL38n7s92RHHi1qIcGtrDYZc7MMGmq7WfAjk6nisGSJ7/s2CQ3K5bt1sIZhS3gCCKgD1/3Nv2aKStQf0URNhC9BzWSn+4LvHqCTTcJwKsgP5zK/jIVf4tSn5092XIVXvEVOGPws8YatFAUX4tg9OSBB8iZjsS6sgQtlp9mR18MSUwIwYJKoZIhvcNAQkVMRYEFB6iL7sNMBQa+ffkj1s23KKDeTNNMEkwMTANBglghkgBZQMEAgEFAAQglV6u6PxF+1wbbAMJE9UZLVUe6Sm3F7mLIe/GyD1K5vgEEDPmEpXRZjWDC9WnipwOe/cCAggA'
    'pw.txt' = 'czNjcmV0Cg=='
    'store.jks' = 'bm90cmVhbGx5amtz'
    'sub/ca-der.cer' = 'MIIDMDCCAhigAwIBAgIUSL4lKGUa9jQpHcE/rwibAY7ckqwwDQYJKoZIhvcNAQELBQAwODELMAkGA1UEBhMCQVUxFTATBgNVBAoMDEJvYWIgVGVzdCBDQTESMBAGA1UEAwwJQm9hYiBSb290MB4XDTI2MTAyMDA4NDI0MloXDTM2MTAxNzA4NDI0MlowODELMAkGA1UEBhMCQVUxFTATBgNVBAoMDEJvYWIgVGVzdCBDQTESMBAGA1UEAwwJQm9hYiBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjPyMpbN0Xg4mF2gEyndwh+KEfyPMBvCCAO9hpfDKmSDZeCnREOUNsWiJugmosYOm7B1K/mrgvCSGpESi78jLj2OqV7DuRAoQ+O9AmE41WNQwW2cIp7fYM+QIdpzEI6fjykWb1dd4rzUEAZCt3HZIM3C+4G2kd5pd2v/2p3Ju5zEWgb+bJyP5ig6f2ZO/zYZVU/urYC5MDG+IFX6K5chugsynRJ9lR3Wg5FhYGwNbqkKKwE3TCnRrqoR+FarDNrRme0DfZrSGtCW57gNC8TBVWq18pv6Kp4hvhrI3acnB7VsmndaMf9gooKaPDlVe15q0dtBZKzb/XF6XrfgHJYiArQIDAQABozIwMDAdBgNVHQ4EFgQUUQMHGRM3+I4vt3Lh4gKIPFzzVwYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAM9BhJpgWHbddHo54dTmPgXtSdqBOGxOS+wEXfwLTJ5XrBy+pdLtB/TmGml2W4I4LGB+28bbfZE3cDjrBtc3Y0s3TB6cFcjfLEuYpkzwWRb0MgwH63XKiCpRGFOh7EA4ZFqorctBL+Tls7GlhB2tlG3zSL2mhOauJ+R5FvV9OD26sZq1Z3a0I1rjC3mSvgEqCp/eGnEPGKuSNfoalkp4EQsYkwoHGf8M9bj7fd6vhuSS8THqzE112kAi7ZtDcS2HY4+IJadIWw3BYZiHriUFJILb2ez+70XtAB3jQhX0Pb8Dd9m+ETRtvYo8T+Iz3ZKaIi4UhVW2cudUMPMhRvlpKUA=='
    'sub/ed25519.crt' = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJXRENDQVFxZ0F3SUJBZ0lVVVk2Q0t6SGpwSlMza3Q0VUxnQ2pJZzVUVkFBd0JRWURLMlZ3TURFeEV6QVIKQmdOVkJBTU1DbVZrTG1WNFlXMXdiR1V4R2pBWUJnTlZCQW9NRWNPRHdweHV3NFBDcjJOdlpHVWdUM0puTUNBWApEVGN3TURFd01UQXdNREF3TUZvWUR6SXdOVEV3TVRBeE1EQXdNREF3V2pBeE1STXdFUVlEVlFRRERBcGxaQzVsCmVHRnRjR3hsTVJvd0dBWURWUVFLREJIRGc4S2Nic09Ed3E5amIyUmxJRTl5WnpBcU1BVUdBeXRsY0FNaEFEaXYKTXBENllDY1FteWQvRURELzNBUnRlVmdaK3pTdUM4cTE2RjBNcHlham96SXdNREFkQmdOVkhRNEVGZ1FVTkxXNQpYNG5lVkVRTTdsWFZiMmFGdXlxV2Fub3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QUZCZ01yWlhBRFFRQ3NWYXdVCm9wbU5uWnN3aXQ3S0NuMHFydUorZ0NJNXBqRkM5dlNzS21OTHo5cjdOVFRab1FkaXMrK1FtQzdHTlBRbFdLY3AKaVd6c1BIQURrbUViWWcwUAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
}

}

Describe 'Scan model' {
    It 'New-BoabScan has the Rust field order and defaults' {
        $s = New-BoabScan -Name 'n' -ScanType 'codebase' -Target 't'
        @($s.Keys) | Should -Be @('id', 'name', 'scan_type', 'status', 'target', 'config', 'started_at', 'completed_at', 'findings', 'error_message')
        $s.status | Should -BeExactly 'queued'
        $s.completed_at | Should -BeNullOrEmpty
        $s.error_message | Should -BeNullOrEmpty
        $s.config.Count | Should -Be 0
        $s.findings.Count | Should -Be 0
        $s.id | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        $s.started_at | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$'
        (ConvertTo-TestJson $s) | Should -Match '^\{"id":"[^"]+","name":"n","scan_type":"codebase","status":"queued","target":"t","config":\{\},"started_at":"[^"]+","completed_at":null,"findings":\[\],"error_message":null\}$'
    }

    It 'New-BoabFinding has the Rust field order and defaults' {
        $f = New-BoabFinding -ScanId 'abc' -SourceType 'cert_subject' -SourceLocation 'x' -Evidence ([ordered]@{ kind = 'k' }) -Confidence 'high'
        @($f.Keys) | Should -Be @('id', 'scan_id', 'crypto_asset_id', 'source_type', 'source_location', 'evidence', 'confidence', 'status', 'discovered_at')
        $f.status | Should -BeExactly 'new'
        $f.crypto_asset_id | Should -BeNullOrEmpty
        $f.scan_id | Should -BeExactly 'abc'
    }

    It 'formats timestamps like time::serde::rfc3339' {
        $dt = [datetime]::new(2026, 10, 20, 8, 16, 30, [System.DateTimeKind]::Utc).AddTicks(7153300)
        Format-BoabRfc3339 -DateTime $dt | Should -BeExactly '2026-10-20T08:16:30.71533Z'
        Format-BoabRfc3339 -DateTime ([datetime]::new(2026, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc)) | Should -BeExactly '2026-01-02T03:04:05Z'
        Format-BoabRfc3339 -DateTime ([datetime]::new(2026, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc).AddTicks(1)) | Should -BeExactly '2026-01-02T03:04:05.0000001Z'
        Get-BoabUtcNow | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d*[1-9])?Z$'
    }
}

Describe 'Pattern packs' {
    It 'has every Rust pattern' {
        (Get-BoabGenericPatterns).Count | Should -Be 28
        (Get-BoabLibraryPatterns).Count | Should -Be 20
    }

    It 'maps extensions to Rust Language Debug names' {
        Get-BoabLanguage -Path 'a/b.RS' | Should -BeExactly 'Rust'
        Get-BoabLanguage -Path 'x.TSX' | Should -BeExactly 'JavaScript'
        Get-BoabLanguage -Path 'x.kts' | Should -BeExactly 'Java'
        Get-BoabLanguage -Path 'x.fs' | Should -BeExactly 'DotNet'
        Get-BoabLanguage -Path 'x.toml' | Should -BeExactly 'Generic'
        Get-BoabLanguage -Path 'Makefile' | Should -BeExactly 'Generic'
        Get-BoabLanguage -Path 'x.md' | Should -BeExactly 'Generic'
    }

    It 'implements Path::extension semantics' {
        Get-BoabPathExtension -Path '.gitignore' | Should -BeNullOrEmpty
        Get-BoabPathExtension -Path 'noext' | Should -BeNullOrEmpty
        Get-BoabPathExtension -Path 'trail.' | Should -BeExactly ''
        Get-BoabPathExtension -Path 'a.b.C' | Should -BeExactly 'C'
        Get-BoabPathExtension -Path '.env.local' | Should -BeExactly 'local'
    }
}

Describe 'Glob and ignore matching' {
    It 'translates globs like globset' {
        $rx = ConvertTo-BoabGlobRegex -Glob '**/node_modules'
        'node_modules' | Should -Match $rx
        'a/b/node_modules' | Should -Match $rx
        'node_modulesx' | Should -Not -Match $rx

        $rx = ConvertTo-BoabGlobRegex -Glob '**/build/**/*'
        'build/x.js' | Should -Match $rx
        'a/build/y/z.js' | Should -Match $rx
        'build' | Should -Not -Match $rx

        $rx = ConvertTo-BoabGlobRegex -Glob 'src/*.rs'
        'src/a.rs' | Should -Match $rx
        'src/x/a.rs' | Should -Not -Match $rx

        $rx = ConvertTo-BoabGlobRegex -Glob '*.{py,go}'
        'a.go' | Should -Match $rx
        'a.rs' | Should -Not -Match $rx

        $rx = ConvertTo-BoabGlobRegex -Glob '[!a]?.txt'
        'bc.txt' | Should -Match $rx
        'ac.txt' | Should -Not -Match $rx

        ConvertTo-BoabGlobRegex -Glob '**' | Should -BeExactly '^.*\z'
        { ConvertTo-BoabGlobRegex -Glob 'a\' } | Should -Throw
    }

    It 'applies gitignore line rules' {
        $m = New-BoabGitignoreMatcher -Root '/r'
        Add-BoabGitignoreLine -Matcher $m -Line '*.log'
        Add-BoabGitignoreLine -Matcher $m -Line '!keep.log'
        Add-BoabGitignoreLine -Matcher $m -Line '/anchored.txt'
        Add-BoabGitignoreLine -Matcher $m -Line 'dir/'
        Add-BoabGitignoreLine -Matcher $m -Line '# comment'
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/a/x.log' -IsDir $false | Should -BeExactly 'ignore'
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/keep.log' -IsDir $false | Should -BeExactly 'whitelist'
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/anchored.txt' -IsDir $false | Should -BeExactly 'ignore'
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/sub/anchored.txt' -IsDir $false | Should -BeNullOrEmpty
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/x/dir' -IsDir $true | Should -BeExactly 'ignore'
        Test-BoabGitignoreMatch -Matcher $m -Path '/r/x/dir' -IsDir $false | Should -BeNullOrEmpty
    }

    It 'inverts override globs and ignores non-included files' {
        $root = if ($IsWindows) { 'C:\r' } else { '/r' }
        $sep = [System.IO.Path]::DirectorySeparatorChar
        $ov = New-BoabCodebaseOverrides -Root $root -Include @('*.py') -Exclude @('sub')
        Test-BoabOverrideMatch -Matcher $ov -Path "$root${sep}node_modules" -IsDir $true | Should -BeExactly 'ignore'
        Test-BoabOverrideMatch -Matcher $ov -Path "$root${sep}sub" -IsDir $true | Should -BeExactly 'ignore'
        Test-BoabOverrideMatch -Matcher $ov -Path "$root${sep}a.py" -IsDir $false | Should -BeExactly 'whitelist'
        Test-BoabOverrideMatch -Matcher $ov -Path "$root${sep}a.go" -IsDir $false | Should -BeExactly 'ignore'
        Test-BoabOverrideMatch -Matcher $ov -Path "$root${sep}pkg" -IsDir $true | Should -BeNullOrEmpty
    }
}

Describe 'Codebase scanner: ported Rust unit tests' {
    It 'detects MD5 in Rust' {
        $dir = Join-Path $TestDrive 'md5'
        [void](New-Item -ItemType Directory -Path $dir)
        [System.IO.File]::WriteAllText((Join-Path $dir 'a.rs'), "use sha2;`n// MD5 is dangerous`nlet h = md5();`n")
        $scan = Invoke-BoabCodebaseScan -Path $dir
        @($scan.findings | Where-Object { $_.evidence['algorithm_name'] -eq 'MD5' }).Count | Should -BeGreaterThan 0
    }

    It 'detects a Python import' {
        $dir = Join-Path $TestDrive 'py'
        [void](New-Item -ItemType Directory -Path $dir)
        [System.IO.File]::WriteAllText((Join-Path $dir 'a.py'), "from cryptography.hazmat import primitives`n")
        $scan = Invoke-BoabCodebaseScan -Path $dir
        @($scan.findings | Where-Object { $_.evidence['kind'] -eq 'library_import' -and $_.evidence['library_name'] -eq 'cryptography' }).Count | Should -BeGreaterThan 0
    }

    It 'detects ML-KEM as resistant' {
        $dir = Join-Path $TestDrive 'go'
        [void](New-Item -ItemType Directory -Path $dir)
        [System.IO.File]::WriteAllText((Join-Path $dir 'a.go'), "// switching to ML-KEM-768 next quarter`n")
        $scan = Invoke-BoabCodebaseScan -Path $dir
        $f = @($scan.findings | Where-Object { $_.evidence['algorithm_name'] -eq 'ML-KEM' })
        $f.Count | Should -Be 1
        $f[0].evidence['pqc_status'] | Should -BeExactly 'resistant'
    }

    It 'flags cert/key files by extension' {
        $dir = Join-Path $TestDrive 'pem'
        [void](New-Item -ItemType Directory -Path $dir)
        [System.IO.File]::WriteAllText((Join-Path $dir 'server.pem'), "-----BEGIN CERTIFICATE-----`n")
        $scan = Invoke-BoabCodebaseScan -Path $dir
        $f = @($scan.findings | Where-Object { $_.evidence['kind'] -eq 'cert_or_keystore_file' })
        $f.Count | Should -Be 1
        $f[0].source_location | Should -BeExactly 'server.pem'
        $f[0].confidence | Should -BeExactly 'low'
        $f[0].evidence['size_bytes'] | Should -Be 28
    }

    It 'skips node_modules by default' {
        $dir = Join-Path $TestDrive 'nm'
        $inner = Join-Path $dir 'node_modules' 'forge'
        [void](New-Item -ItemType Directory -Path $inner -Force)
        [System.IO.File]::WriteAllText((Join-Path $inner 'index.js'), "const md5 = require('crypto');`n")
        $scan = Invoke-BoabCodebaseScan -Path $dir
        $scan.findings.Count | Should -Be 0
    }

    It 'fails on a missing path like Rust' {
        { Invoke-BoabCodebaseScan -Path (Join-Path $TestDrive 'does-not-exist') } | Should -Throw -ExpectedMessage 'could not resolve scan path*'
    }

    It 'fills scan metadata' {
        $dir = Join-Path $TestDrive 'meta'
        [void](New-Item -ItemType Directory -Path $dir)
        $scan = Invoke-BoabCodebaseScan -Path $dir -Name 'custom'
        $scan.name | Should -BeExactly 'custom'
        $scan.scan_type | Should -BeExactly 'codebase'
        $scan.status | Should -BeExactly 'completed'
        $scan.completed_at | Should -Not -BeNullOrEmpty
        $scan.target | Should -BeExactly (Get-BoabPathDisplay -Path (Resolve-BoabCanonicalPath -Path $dir))
        (ConvertTo-TestJson $scan.config) | Should -BeExactly '{"include":[],"exclude":[],"default_excludes":["node_modules","vendor",".venv","venv","target","dist","build",".git"]}'
    }
}

Describe 'Codebase scanner: parity with Rust output' {
    It 'matches Rust on examples/demo/app' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'app')
        $scan = Invoke-BoabCodebaseScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'demo_app')
    }

    It 'matches Rust on tests/fixtures/codebase' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'tests', 'fixtures', 'codebase')
        $scan = Invoke-BoabCodebaseScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'fixtures_codebase')
        # Port of tests/codebase_scan.rs sanity checks.
        $algos = @($scan.findings | ForEach-Object { $_.evidence['algorithm_name'] })
        ($algos -contains 'MD5' -or $algos -contains 'SHA-1') | Should -BeTrue
        ($algos -contains 'ML-KEM' -or $algos -contains 'ML-DSA' -or $algos -contains 'Kyber') | Should -BeTrue
    }

    Context 'edge-case tree' {
        BeforeAll {
            $script:EdgeRoot = Join-Path $TestDrive 'edge'
            # Windows cannot create a file name ending in '.'.
            $script:EdgeSkip = if ($IsWindows) { @('trail.') } else { @() }
            Write-TreeFromTable -Table $script:EdgeTreeFiles -Root $script:EdgeRoot -Skip $script:EdgeSkip
            # Just over the 4 MiB limit: Rust skips it.
            $big = [System.Text.Encoding]::ASCII.GetBytes("MD5`n" + ('a' * (4 * 1024 * 1024)))
            [System.IO.File]::WriteAllBytes((Join-Path $script:EdgeRoot 'big.txt'), $big)
        }

        It 'matches Rust with default options (gitignore, .ignore, hidden, default excludes, encodings)' {
            $scan = Invoke-BoabCodebaseScan -Path $script:EdgeRoot
            Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'edge' -DropLocationsLike $script:EdgeSkip)
        }

        It 'matches Rust with --include *.py --exclude sub --name edge-inc' {
            $scan = Invoke-BoabCodebaseScan -Path $script:EdgeRoot -Include @('*.py') -Exclude @('sub') -Name 'edge-inc'
            Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'edge_inc')
        }
    }
}

Describe 'Certificate store scanner' {
    It 'scans a PEM directory (port of cert_store.rs scans_pem_directory)' {
        $dir = Join-Path $TestDrive 'pemdir'
        [void](New-Item -ItemType Directory -Path $dir)
        Copy-Item -LiteralPath ([System.IO.Path]::Combine($script:RepoRoot, 'tests', 'fixtures', 'certs', 'rsa2048-selfsigned.pem')) -Destination (Join-Path $dir 'rsa.pem')
        $scan = Invoke-BoabCertStoreScan -Path $dir
        $scan.findings.Count | Should -BeGreaterThan 0
        $scan.findings[0].evidence['kind'] | Should -BeExactly 'tls_certificate'
        $scan.findings[0].evidence['public_key_algorithm'] | Should -BeLike '*RSA*'
        $scan.findings[0].source_type | Should -BeExactly 'cert_subject'
    }

    It 'matches Rust on examples/demo/certs' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs')
        $scan = Invoke-BoabCertStoreScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'demo_certs')
    }

    It 'matches Rust on tests/fixtures/certs' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'tests', 'fixtures', 'certs')
        $scan = Invoke-BoabCertStoreScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'fixtures_certs')
    }

    Context 'certificate edge-case tree (DER, PEM bundles, CRLF, PKCS#12, JKS, hidden files)' {
        BeforeAll {
            $script:CertRoot = Join-Path $TestDrive 'certs'
            Write-TreeFromTable -Table $script:CertTreeFiles -Root $script:CertRoot
            if ($IsWindows) {
                foreach ($h in @('.hidden.crt', '.hid')) {
                    $item = Get-Item -LiteralPath (Join-Path $script:CertRoot $h) -Force
                    $item.Attributes = $item.Attributes -bor [System.IO.FileAttributes]::Hidden
                }
            }
        }

        It 'matches Rust without a password file' {
            $scan = Invoke-BoabCertStoreScan -Path $script:CertRoot -Name 'certs-nopw'
            Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'certs_nopw')
        }

        It 'matches Rust with --password-file' {
            $scan = Invoke-BoabCertStoreScan -Path $script:CertRoot -PasswordFile (Join-Path $script:CertRoot 'pw.txt') -Name 'certs-pw'
            Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $scan -Root $scan.target) -Expected (Get-ExpectedScan -Key 'certs_pw')
        }
    }

    It 'fails on a missing path like Rust' {
        { Invoke-BoabCertStoreScan -Path (Join-Path $TestDrive 'nope') } | Should -Throw -ExpectedMessage 'could not resolve cert store path*'
    }

    It 'decodes OIDs and DER structure' {
        ConvertFrom-BoabDerOid -Content (ConvertFrom-TestHex '2a864886f70d010101') | Should -BeExactly '1.2.840.113549.1.1.1'
        ConvertFrom-BoabDerOid -Content (ConvertFrom-TestHex '2b6570') | Should -BeExactly '1.3.101.112'
        ConvertFrom-BoabDerOid -Content (ConvertFrom-TestHex '0992268993f22c640119') | Should -BeExactly '0.9.2342.19200300.100.1.25'
        Get-BoabX509AttributeAbbrev -Oid '2.5.4.5' | Should -BeExactly 'serialNumber'
        Get-BoabX509AttributeAbbrev -Oid '1.2.3.4' | Should -BeExactly 'OID(1.2.3.4)'
        Get-BoabSignaturePqcStatus -Name 'ML-DSA-65' | Should -BeExactly 'resistant'
        Get-BoabSignaturePqcStatus -Name 'sha1WithRSAEncryption' | Should -BeExactly 'vulnerable'
        Get-BoabSignaturePqcStatus -Name '1.2.3' | Should -BeExactly 'unknown'
    }

    It 'computes approximate key bits like x509-parser' {
        $pem = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs', 'rsa1024.crt'))
        $der = (Get-BoabPemBlocks -Bytes $pem)[0]
        Get-BoabApproximateKeyBits -Cert (ConvertFrom-BoabX509Der -Der $der) | Should -Be 1024
        $pem = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs', 'ecdsa-p256.crt'))
        $der = (Get-BoabPemBlocks -Bytes $pem)[0]
        Get-BoabApproximateKeyBits -Cert (ConvertFrom-BoabX509Der -Der $der) | Should -Be 256
    }
}

Describe 'TLS scanner (offline)' {
    It 'names groups and detects hybrids (port of hybrid_groups_classified)' {
        Test-BoabTlsHybridGroup -Codepoint 0x11EC | Should -BeTrue
        Test-BoabTlsHybridGroup -Codepoint 0x6399 | Should -BeTrue
        Test-BoabTlsHybridGroup -Codepoint 0x001D | Should -BeFalse
        Get-BoabTlsGroupName -Codepoint 0x11EC | Should -BeExactly 'X25519MLKEM768'
        Get-BoabTlsGroupName -Codepoint 0x001D | Should -BeExactly 'x25519'
        Get-BoabTlsGroupName -Codepoint 0x0017 | Should -BeExactly 'secp256r1'
        Get-BoabTlsGroupName -Codepoint 0x6399 | Should -BeExactly 'X25519Kyber768Draft00'
        Get-BoabTlsGroupName -Codepoint 0x0102 | Should -BeExactly 'ffdhe4096'
        Get-BoabTlsGroupName -Codepoint 0x1234 | Should -BeExactly 'unknown'
    }

    It 'parses rate limits (port of rate_limit_parses)' {
        (ConvertFrom-BoabRateLimit -Value '1/second').TotalMilliseconds | Should -Be 1000
        (ConvertFrom-BoabRateLimit -Value '2/sec').TotalMilliseconds | Should -Be 500
        (ConvertFrom-BoabRateLimit -Value '60/minute').TotalMilliseconds | Should -Be 1000
        (ConvertFrom-BoabRateLimit -Value '3/s').TotalMilliseconds | Should -Be 333
        ConvertFrom-BoabRateLimit -Value 'garbage' | Should -BeNullOrEmpty
        ConvertFrom-BoabRateLimit -Value '0/second' | Should -BeNullOrEmpty
        ConvertFrom-BoabRateLimit -Value '1/hour' | Should -BeNullOrEmpty
    }

    It 'parses targets (port of parse_target_works)' {
        $r = Split-BoabTlsTarget -Target 'example.com:443'
        $r[0] | Should -BeExactly 'example.com'
        $r[1] | Should -Be 443
        { Split-BoabTlsTarget -Target 'no-port' } | Should -Throw -ExpectedMessage 'target must be host:port, got no-port'
        { Split-BoabTlsTarget -Target 'bad:port' } | Should -Throw -ExpectedMessage 'invalid port in target bad:port'
        { Split-BoabTlsTarget -Target 'a:65536' } | Should -Throw
        (Split-BoabTlsTarget -Target '::1:8443')[0] | Should -BeExactly '::1'
    }

    It 'validates server names like rustls-pki-types' {
        Test-BoabDnsName -Name 'example.com' | Should -BeTrue
        Test-BoabDnsName -Name 'example.com.' | Should -BeTrue
        Test-BoabDnsName -Name 'under_score.example' | Should -BeTrue
        Test-BoabDnsName -Name '1.2.3.4' | Should -BeFalse
        Test-BoabDnsName -Name '-bad.example' | Should -BeFalse
        Test-BoabDnsName -Name 'bad-.example' | Should -BeFalse
        Test-BoabDnsName -Name '[::1]' | Should -BeFalse
        Test-BoabDnsName -Name '' | Should -BeFalse
        ConvertFrom-BoabIpLiteral -Text '1.2.3.4' | Should -Not -BeNullOrEmpty
        ConvertFrom-BoabIpLiteral -Text '::1' | Should -Not -BeNullOrEmpty
        ConvertFrom-BoabIpLiteral -Text '[::1]' | Should -BeNullOrEmpty
    }

    It 'names cipher suites like rustls Debug' {
        Get-BoabTlsCipherSuiteName -Code 0x1302 | Should -BeExactly 'TLS13_AES_256_GCM_SHA384'
        Get-BoabTlsCipherSuiteName -Code 0xC02F | Should -BeExactly 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        Get-BoabTlsCipherSuiteName -Code 0xCCA9 | Should -BeExactly 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
    }

    It 'computes X25519 (RFC 7748 section 5.2 vector)' {
        $k = ConvertFrom-TestHex 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
        $u = ConvertFrom-TestHex 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
        $out = Invoke-BoabX25519 -Scalar $k -U $u
        [System.Convert]::ToHexString($out).ToLowerInvariant() | Should -BeExactly 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
    }

    It 'derives TLS 1.3 secrets (RFC 8448 early secret and "derived")' {
        $zeros = [byte[]]::new(32)
        $early = Get-BoabHmac 'SHA256' $zeros $zeros
        [System.Convert]::ToHexString($early).ToLowerInvariant() | Should -BeExactly '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a'
        $derived = Invoke-BoabHkdfExpandLabel 'SHA256' $early 'derived' (Get-BoabDigest 'SHA256' ([byte[]]::new(0))) 32
        [System.Convert]::ToHexString($derived).ToLowerInvariant() | Should -BeExactly '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba'
    }

    It 'computes the ChaCha20 block function (RFC 8439 section 2.3.2)' {
        $key = [byte[]](0..31)
        $nonce = ConvertFrom-TestHex '000000090000004a00000000'
        $block = Get-BoabChaCha20Block -Key $key -Counter 1 -Nonce $nonce
        [System.Convert]::ToHexString([byte[]]$block[0..15]).ToLowerInvariant() | Should -BeExactly '10f1e7e4d13b5915500fdd1fa32071c4'
    }

    It 'decrypts a TLS 1.3 AES-GCM record' -Skip:(-not [System.Security.Cryptography.AesGcm]::IsSupported) {
        $key = [byte[]](1..16)
        $iv = [byte[]](21..32)
        $plain = [byte[]](0x08, 0, 0, 2, 0, 0, 22) # EncryptedExtensions + inner type 22
        $seq = 3
        $nonce = [byte[]]$iv.Clone()
        $nonce[11] = $nonce[11] -bxor 3
        $ct = [byte[]]::new($plain.Length)
        $tag = [byte[]]::new(16)
        $hdr = [byte[]](23, 3, 3, 0, ($plain.Length + 16))
        $g = [System.Security.Cryptography.AesGcm]::new($key, 16)
        $g.Encrypt($nonce, $plain, $ct, $tag, $hdr)
        $g.Dispose()
        $res = Unprotect-BoabTlsRecord -Suite 0x1301 -Key $key -Iv $iv -Seq $seq -Header $hdr -Payload ([byte[]]($ct + $tag))
        $res[0] | Should -Be 22
        [System.Convert]::ToHexString([byte[]]$res[1]) | Should -BeExactly '080000020000'
    }

    It 'builds a ClientHello offering what rustls/ring offers' {
        $share = New-BoabKeyShare -Group 0x001D
        $ch = New-BoabTlsClientHello -OfferTls13 $true -ServerName 'example.com' -Random ([byte[]]::new(32)) -SessionId ([byte[]]::new(32)) -KeyShares @($share) -Cookie $null
        $ch[0] | Should -Be 1
        (Get-BoabU24 $ch 1) | Should -Be ($ch.Length - 4)
        # legacy_version(2) random(32) sid_len(1) sid(32) -> cipher suites
        $o = 4 + 2 + 32 + 1 + 32
        $n = Get-BoabU16 $ch $o
        $suites = for ($i = 0; $i -lt $n; $i += 2) { Get-BoabU16 $ch ($o + 2 + $i) }
        $suites | Should -Be @(0x1302, 0x1301, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0x00FF)
        $ch12 = New-BoabTlsClientHello -OfferTls13 $false -ServerName $null -Random ([byte[]]::new(32)) -SessionId ([byte[]]::new(0)) -KeyShares @() -Cookie $null
        $o = 4 + 2 + 32 + 1
        $n = Get-BoabU16 $ch12 $o
        $n | Should -Be 14
    }

    It 'parses ServerHello messages, including HelloRetryRequest' {
        $pub = [byte[]](1..32)
        $exts = [System.IO.MemoryStream]::new()
        Add-BoabU16 $exts 0x002B; Add-BoabU16 $exts 2; Add-BoabU16 $exts 0x0304
        Add-BoabU16 $exts 0x0033; Add-BoabU16 $exts 36; Add-BoabU16 $exts 0x001D; Add-BoabU16 $exts 32; Add-BoabBytes $exts $pub
        $e = $exts.ToArray()
        $body = [System.IO.MemoryStream]::new()
        Add-BoabU16 $body 0x0303; Add-BoabBytes $body ([byte[]]::new(32)); Add-BoabU8 $body 0
        Add-BoabU16 $body 0x1301; Add-BoabU8 $body 0; Add-BoabU16 $body $e.Length; Add-BoabBytes $body $e
        $b = $body.ToArray()
        $msg = [System.IO.MemoryStream]::new(); Add-BoabU8 $msg 2; Add-BoabU24 $msg $b.Length; Add-BoabBytes $msg $b
        $sh = ConvertFrom-BoabTlsServerHello -Message $msg.ToArray()
        $sh.SelectedVersion | Should -Be 0x0304
        $sh.CipherSuite | Should -Be 0x1301
        $sh.KeyShareGroup | Should -Be 0x001D
        Get-BoabTlsGroupName -Codepoint $sh.KeyShareGroup | Should -BeExactly 'x25519'
        $sh.IsHelloRetry | Should -BeFalse
        [System.Convert]::ToHexString($sh.KeySharePublic) | Should -BeExactly ([System.Convert]::ToHexString($pub))

        $hrrRandom = ConvertFrom-TestHex 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c'
        $exts = [System.IO.MemoryStream]::new()
        Add-BoabU16 $exts 0x002B; Add-BoabU16 $exts 2; Add-BoabU16 $exts 0x0304
        Add-BoabU16 $exts 0x0033; Add-BoabU16 $exts 2; Add-BoabU16 $exts 0x11EC
        $e = $exts.ToArray()
        $body = [System.IO.MemoryStream]::new()
        Add-BoabU16 $body 0x0303; Add-BoabBytes $body $hrrRandom; Add-BoabU8 $body 0
        Add-BoabU16 $body 0x1302; Add-BoabU8 $body 0; Add-BoabU16 $body $e.Length; Add-BoabBytes $body $e
        $b = $body.ToArray()
        $msg = [System.IO.MemoryStream]::new(); Add-BoabU8 $msg 2; Add-BoabU24 $msg $b.Length; Add-BoabBytes $msg $b
        $hrr = ConvertFrom-BoabTlsServerHello -Message $msg.ToArray()
        $hrr.IsHelloRetry | Should -BeTrue
        $hrr.KeyShareGroup | Should -Be 0x11EC
        Test-BoabTlsHybridGroup -Codepoint $hrr.KeyShareGroup | Should -BeTrue

        $body = [System.IO.MemoryStream]::new()
        Add-BoabU16 $body 0x0303; Add-BoabBytes $body ([byte[]]::new(32)); Add-BoabU8 $body 0
        Add-BoabU16 $body 0xC02F; Add-BoabU8 $body 0
        $b = $body.ToArray()
        $msg = [System.IO.MemoryStream]::new(); Add-BoabU8 $msg 2; Add-BoabU24 $msg $b.Length; Add-BoabBytes $msg $b
        $sh12 = ConvertFrom-BoabTlsServerHello -Message $msg.ToArray()
        $sh12.SelectedVersion | Should -Be 0x0303
        Get-BoabTlsCipherSuiteName -Code $sh12.CipherSuite | Should -BeExactly 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        $sh12.KeyShareGroup | Should -BeNullOrEmpty
    }

    It 'parses TLS 1.2 and TLS 1.3 Certificate messages' {
        $pem = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs', 'rsa2048.crt'))
        $der = [byte[]](Get-BoabPemBlocks -Bytes $pem)[0]
        $b12 = [System.IO.MemoryStream]::new()
        Add-BoabU24 $b12 ($der.Length + 3); Add-BoabU24 $b12 $der.Length; Add-BoabBytes $b12 $der
        $body = $b12.ToArray()
        $m = [System.IO.MemoryStream]::new(); Add-BoabU8 $m 11; Add-BoabU24 $m $body.Length; Add-BoabBytes $m $body
        $certs = ConvertFrom-BoabTlsCertificateMessage -Message $m.ToArray() -Tls13 $false
        $certs.Count | Should -Be 1
        [System.Convert]::ToHexString([byte[]]$certs[0]) | Should -BeExactly ([System.Convert]::ToHexString($der))

        $b13 = [System.IO.MemoryStream]::new()
        Add-BoabU8 $b13 0; Add-BoabU24 $b13 ($der.Length + 5); Add-BoabU24 $b13 $der.Length; Add-BoabBytes $b13 $der; Add-BoabU16 $b13 0
        $body = $b13.ToArray()
        $m = [System.IO.MemoryStream]::new(); Add-BoabU8 $m 11; Add-BoabU24 $m $body.Length; Add-BoabBytes $m $body
        $certs = ConvertFrom-BoabTlsCertificateMessage -Message $m.ToArray() -Tls13 $true
        $certs.Count | Should -Be 1
    }

    It 'builds TLS certificate evidence like cert_finding_from_der' {
        $pem = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs', 'rsa2048.crt'))
        $der = [byte[]](Get-BoabPemBlocks -Bytes $pem)[0]
        $chain = [System.Collections.Generic.List[object]]::new()
        $chain.Add($der)
        $result = [pscustomobject]@{ NegotiatedVersion = 'TLSv1.2'; CipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'; CertChain = $chain; Alpn = $null }
        $found = Get-BoabTlsPopulatedFindings -ScanId 'sid' -Target 'host.example:443' -Result $result
        $found.Count | Should -Be 2
        (ConvertTo-TestJson $found[0].evidence) | Should -BeExactly '{"kind":"tls_endpoint","target":"host.example:443","tls_version":"TLSv1.2","cipher_suite":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","alpn":null,"pqc_status":"symmetric_ok"}'
        $found[0].source_type | Should -BeExactly 'host'
        @($found[1].evidence.Keys) | Should -Be @('kind', 'target', 'subject', 'issuer', 'signature_algorithm', 'signature_algorithm_oid', 'public_key_algorithm', 'public_key_algorithm_oid', 'public_key_bits', 'not_before_unix', 'not_after_unix', 'fingerprint_sha256', 'pqc_status')
        $found[1].evidence['public_key_bits'] | Should -Be 2048
        $found[1].evidence['subject'] | Should -BeExactly 'CN=rsa2048.example, O=Boab Demo, C=AU'
        $found[1].source_location | Should -BeExactly 'host.example:443|CN=rsa2048.example, O=Boab Demo, C=AU'
    }

    It 'rejects self-signed certificates like webpki' {
        $pem = [System.IO.File]::ReadAllBytes([System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs', 'rsa2048.crt'))
        $chain = [System.Collections.Generic.List[object]]::new()
        $chain.Add([byte[]](Get-BoabPemBlocks -Bytes $pem)[0])
        Test-BoabTlsServerCertificate -Chain $chain -ServerName 'rsa2048.example' -IpBytes $null | Should -BeFalse
    }

    It 'refuses --probe-hsts in air-gapped mode (port of probe_hsts_rejected_in_air_gapped_mode)' {
        { Invoke-BoabTlsScan -Targets @('example.com:443') -ProbeHsts } | Should -Throw -ExpectedMessage '*air-gapped*'
    }

    It 'skips excluded targets' {
        $scans = Invoke-BoabTlsScan -Targets @('a:1', 'b:2') -Exclude @('a:1', 'b:2')
        $scans.Count | Should -Be 0
    }

    It 'records failures with the Rust error text and keeps going' {
        $scans = Invoke-BoabTlsScan -Targets @('no-port', 'bad:port', '[::1]:443', '127.0.0.1:1') -RateLimit '1000/second' -TimeoutSeconds 3
        $scans.Count | Should -Be 4
        foreach ($s in $scans) {
            $s.status | Should -BeExactly 'failed'
            $s.scan_type | Should -BeExactly 'tls_endpoint'
            $s.findings.Count | Should -Be 0
            $s.completed_at | Should -Not -BeNullOrEmpty
            (ConvertTo-TestJson $s.config) | Should -BeExactly '{}'
        }
        $scans[0].name | Should -BeExactly 'tls:no-port'
        $scans[0].error_message | Should -BeExactly 'TLS handshake failed: tls13=target must be host:port, got no-port tls12=target must be host:port, got no-port'
        $scans[1].error_message | Should -BeExactly 'TLS handshake failed: tls13=invalid port in target bad:port tls12=invalid port in target bad:port'
        $scans[2].error_message | Should -BeExactly 'TLS handshake failed: tls13=invalid server name: [::1] tls12=invalid server name: [::1]'
        $scans[3].error_message | Should -BeExactly 'TLS handshake failed: tls13=TCP connect tls12=TCP connect'
    }
}

Describe 'TLS scanner (live)' -Tag 'Network' -Skip:(-not $script:RunNetworkTests) {
    It 'scans rsa2048.badssl.com like the Rust demo run' {
        $scans = Invoke-BoabTlsScan -Targets @('rsa2048.badssl.com:443') -RateLimit '1000/second'
        $s = $scans[0]
        $s.status | Should -BeExactly 'completed'
        $s.findings[0].evidence['tls_version'] | Should -BeExactly 'TLSv1.2'
        $s.findings[0].evidence['cipher_suite'] | Should -BeExactly 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        $leaf = @($s.findings | Where-Object { $_.source_location -eq 'rsa2048.badssl.com:443|CN=*.badssl.com' })
        $leaf.Count | Should -Be 1
        $leaf[0].evidence['public_key_bits'] | Should -Be 2048
    }

    It 'fails like rustls on untrusted or legacy endpoints' {
        $targets = @('expired.badssl.com:443', 'self-signed.badssl.com:443', 'sha1-intermediate.badssl.com:443', 'tls-v1-0.badssl.com:1010')
        foreach ($s in (Invoke-BoabTlsScan -Targets $targets -RateLimit '1000/second')) {
            $s.status | Should -BeExactly 'failed'
            $s.error_message | Should -BeExactly 'TLS handshake failed: tls13=TLS handshake tls12=TLS handshake'
        }
    }
}

Describe 'Live parity with the Rust binary' -Skip:(-not $script:HasRustBinary) {
    BeforeAll {
        $script:Ws = Join-Path $TestDrive 'ws'
        [void](New-Item -ItemType Directory -Path $script:Ws)
        & $env:BOAB_RUST_BIN --workspace $script:Ws init | Out-Null

        function Invoke-RustScan {
            param([string[]] $ScanArgs)
            $before = @(Get-ChildItem -LiteralPath (Join-Path $script:Ws '.boab' 'scans') -Filter '*.json' -ErrorAction Ignore | ForEach-Object Name)
            & $env:BOAB_RUST_BIN --workspace $script:Ws scan @ScanArgs | Out-Null
            $new = @(Get-ChildItem -LiteralPath (Join-Path $script:Ws '.boab' 'scans') -Filter '*.json' | Where-Object { $before -notcontains $_.Name })
            return (Get-Content -Raw -LiteralPath $new[0].FullName | ConvertFrom-Json)
        }

        function Get-NormalizedRustScan {
            param($Scan)
            $root = $Scan.target
            $hdr = [ordered]@{ name = $Scan.name; scan_type = $Scan.scan_type; status = $Scan.status; target = $Scan.target; config = $Scan.config; error_message = $Scan.error_message }
            $findings = foreach ($f in $Scan.findings) {
                $o = [ordered]@{ source_type = $f.source_type; source_location = $f.source_location; evidence = $f.evidence; confidence = $f.confidence; status = $f.status }
                Get-NormalizedJson -Json (ConvertTo-TestJson $o) -Root $root
            }
            $arr = [string[]]@($findings)
            [Array]::Sort($arr, [System.StringComparer]::Ordinal)
            return [pscustomobject]@{ Header = Get-NormalizedJson -Json (ConvertTo-TestJson $hdr) -Root $root; Findings = $arr }
        }
    }

    It 'matches the Rust binary on tests/fixtures/codebase' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'tests', 'fixtures', 'codebase')
        $rust = Invoke-RustScan -ScanArgs @('codebase', $path)
        $ps = Invoke-BoabCodebaseScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $ps -Root $ps.target) -Expected (Get-NormalizedRustScan -Scan $rust)
    }

    It 'matches the Rust binary on examples/demo/certs' {
        $path = [System.IO.Path]::Combine($script:RepoRoot, 'examples', 'demo', 'certs')
        $rust = Invoke-RustScan -ScanArgs @('certs', $path)
        $ps = Invoke-BoabCertStoreScan -Path $path
        Assert-ScanMatchesReference -Actual (Get-NormalizedScan -Scan $ps -Root $ps.target) -Expected (Get-NormalizedRustScan -Scan $rust)
    }
}
