#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Port of the unit tests in src/dedup.rs plus key-derivation checks.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    InModuleScope Boab {
        function script:New-TestScan {
            [ordered]@{
                id = New-BoabUuid; name = 't'; scan_type = 'codebase'; status = 'queued'; target = 'x'
                config = [ordered]@{}; started_at = Get-BoabTimestamp; completed_at = $null
                findings = (New-BoabList); error_message = $null
            }
        }
        function script:New-TestFinding {
            param($ScanId, [string]$SourceLocation, $Evidence, [string]$SourceType = 'file')
            [ordered]@{
                id = New-BoabUuid; scan_id = $ScanId; crypto_asset_id = $null; source_type = $SourceType
                source_location = $SourceLocation; evidence = $Evidence; confidence = 'high'; status = 'new'
                discovered_at = Get-BoabTimestamp
            }
        }
        function script:New-TestAlgoFinding {
            param($ScanId, [string]$Algo, [string]$Status, [string]$Src, $Bits)
            $params = [ordered]@{}
            if ($null -ne $Bits) { $params.key_size_bits = [long]$Bits }
            New-TestFinding -ScanId $ScanId -SourceLocation $Src -Evidence ([ordered]@{
                    kind = 'algorithm_match'; algorithm_name = $Algo; pqc_status = $Status; parameter_set = $params
                })
        }
    }
}

Describe 'promote_findings' {
    It 'first run creates inventory entries and links findings' {
        InModuleScope Boab {
            $scan = New-TestScan
            $scan.findings.Add((New-TestAlgoFinding $scan.id 'MD5' 'vulnerable' 'src/a.rs:10' $null))
            $scan.findings.Add((New-TestAlgoFinding $scan.id 'AES-256' 'symmetric_ok' 'src/b.rs:5' 256))
            $inv = Merge-BoabFindingIntoInventory -Scan $scan -Inventory (New-BoabList)
            $inv.Count | Should -Be 2
            foreach ($f in $scan.findings) { $f.crypto_asset_id | Should -Not -BeNullOrEmpty }
            $inv[1].migration_difficulty | Should -BeExactly 'trivial'
            $inv[1].quantum_vulnerable | Should -BeFalse
            ConvertTo-BoabJson $inv[1].parameter_set -Compress | Should -BeExactly '{"key_size_bits":256,"source_root":"src"}'
        }
    }

    It 'second run does not duplicate' {
        InModuleScope Boab {
            $s1 = New-TestScan
            $s1.findings.Add((New-TestAlgoFinding $s1.id 'RSA' 'vulnerable' 'src/a.rs:1' 2048))
            $inv = Merge-BoabFindingIntoInventory -Scan $s1 -Inventory (New-BoabList)
            $inv.Count | Should -Be 1
            $s2 = New-TestScan
            $s2.findings.Add((New-TestAlgoFinding $s2.id 'RSA' 'vulnerable' 'src/a.rs:1' 2048))
            $inv2 = Merge-BoabFindingIntoInventory -Scan $s2 -Inventory $inv
            $inv2.Count | Should -Be 1
            $s2.findings[0].crypto_asset_id | Should -BeExactly $inv[0].id
        }
    }

    It 'preserves user-set fields on rescan' {
        InModuleScope Boab {
            $s1 = New-TestScan
            $s1.findings.Add((New-TestAlgoFinding $s1.id 'RSA' 'vulnerable' 'src/a.rs:1' 2048))
            $inv = Merge-BoabFindingIntoInventory -Scan $s1 -Inventory (New-BoabList)
            $inv[0].notes = 'Owned by Payments team'
            $inv[0].migration_status = 'in_progress'
            $s2 = New-TestScan
            $s2.findings.Add((New-TestAlgoFinding $s2.id 'RSA' 'vulnerable' 'src/a.rs:1' 2048))
            $inv2 = Merge-BoabFindingIntoInventory -Scan $s2 -Inventory $inv
            $inv2.Count | Should -Be 1
            $inv2[0].notes | Should -BeExactly 'Owned by Payments team'
            $inv2[0].migration_status | Should -BeExactly 'in_progress'
        }
    }

    It 'treats dedup keys case-sensitively apart from the lowered algorithm name' {
        InModuleScope Boab {
            $s = New-TestScan
            $s.findings.Add((New-TestAlgoFinding $s.id 'RSA' 'vulnerable' 'src/a.rs:1' 2048))
            $s.findings.Add((New-TestAlgoFinding $s.id 'rsa' 'vulnerable' 'src/b.rs:9' 2048))
            $s.findings.Add((New-TestAlgoFinding $s.id 'RSA' 'vulnerable' 'SRC/a.rs:1' 2048))
            $inv = Merge-BoabFindingIntoInventory -Scan $s -Inventory (New-BoabList)
            $inv.Count | Should -Be 2
        }
    }
}

Describe 'dedup key derivation' {
    It 'derives the source root of <Location> as <Root>' -ForEach @(
        @{ Location = 'src/a.rs:10'; Root = 'src' }
        @{ Location = 'go/example.go:10'; Root = 'go' }
        @{ Location = 'example.py:3'; Root = 'example.py' }
        @{ Location = 'host.example:443'; Root = 'host.example' }
        @{ Location = './app/x.py:1'; Root = '.' }
        @{ Location = 'a//b:1'; Root = 'a' }
        @{ Location = 'no-colon'; Root = 'no-colon' }
        @{ Location = ''; Root = '' }
    ) {
        InModuleScope Boab -Parameters @{ L = $Location; R = $Root } {
            param($L, $R)
            Get-BoabSourceRoot -SourceLocation $L | Should -BeExactly $R
        }
    }

    It 'uses / as the root of absolute unix paths' -Skip:$IsWindows {
        InModuleScope Boab { Get-BoabSourceRoot -SourceLocation '/abs/path/x.crt|CN=x' | Should -BeExactly '/' }
    }

    It 'builds library, TLS and fallback assets like dedup.rs' {
        InModuleScope Boab {
            $s = New-TestScan
            $s.findings.Add((New-TestFinding $s.id 'js/example.js:1' ([ordered]@{ kind = 'library_import'; library_name = 'node-forge' })))
            $s.findings.Add((New-TestFinding $s.id 'example.com:443' ([ordered]@{ kind = 'tls_endpoint'; target = 'example.com:443'; cipher_suite = 'TLS_AES_256_GCM_SHA384'; pqc_status = 'symmetric_ok' }) 'host'))
            $s.findings.Add((New-TestFinding $s.id 'example.com:443' ([ordered]@{ kind = 'tls_supported_group'; target = 'example.com:443'; group = 'X25519MLKEM768'; pqc_status = 'hybrid' }) 'host'))
            $s.findings.Add((New-TestFinding $s.id 'example.com:443|CN=x' ([ordered]@{ kind = 'tls_certificate'; target = 'example.com:443'; fingerprint_sha256 = 'abc'; signature_algorithm = 'sha256WithRSAEncryption'; public_key_bits = [long]2048; pqc_status = 'vulnerable' }) 'cert_subject'))
            $s.findings.Add((New-TestFinding $s.id 'weird:1' ([ordered]@{ kind = 'mystery' })))
            $inv = Merge-BoabFindingIntoInventory -Scan $s -Inventory (New-BoabList)
            $inv.Count | Should -Be 5
            $inv[0].asset_type | Should -BeExactly 'library_dependency'
            $inv[0].migration_difficulty | Should -BeExactly 'low'
            $inv[1].name | Should -BeExactly 'TLS_AES_256_GCM_SHA384@example.com'
            ConvertTo-BoabJson $inv[1].parameter_set -Compress | Should -BeExactly '{"source_root":"example.com","target":"example.com:443"}'
            $inv[2].primitive | Should -BeExactly 'kem'
            $inv[2].quantum_vulnerable | Should -BeTrue
            $inv[3].asset_type | Should -BeExactly 'certificate'
            $inv[3].name | Should -BeExactly 'example.com:443|CN=x'
            ConvertTo-BoabJson $inv[3].parameter_set -Compress | Should -BeExactly '{"key_size_bits":2048,"primitive":"signature","source_root":"example.com","target":"example.com:443","fingerprint_sha256":"abc"}'
            $inv[4].algorithm_name | Should -BeExactly 'unknown'
            (Get-BoabAssetDedupKey -Asset $inv[3]) | Should -BeExactly 'cert:abc'
            (Get-BoabAssetDedupKey -Asset $inv[1]) | Should -BeExactly 'tls_endpoint:example.com:443:TLS_AES_256_GCM_SHA384'
        }
    }

    It 'renders key-agreement primitives with Rust Debug casing inside parameter_set' {
        InModuleScope Boab {
            $s = New-TestScan
            $f = New-TestAlgoFinding $s.id 'ECDH' 'vulnerable' 'a/b.go:1' $null
            $f.evidence.parameter_set.primitive = 'key_agreement'
            $s.findings.Add($f)
            $inv = Merge-BoabFindingIntoInventory -Scan $s -Inventory (New-BoabList)
            $inv[0].primitive | Should -BeExactly 'key_agreement'
            $inv[0].parameter_set.primitive | Should -BeExactly 'keyagreement'
        }
    }

    It 'fingerprints cert_or_keystore_file findings by file content' {
        $dir = New-BoabTestDirectory
        $file = Join-Path $dir 'a.pem'
        Set-Content -LiteralPath $file -Value 'hello' -NoNewline
        InModuleScope Boab -Parameters @{ F = $file } {
            param($F)
            $s = New-TestScan
            $s.findings.Add((New-TestFinding $s.id $F ([ordered]@{ kind = 'cert_or_keystore_file'; extension = 'pem' })))
            $key = Get-BoabFindingKey -Finding $s.findings[0]
            $key.DedupKey | Should -BeExactly 'cert:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
            $inv = Merge-BoabFindingIntoInventory -Scan $s -Inventory (New-BoabList)
            $inv[0].algorithm_name | Should -BeExactly 'x509'
            $inv[0].name | Should -BeExactly $F
        }
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
