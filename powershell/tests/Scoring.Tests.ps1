#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

# Port of the unit tests in src/scoring.rs plus exhaustive golden comparisons
# against values produced by the Rust library (fixtures/golden/scores.json).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    $script:ScoresPath = Join-Path $PSScriptRoot 'fixtures' 'golden' 'scores.json'
    InModuleScope Boab {
        function script:New-TestAlgoAsset {
            param([string]$Name, $Params = [ordered]@{}, [string]$Status = 'vulnerable')
            $a = New-BoabCryptoAssetRecord -AssetType algorithm -AlgorithmName $Name -Name $Name -PqcStatus $Status -QuantumVulnerable $true -MigrationDifficulty medium
            $a.parameter_set = $Params
            $a
        }
        function script:New-TestSystem {
            param([string]$Criticality = 'standard', [bool]$Soci = $false, $Lifetime = $null)
            New-BoabSystemRecord -Name 'S' -Classification official -Criticality $Criticality -IsSoci $Soci -ExpectedDataLifetimeYears $Lifetime
        }
    }
}

Describe 'algo_vuln_score' {
    It 'scores <Name> (bits <Bits>) as <Expected>' -ForEach @(
        @{ Name = 'MD5'; Bits = $null; Expected = 10 }
        @{ Name = 'SHA-1'; Bits = $null; Expected = 10 }
        @{ Name = 'sha1'; Bits = $null; Expected = 10 }
        @{ Name = 'RSA'; Bits = 1024; Expected = 10 }
        @{ Name = 'DSA'; Bits = 1024; Expected = 10 }
        @{ Name = '3DES'; Bits = $null; Expected = 10 }
        @{ Name = 'RC4'; Bits = $null; Expected = 10 }
        @{ Name = 'RSA'; Bits = 2048; Expected = 9 }
        @{ Name = 'ECDSA-P-256'; Bits = $null; Expected = 9 }
        @{ Name = 'ECDSA-256'; Bits = $null; Expected = 9 }
        @{ Name = 'ECDH-256'; Bits = $null; Expected = 9 }
        @{ Name = 'DH'; Bits = 2048; Expected = 9 }
        @{ Name = 'RSA'; Bits = 3072; Expected = 8 }
        @{ Name = 'RSA'; Bits = 4096; Expected = 8 }
        @{ Name = 'ECDSA-P-384'; Bits = $null; Expected = 8 }
        @{ Name = 'ECDSA-P-521'; Bits = $null; Expected = 8 }
        @{ Name = 'X25519'; Bits = $null; Expected = 8 }
        @{ Name = 'Ed25519'; Bits = $null; Expected = 8 }
        @{ Name = 'X448'; Bits = $null; Expected = 8 }
        @{ Name = 'ML-KEM-768'; Bits = $null; Expected = 1 }
        @{ Name = 'ML-DSA-65'; Bits = $null; Expected = 1 }
        @{ Name = 'dilithium3'; Bits = $null; Expected = 1 }
        @{ Name = 'SLH-DSA-SHA2-128s'; Bits = $null; Expected = 1 }
        @{ Name = 'falcon-512'; Bits = $null; Expected = 1 }
        @{ Name = 'kyber768'; Bits = $null; Expected = 1 }
        @{ Name = 'hqc-128'; Bits = $null; Expected = 1 }
        @{ Name = 'sphincs+'; Bits = $null; Expected = 1 }
        @{ Name = 'AES-256-GCM'; Bits = $null; Expected = 0 }
        @{ Name = 'AES256'; Bits = $null; Expected = 0 }
        @{ Name = 'SHA-256'; Bits = $null; Expected = 0 }
        @{ Name = 'SHA384'; Bits = $null; Expected = 0 }
        @{ Name = 'SHA-512'; Bits = $null; Expected = 0 }
        @{ Name = 'SHA3-256'; Bits = $null; Expected = 0 }
        @{ Name = 'SHAKE128'; Bits = $null; Expected = 0 }
        @{ Name = 'ChaCha20-Poly1305'; Bits = $null; Expected = 0 }
        @{ Name = 'FrobnicatorCipher'; Bits = $null; Expected = 7 }
        @{ Name = 'RSA'; Bits = $null; Expected = 9 }
        @{ Name = 'DSA'; Bits = $null; Expected = 9 }
    ) {
        InModuleScope Boab -Parameters @{ N = $Name; B = $Bits; E = $Expected } {
            param($N, $B, $E)
            $params = [ordered]@{}
            if ($null -ne $B) { $params.key_size_bits = [long]$B }
            Get-BoabAlgorithmVulnerabilityScore -Asset (New-TestAlgoAsset -Name $N -Params $params) | Should -Be $E
        }
    }

    It 'uses pqc_status overrides (hybrid 5, resistant 1, symmetric_ok 0)' {
        InModuleScope Boab {
            Get-BoabAlgorithmVulnerabilityScore -Asset (New-TestAlgoAsset -Name 'X25519MLKEM768' -Status hybrid) | Should -Be 5
            Get-BoabAlgorithmVulnerabilityScore -Asset (New-TestAlgoAsset -Name 'ML-KEM-768' -Status resistant) | Should -Be 1
            Get-BoabAlgorithmVulnerabilityScore -Asset (New-TestAlgoAsset -Name 'some-cipher' -Status symmetric_ok) | Should -Be 0
        }
    }
}

Describe 'LATICE sub-scores' {
    It 'scores every data classification' {
        InModuleScope Boab {
            $expect = [ordered]@{ top_secret = 10; secret = 8; protected = 6; official_sensitive = 4; official = 2; unofficial = 0 }
            foreach ($k in $expect.Keys) {
                $a = New-TestAlgoAsset -Name 'RSA'
                $a.data_classification = $k
                Get-BoabDataSensitivityScore -Asset $a | Should -Be $expect[$k]
            }
            Get-BoabDataSensitivityScore -Asset (New-TestAlgoAsset -Name 'RSA') | Should -Be 0
        }
    }

    It 'buckets the HNDL horizon (today = 2026)' {
        InModuleScope Boab {
            $cases = @{ 2050 = 10; 2041 = 10; 2036 = 8; 2031 = 6; 2028 = 3; 2027 = 0; 2026 = 0; 2020 = 0 }
            foreach ($y in $cases.Keys) {
                $a = New-TestAlgoAsset -Name 'RSA'
                $a.data_retention_horizon_year = [long]$y
                Get-BoabHndlScore -Asset $a -CurrentYear 2026 -System $null | Should -Be $cases[$y] -Because "retention $y"
            }
        }
    }

    It 'falls back to the system lifetime, then to 5' {
        InModuleScope Boab {
            $a = New-TestAlgoAsset -Name 'RSA'
            Get-BoabHndlScore -Asset $a -CurrentYear 2026 -System (New-TestSystem -Lifetime 12) | Should -Be 8
            Get-BoabHndlScore -Asset $a -CurrentYear 2026 -System $null | Should -Be 5
            Get-BoabHndlScore -Asset $a -CurrentYear 2026 -System (New-TestSystem) | Should -Be 5
        }
    }

    It 'scores system criticality branches' {
        InModuleScope Boab {
            Get-BoabSystemCriticalityScore -System (New-TestSystem -Criticality mission_critical) | Should -Be 10
            Get-BoabSystemCriticalityScore -System (New-TestSystem -Criticality essential) | Should -Be 7
            Get-BoabSystemCriticalityScore -System (New-TestSystem -Criticality standard) | Should -Be 4
            Get-BoabSystemCriticalityScore -System (New-TestSystem -Criticality low) | Should -Be 1
            Get-BoabSystemCriticalityScore -System (New-TestSystem -Criticality low -Soci $true) | Should -Be 10
            Get-BoabSystemCriticalityScore -System $null | Should -Be 4
        }
    }

    It 'scores migration difficulty branches' {
        InModuleScope Boab {
            $expect = [ordered]@{ hardware_locked = 10; high = 8; medium = 6; low = 3; trivial = 1 }
            foreach ($k in $expect.Keys) {
                $a = New-TestAlgoAsset -Name 'RSA'
                $a.migration_difficulty = $k
                Get-BoabMigrationDifficultyScore -Asset $a | Should -Be $expect[$k]
            }
        }
    }
}

Describe 'priority and triage tier' {
    It 'rounds the weighted priority to one decimal' {
        InModuleScope Boab {
            [double](Get-BoabPriority 10 10 10 10 10) | Should -Be 10.0
            [double](Get-BoabPriority 5 5 0 0 0) | Should -Be 3.0
            Format-BoabF32 (Get-BoabPriority 7 7 3 3 3) | Should -BeExactly '5.4'
            Get-BoabPriority 7 7 3 3 3 | Should -BeOfType [single]
        }
    }

    It 'assigns tiers like the Rust rubric' {
        InModuleScope Boab {
            $p = Get-BoabPriority 10 10 10 0 1
            $p | Should -BeGreaterOrEqual 7.0
            Get-BoabTriageTier -Priority $p -MigDiff 1 -AlgoVuln 10 | Should -Be 1
            $p = Get-BoabPriority 10 10 0 0 8
            Get-BoabTriageTier -Priority $p -MigDiff 8 -AlgoVuln 10 | Should -Be 2
            $p = Get-BoabPriority 8 0 0 0 10
            Get-BoabTriageTier -Priority $p -MigDiff 10 -AlgoVuln 8 | Should -Be 2
            $p = Get-BoabPriority 7 0 0 0 1
            Get-BoabTriageTier -Priority $p -MigDiff 1 -AlgoVuln 7 | Should -Be 3
            $p = Get-BoabPriority 0 0 0 0 1
            Get-BoabTriageTier -Priority $p -MigDiff 1 -AlgoVuln 0 | Should -Be 4
        }
    }

    It 'has a recommended action for every tier and asset type' {
        InModuleScope Boab {
            foreach ($tier in 1..4) {
                foreach ($t in $script:BoabEnums.AssetType) {
                    Get-BoabRecommendedAction -Tier $tier -AssetType $t | Should -Not -BeNullOrEmpty
                }
            }
        }
    }

    It 'scores an asset end to end' {
        InModuleScope Boab {
            $a = New-TestAlgoAsset -Name 'RSA' -Params ([ordered]@{ key_size_bits = [long]2048 })
            $a.asset_type = 'certificate'
            $a.data_classification = 'protected'
            $a.data_retention_horizon_year = [long]2050
            $a.migration_difficulty = 'low'
            $sys = New-BoabSystemRecord -Name 'Payments' -Classification protected -Criticality mission_critical -IsSoci $true
            $s = Get-BoabRiskScore -Asset $a -System $sys -CurrentYear 2026
            $s.algorithm_vulnerability | Should -Be 9
            $s.data_sensitivity | Should -Be 6
            $s.harvest_now_decrypt_later | Should -Be 10
            $s.system_criticality | Should -Be 10
            $s.migration_difficulty | Should -Be 3
            $s.priority | Should -BeGreaterOrEqual 7.0
            $s.triage_tier | Should -Be 1
            $s.recommended_action | Should -Match 'ML-DSA'
            @($s.Keys) | Should -Be @('algorithm_vulnerability', 'data_sensitivity', 'harvest_now_decrypt_later', 'system_criticality', 'migration_difficulty', 'priority', 'triage_tier', 'recommended_action')
        }
    }
}

Describe 'Golden parity with the Rust scoring engine' {
    BeforeAll {
        $script:Golden = InModuleScope Boab -Parameters @{ P = $script:ScoresPath } {
            param($P)
            ConvertFrom-BoabJson -Json ([System.IO.File]::ReadAllText($P))
        }
    }

    It 'computes identical f32 priority and tier for every sub-score combination' {
        $failures = InModuleScope Boab -Parameters @{ Table = $script:Golden.table } {
            param($Table)
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($row in $Table) {
                $p = Get-BoabPriority $row[0] $row[1] $row[2] $row[3] $row[4]
                $t = Get-BoabTriageTier -Priority $p -MigDiff $row[4] -AlgoVuln $row[0]
                $expectedText = Format-BoabF32 ([single]$row[5])
                if ((Format-BoabF32 $p) -cne $expectedText -or [single]$row[5] -ne $p -or $t -ne $row[6]) {
                    $bad.Add(('{0}: got {1}/{2}' -f ($row -join ','), (Format-BoabF32 $p), $t))
                }
            }
            , $bad
        }
        $failures | Should -BeNullOrEmpty
        $script:Golden.table.Count | Should -Be 7920
    }

    It 'computes identical algorithm vulnerability scores' {
        $failures = InModuleScope Boab -Parameters @{ Cases = $script:Golden.algorithms } {
            param($Cases)
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $Cases) {
                $a = New-TestAlgoAsset -Name $c.name -Params $c.params -Status $c.pqc_status
                $got = Get-BoabAlgorithmVulnerabilityScore -Asset $a
                if ($got -ne $c.score) { $bad.Add(('{0} {1} {2}: got {3} expected {4}' -f $c.name, (ConvertTo-BoabJson $c.params -Compress), $c.pqc_status, $got, $c.score)) }
            }
            , $bad
        }
        $failures | Should -BeNullOrEmpty
    }

    It 'produces byte-identical RiskScore JSON for representative assets and systems' {
        $failures = InModuleScope Boab -Parameters @{ Cases = $script:Golden.full } {
            param($Cases)
            $bad = [System.Collections.Generic.List[string]]::new()
            $i = 0
            foreach ($c in $Cases) {
                $asset = ConvertTo-BoabCryptoAssetRecord -InputObject $c.asset
                $sys = if ($null -ne $c.system) { ConvertTo-BoabSystemRecord -InputObject $c.system } else { $null }
                $score = Get-BoabRiskScore -Asset $asset -System $sys -CurrentYear 2026
                # The golden fixture was written through serde_json::json!, which widens f32 to f64.
                $score.priority = [double]$score.priority
                $expected = ConvertTo-BoabJson -InputObject $c.score
                $got = ConvertTo-BoabJson -InputObject $score
                if ($got -cne $expected) { $bad.Add("case ${i}: $got <> $expected") }
                $i++
            }
            , $bad
        }
        $failures | Should -BeNullOrEmpty
        $script:Golden.full.Count | Should -BeGreaterThan 100
    }
}
