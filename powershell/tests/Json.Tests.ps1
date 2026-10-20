#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-BoabTestModule
    $script:Numbers = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'golden' 'numbers.json') | ConvertFrom-Json
}

Describe 'ConvertTo-BoabJson (serde_json::to_string_pretty parity)' {
    It 'renders empty containers like serde_json' {
        ConvertTo-BoabJson -InputObject ([ordered]@{ a = @(); b = [ordered]@{} }) | Should -BeExactly "{`n  `"a`": [],`n  `"b`": {}`n}"
    }

    It 'renders nested structures with two-space indentation' {
        $v = [ordered]@{ name = 'x'; list = @(1, 2); obj = [ordered]@{ k = $null; t = $true } }
        $expected = "{`n  `"name`": `"x`",`n  `"list`": [`n    1,`n    2`n  ],`n  `"obj`": {`n    `"k`": null,`n    `"t`": true`n  }`n}"
        ConvertTo-BoabJson -InputObject $v | Should -BeExactly $expected
    }

    It 'renders a top-level empty array as []' {
        ConvertTo-BoabJson -InputObject ([System.Collections.Generic.List[object]]::new()) | Should -BeExactly '[]'
    }

    It 'escapes only quote, backslash and control characters' {
        $s = "a`"b\c/d`té" + [char]1 + [char]0x7f + "`n`r" + [char]8 + [char]12
        ConvertTo-BoabJson -InputObject $s | Should -BeExactly ('"a\"b\\c/d\t' + 'é' + '\u0001' + [char]0x7f + '\n\r\b\f"')
    }

    It 'keeps integers integral and floats with a decimal point' {
        ConvertTo-BoabJson -InputObject ([ordered]@{ i = [long]25; f = 1.0; g = [single]5.4; u = [ulong]::MaxValue }) -Compress |
            Should -BeExactly '{"i":25,"f":1.0,"g":5.4,"u":18446744073709551615}'
    }

    It 'matches serde_json f64 formatting for every reference value' {
        $parsed = InModuleScope Boab -Parameters @{ Text = $script:Numbers.f64 } { param($Text) ConvertFrom-BoabJson -Json $Text }
        ConvertTo-BoabJson -InputObject $parsed -Compress | Should -BeExactly $script:Numbers.f64
    }

    It 'matches serde_json f32 formatting for every reference value' {
        $out = InModuleScope Boab -Parameters @{ Text = $script:Numbers.f32 } {
            param($Text)
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($d in (ConvertFrom-BoabJson -Json $Text)) { $list.Add([single][double]$d) }
            ConvertTo-BoabJson -InputObject $list -Compress
        }
        $out | Should -BeExactly $script:Numbers.f32
    }

    It 'matches Rust {:.1} formatting of f32 values' {
        $failures = InModuleScope Boab -Parameters @{ Text = $script:Numbers.f32; Expected = @($script:Numbers.f32_fixed1) } {
            param($Text, $Expected)
            $values = @(ConvertFrom-BoabJson -Json $Text)
            $bad = @()
            for ($i = 0; $i -lt $values.Count; $i++) {
                $got = Format-BoabFixed -Value ([double][single][double]$values[$i]) -Decimals 1
                if ($got -cne $Expected[$i]) { $bad += "$($values[$i]): got $got expected $($Expected[$i])" }
            }
            , $bad
        }
        $failures | Should -BeNullOrEmpty
    }

    It 'matches the Markdown vulnerable-percentage computation for every ratio up to 64' {
        $failures = InModuleScope Boab -Parameters @{ Cases = @($script:Numbers.percent) } {
            param($Cases)
            $bad = @()
            foreach ($c in $Cases) {
                $v = [int]$c[0]; $t = [int]$c[1]
                $pct = ConvertTo-BoabF32 ((ConvertTo-BoabF32 ([double]$v * 100.0)) / [double]$t)
                $got = Format-BoabFixed -Value $pct -Decimals 1
                if ($got -cne $c[2]) { $bad += "$v/$t got $got expected $($c[2])" }
            }
            , $bad
        }
        $failures | Should -BeNullOrEmpty
    }

    It 'rounds {:.1} half to even on exact ties' {
        InModuleScope Boab {
            Format-BoabFixed -Value 0.25 -Decimals 1 | Should -BeExactly '0.2'
            Format-BoabFixed -Value 0.75 -Decimals 1 | Should -BeExactly '0.8'
            Format-BoabFixed -Value 12.25 -Decimals 1 | Should -BeExactly '12.2'
            Format-BoabFixed -Value 0.35 -Decimals 1 | Should -BeExactly '0.3'
        }
    }
}

Describe 'ConvertFrom-BoabJson' {
    It 'preserves key order and distinguishes integers from floats' {
        InModuleScope Boab {
            $v = ConvertFrom-BoabJson -Json '{"z":1,"a":2.0,"m":[true,null,"s"],"big":18446744073709551615}'
            @($v.Keys) | Should -Be @('z', 'a', 'm', 'big')
            $v.z | Should -BeOfType [long]
            $v.a | Should -BeOfType [double]
            $v.big | Should -BeOfType [ulong]
            $v.m.Count | Should -Be 3
            ConvertTo-BoabJson -InputObject $v -Compress | Should -BeExactly '{"z":1,"a":2.0,"m":[true,null,"s"],"big":18446744073709551615}'
        }
    }

    It 'mirrors serde_json::Value::as_u64 semantics' {
        InModuleScope Boab {
            Get-BoabJsonU64 ([long]2048) | Should -Be 2048
            Get-BoabJsonU64 ([long]-1) | Should -BeNullOrEmpty
            Get-BoabJsonU64 ([double]2048.0) | Should -BeNullOrEmpty
            Get-BoabJsonU64 '2048' | Should -BeNullOrEmpty
        }
    }

    It 'round-trips the bundled vendor registry byte-for-byte through the model' {
        InModuleScope Boab {
            $text = [System.IO.File]::ReadAllText($script:BoabBundledRegistryPath)
            $reg = ConvertTo-BoabVendorRegistryRecord -InputObject (ConvertFrom-BoabJson -Json $text)
            (ConvertTo-BoabJson -InputObject $reg) | Should -BeExactly ($text.TrimEnd("`n") -replace "`r`n", "`n")
        }
    }
}

Describe 'Timestamps' {
    It 'formats RFC 3339 like the time crate (trimmed fraction, Z)' {
        InModuleScope Boab {
            ConvertTo-BoabCanonicalRfc3339 -Text '2026-05-19T01:42:01.749119000Z' | Should -BeExactly '2026-05-19T01:42:01.749119Z'
            ConvertTo-BoabCanonicalRfc3339 -Text '2026-05-19T01:42:01.000Z' | Should -BeExactly '2026-05-19T01:42:01Z'
            ConvertTo-BoabCanonicalRfc3339 -Text '2026-05-19T01:42:01+10:00' | Should -BeExactly '2026-05-19T01:42:01+10:00'
        }
    }

    It 'formats plan target dates with the iso8601 serde format' {
        InModuleScope Boab {
            Get-BoabFrontLoadedTargetDate -Milestone 'y2030' -Tier 3 | Should -BeExactly '+002030-09-01T00:00:00.000000000Z'
            Get-BoabFrontLoadedTargetDate -Milestone 'y2028' -Tier 1 | Should -BeExactly '+002028-03-01T00:00:00.000000000Z'
            Get-BoabFrontLoadedTargetDate -Milestone 'y2028' -Tier 2 | Should -BeExactly '+002028-06-01T00:00:00.000000000Z'
            Get-BoabFrontLoadedTargetDate -Milestone 'y2026' -Tier 4 | Should -BeExactly '+002026-12-01T00:00:00.000000000Z'
        }
    }
}

Describe 'TOML config (toml::to_string_pretty parity)' {
    It 'chooses the same string representation as toml_write for <Value>' -ForEach @(
        @{ Value = 'plain'; Expected = '"plain"' }
        @{ Value = 'a"b'; Expected = "'a`"b'" }
        @{ Value = 'a\b'; Expected = "'a\b'" }
        @{ Value = "a'b`"c"; Expected = "`"`"`"a'b`"c`"`"`"" }
        @{ Value = "line`nbreak"; Expected = "`"`"`"`nline`nbreak`"`"`"" }
        @{ Value = 'é ünï'; Expected = '"é ünï"' }
        @{ Value = "tab`there"; Expected = '"tab\there"' }
        @{ Value = 'ctl' + [char]1 + 'x'; Expected = '"ctl\u0001x"' }
        @{ Value = "it's"; Expected = "`"it's`"" }
        @{ Value = "a`"b'c\d"; Expected = "'''a`"b'c\d'''" }
        @{ Value = ''; Expected = '""' }
        @{ Value = 'tri"""ple'; Expected = "'tri`"`"`"ple'" }
        @{ Value = "a'''b`"c`n"; Expected = "`"`"`"`na'''b`"c`n`"`"`"" }
        @{ Value = [string][char]0x7f; Expected = '"\u007F"' }
    ) {
        InModuleScope Boab -Parameters @{ V = $Value; E = $Expected } {
            param($V, $E)
            ConvertTo-BoabTomlString -Value $V | Should -BeExactly $E
            $cfg = New-BoabDefaultConfig
            $cfg.scanner.default_rate_limit = $V
            $parsed = ConvertTo-BoabConfigRecord -Table (ConvertFrom-BoabToml -Text (ConvertTo-BoabConfigToml -Config $cfg))
            $parsed.scanner.default_rate_limit | Should -BeExactly $V
        }
    }

    It 'serialises the default config exactly like the Rust crate' {
        InModuleScope Boab {
            ConvertTo-BoabConfigToml -Config (New-BoabDefaultConfig) |
                Should -BeExactly "schema_version = 1`n`n[scanner]`ndefault_rate_limit = `"1/second`"`ntls_timeout_seconds = 10`nair_gapped = true`n`n[reporting]`ndefault_format = `"md`"`n"
        }
    }

    It 'parses the commented default config written by init' {
        InModuleScope Boab {
            $cfg = ConvertTo-BoabConfigRecord -Table (ConvertFrom-BoabToml -Text $script:BoabDefaultConfigText)
            $cfg.schema_version | Should -Be 1
            $cfg.scanner.tls_timeout_seconds | Should -Be 10
            $cfg.scanner.air_gapped | Should -BeTrue
            $cfg.reporting.default_format | Should -BeExactly 'md'
        }
    }

    It 'reports Rust parse errors for config set' {
        InModuleScope Boab {
            $cfg = New-BoabDefaultConfig
            { Set-BoabConfigValue -Config $cfg -Key 'scanner.air_gapped' -Value 'maybe' } | Should -Throw 'air_gapped must be true or false: provided string was not `true` or `false`'
            { Set-BoabConfigValue -Config $cfg -Key 'schema_version' -Value 'abc' } | Should -Throw 'schema_version must be a u32: invalid digit found in string'
            { Set-BoabConfigValue -Config $cfg -Key 'reporting.default_format' -Value 'x' } | Should -Throw 'default_format must be one of: json, md, cbom'
            { Set-BoabConfigValue -Config $cfg -Key 'nope' -Value 'x' } | Should -Throw 'unknown config key: nope'
        }
    }
}
