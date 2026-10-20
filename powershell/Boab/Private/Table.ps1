# Console tables matching comfy-table's UTF8_FULL preset with the default
# (disabled) content arrangement, as printed by the Rust CLI when stdout is not a TTY.

function Format-BoabTable {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string[]]$Header,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IList]$Rows
    )
    $cols = $Header.Count
    # Split every cell into lines (comfy-table: content.split('\n')).
    $splitCell = {
        param([string]$s)
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $s.Split([char]10)) { $lines.Add($p) }
        , $lines
    }
    $allRows = [System.Collections.Generic.List[object]]::new()
    $allRows.Add($Header)
    foreach ($r in $Rows) { $allRows.Add($r) }
    $cellLines = [System.Collections.Generic.List[object]]::new()
    $widths = [int[]]::new($cols)
    for ($c = 0; $c -lt $cols; $c++) { $widths[$c] = 1 }  # comfy-table minimum content width
    foreach ($r in $allRows) {
        $rowLines = [object[]]::new($cols)
        for ($c = 0; $c -lt $cols; $c++) {
            $text = if ($c -lt @($r).Count) { [string]$r[$c] } else { '' }
            $lines = & $splitCell $text
            $rowLines[$c] = $lines
            foreach ($l in $lines) {
                $w = Get-BoabDisplayWidth -Text $l
                if ($w -gt $widths[$c]) { $widths[$c] = $w }
            }
        }
        $cellLines.Add($rowLines)
    }
    $border = {
        param([char]$left, [char]$fill, [char]$mid, [char]$right)
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append($left)
        for ($c = 0; $c -lt $cols; $c++) {
            if ($c -gt 0) { [void]$sb.Append($mid) }
            [void]$sb.Append($fill, $widths[$c] + 2)
        }
        [void]$sb.Append($right)
        $sb.ToString()
    }
    $renderRow = {
        param([object[]]$rowLines)
        $height = 1
        foreach ($l in $rowLines) { if ($l.Count -gt $height) { $height = $l.Count } }
        $out = [System.Collections.Generic.List[string]]::new()
        for ($h = 0; $h -lt $height; $h++) {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append([char]0x2502)
            for ($c = 0; $c -lt $cols; $c++) {
                if ($c -gt 0) { [void]$sb.Append([char]0x2506) }
                $cell = $rowLines[$c]
                $text = if ($h -lt $cell.Count) { $cell[$h] } else { '' }
                $pad = $widths[$c] - (Get-BoabDisplayWidth -Text $text)
                [void]$sb.Append([char]32).Append($text).Append([char]32, [int]($pad + 1))
            }
            [void]$sb.Append([char]0x2502)
            $out.Add($sb.ToString())
        }
        , $out
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add((& $border ([char]0x250C) ([char]0x2500) ([char]0x252C) ([char]0x2510)))
    $lines.AddRange([string[]](& $renderRow $cellLines[0]))
    $lines.Add((& $border ([char]0x255E) ([char]0x2550) ([char]0x256A) ([char]0x2561)))
    for ($i = 1; $i -lt $cellLines.Count; $i++) {
        if ($i -gt 1) { $lines.Add((& $border ([char]0x251C) ([char]0x254C) ([char]0x253C) ([char]0x2524))) }
        $lines.AddRange([string[]](& $renderRow $cellLines[$i]))
    }
    $lines.Add((& $border ([char]0x2514) ([char]0x2500) ([char]0x2534) ([char]0x2518)))
    $lines -join "`n"
}
