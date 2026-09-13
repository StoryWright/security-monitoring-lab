$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$script:checks = 0
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'wazuh') -Filter '*.xml' -File) {
    [xml]$parsed = Get-Content -LiteralPath $file.FullName -Raw
    if ($parsed.DocumentElement.get_LocalName() -notin 'group','ossec_config') { throw "Unexpected root element: $($file.Name)" }
    $script:checks++
    Write-Output "PASS: XML syntax and root: $($file.Name)"
}
[xml]$rules = Get-Content -LiteralPath (Join-Path $root 'wazuh/storylab_rules.xml') -Raw
$ids = @($rules.group.rule | ForEach-Object { [string]$_.id })
if ($ids.Count -ne 6 -or @($ids | Sort-Object -Unique).Count -ne 6) { throw 'Expected six unique local rule IDs' }
$script:checks++
Write-Output 'PASS: Six unique local rule IDs'
$expected = Get-Content -LiteralPath (Join-Path $root 'fixtures/wazuh-expected.json') -Raw | ConvertFrom-Json
foreach ($item in $expected) {
    if ([string]$item.ruleId -notin $ids) { throw "Expected fixture rule is absent: $($item.ruleId)" }
}
if (@($expected).Count -ne 5) { throw 'Expected five native classification fixtures' }
$script:checks++
Write-Output 'PASS: Fixture expectations reference supplied rule IDs'
Write-Output "$script:checks configuration checks passed. Native Wazuh decoding and rule evaluation were NOT RUN."
