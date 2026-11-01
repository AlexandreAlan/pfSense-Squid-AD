<#
.SYNOPSIS
    Parser do PowerShell nos scripts, ASCII puro nos .ps1/.php e (opcional)
    PSScriptAnalyzer com a regra de compatibilidade com o Windows PowerShell 5.1.
    Rode no Windows PowerShell 5.1 (o dos servidores AD) e/ou no pwsh.
#>
param([switch]$Analyzer)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$erros = 0
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
foreach ($s in @('Install-SquidAD.ps1', 'tests/Test-AD.ps1', 'tests/Test-Sintaxe.ps1')) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $s), [ref]$t, [ref]$e)
    if ($e) { foreach ($x in $e) { Write-Host "ERRO $s linha $($x.Extent.StartLineNumber): $($x.Message)" }; $erros += $e.Count }
    else { Write-Host "Sintaxe OK: $s" }
}
# PS 5.1 le .ps1 sem BOM como ANSI: acento vira lixo. O .php vai para o pfSense.
foreach ($s in @('Install-SquidAD.ps1', 'pfsense/squid-ad.php')) {
    $b = [IO.File]::ReadAllBytes((Join-Path $repo $s))
    if (@($b | Where-Object { $_ -gt 127 }).Count) { Write-Host "ERRO ${s}: caractere fora do ASCII"; $erros++ } else { Write-Host "ASCII OK: $s" }
}
if ($Analyzer) {
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { Install-Module PSScriptAnalyzer -Scope CurrentUser -Force }
    $excluir = @('PSAvoidUsingWriteHost', 'PSUseApprovedVerbs', 'PSUseSingularNouns', 'PSUseShouldProcessForStateChangingFunctions',
                 'PSAvoidUsingConvertToSecureStringWithPlainText', 'PSReviewUnusedParameter', 'PSAvoidUsingEmptyCatchBlock')
    $cfg = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') } } }
    $r = @(Invoke-ScriptAnalyzer -Path (Join-Path $repo 'Install-SquidAD.ps1') -Severity Warning, Error -ExcludeRule $excluir -Settings $cfg)
    foreach ($x in $r) { Write-Host "[$($x.Severity)] linha $($x.Line) $($x.RuleName): $($x.Message)" }
    $erros += @($r | Where-Object { $_.Severity -eq 'Error' -or $_.RuleName -eq 'PSUseCompatibleSyntax' }).Count
    if (-not $r) { Write-Host 'PSScriptAnalyzer OK: Install-SquidAD.ps1' }
}
if ($erros) { Write-Host "FALHOU: $erros problema(s)."; exit 1 }
Write-Host 'Tudo OK.'
