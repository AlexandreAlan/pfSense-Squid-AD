<#
.SYNOPSIS
    Testes das funcoes do Install-SquidAD.ps1 (roda no pwsh do Linux ou do Windows).
    Carrega as funcoes REAIS do script (sem rodar o fluxo dele) e confere:
    leitura do certificado LDAPS, PEM, senha gerada, escape de filtro LDAP,
    perguntas S/N e o arquivo .json que vai para o pfSense.
    Chamado pelo run-testes.sh, que sobe um servidor TLS local antes.
#>
param(
    [Parameter(Mandatory = $true)][int]$PortaTls,       # servidor TLS com SAN dc.teste.local
    [Parameter(Mandatory = $true)][string]$PinCaOpenssl,  # SHA-256 (hex) da CA que assinou, calculado pelo openssl
    [Parameter(Mandatory = $true)][string]$WorkDir
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Install-SquidAD.ps1'), [ref]$null, [ref]$null)
$ast.FindAll({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
function Write-Host { param($Object, $ForegroundColor) }   # silencia as mensagens das funcoes
$VersaoProjeto = 'teste'

$script:falhas = 0
function Cenario([string]$Nome, [scriptblock]$Corpo) {
    try { $r = & $Corpo; [Console]::WriteLine("  [PASSOU] $Nome $r") }
    catch { $script:falhas++; [Console]::WriteLine("  [FALHOU] $Nome -> $($_.Exception.Message)") }
}

[Console]::WriteLine('1) Certificado LDAPS do controlador')
Cenario 'le o certificado, a CA e confere o nome' {
    $i = Get-LdapsInfo 'dc.teste.local' $PortaTls '127.0.0.1'
    if (-not $i.NomeConfere) { throw "nome nao conferiu (nomes: $($i.Nomes))" }
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($i.Raiz.RawData)) -replace '-', ''
    if ($sha -ne $PinCaOpenssl.ToUpper()) { throw "CA extraida errada: $sha" }
    "(nomes: $($i.Nomes))"
}
Cenario 'nome diferente do certificado e detectado' {
    $i = Get-LdapsInfo 'outro.teste.local' $PortaTls '127.0.0.1'
    if ($i.NomeConfere) { throw 'deveria NAO conferir' }
    '(outro.teste.local nao esta no certificado)'
}
Cenario 'curinga *.dcs.teste.local cobre srv2.dcs.teste.local' {
    $i = Get-LdapsInfo 'srv2.dcs.teste.local' $PortaTls '127.0.0.1'
    if (-not $i.NomeConfere) { throw "curinga nao foi aceito (nomes: $($i.Nomes))" }
    'ok'
}
Cenario 'porta fechada da erro claro' {
    try { Get-LdapsInfo 'dc.teste.local' 1 '127.0.0.1' | Out-Null; throw 'deveria falhar' }
    catch { if ($_.Exception.Message -eq 'deveria falhar') { throw } }
    'ok'
}

[Console]::WriteLine('2) PEM da CA')
Cenario 'PEM valido para o openssl' {
    $i = Get-LdapsInfo 'dc.teste.local' $PortaTls '127.0.0.1'
    $pem = ConvertTo-Pem $i.Raiz.RawData
    $arq = Join-Path $WorkDir 'ca-extraida.pem'
    [IO.File]::WriteAllText($arq, $pem)
    $out = & openssl x509 -in $arq -noout -subject 2>&1
    if ($LASTEXITCODE -ne 0) { throw "openssl recusou o PEM: $out" }
    "($out)"
}

[Console]::WriteLine('3) Senha da conta de servico')
Cenario '32 caracteres, 4 classes, sem caracteres perigosos, sempre diferente' {
    $vistas = @{}
    for ($k = 0; $k -lt 200; $k++) {
        $s = New-SenhaForte
        if ($s.Length -ne 32) { throw "tamanho $($s.Length)" }
        if ($s -notmatch '[A-Z]' -or $s -notmatch '[a-z]' -or $s -notmatch '\d' -or $s -notmatch '[^A-Za-z0-9]') { throw "faltou classe: $s" }
        if ($s -match "[`"'\\\s`$``]") { throw "caractere perigoso: $s" }
        if ($vistas.ContainsKey($s)) { throw 'senha repetida' }
        $vistas[$s] = $true
    }
    '(200 senhas conferidas)'
}

[Console]::WriteLine('4) Escape de filtro LDAP (RFC 4515)')
Cenario 'caracteres especiais escapados' {
    $r = ConvertTo-LdapFiltro 'CN=Setor (TI)*,OU=X\Y'
    if ($r -ne 'CN=Setor \28TI\29\2a,OU=X\5cY') { throw "resultado: $r" }
    'ok'
}

[Console]::WriteLine('5) Perguntas S/N e valores')
$script:fila = New-Object System.Collections.Queue
function Read-Host { param($Prompt, [switch]$AsSecureString) $script:fila.Dequeue() }
function Warn { param($m) }
function Responder([string[]]$r) { $script:fila.Clear(); foreach ($x in $r) { $script:fila.Enqueue($x) } }
$Yes = $false
Cenario 'ENTER usa o padrao, S/N funcionam, lixo pergunta de novo' {
    Responder @(''); if (-not (Read-SimNao 'x' $true)) { throw 'ENTER com padrao S' }
    Responder @(''); if (Read-SimNao 'x' $false) { throw 'ENTER com padrao N' }
    Responder @('talvez', 'n'); if (Read-SimNao 'x' $true) { throw 'lixo e depois N' }
    Responder @('S'); if (-not (Read-SimNao 'x' $false)) { throw 'S maiusculo' }
    'ok'
}
Cenario 'Read-Valor valida e repete' {
    Responder @('abc', '0', '3128')
    $v = Read-Valor 'porta' '3128' { param($v) $v -match '^\d+$' -and [int]$v -ge 1 }
    if ($v -ne '3128') { throw "valor: $v" }
    'ok'
}
$Yes = $true
Cenario '-Yes responde o padrao sem perguntar' {
    Responder @()
    if (-not (Read-SimNao 'x' $true)) { throw 'padrao S' }
    if (Read-SimNao 'x' $false) { throw 'padrao N continua N com -Yes' }
    if ((Read-Valor 'v' 'abc') -ne 'abc') { throw 'valor padrao' }
    'ok'
}
$Yes = $false

[Console]::WriteLine('6) Arquivo para o pfSense (contrato com o squid-ad.php)')
Cenario 'New-PacoteSquid gera o JSON que o PHP le' {
    $dom = [pscustomobject]@{ DNSRoot = 'teste.local'; NetBIOSName = 'TESTE'; DistinguishedName = 'DC=teste,DC=local' }
    $setores = @([pscustomobject]@{ Name = 'SETOR-FINANCEIRO'; DistinguishedName = 'CN=SETOR-FINANCEIRO,OU=Setores,DC=teste,DC=local' },
                 [pscustomobject]@{ Name = 'SETOR-COMPRAS';    DistinguishedName = 'CN=SETOR-COMPRAS,OU=Setores,DC=teste,DC=local' })
    $i = Get-LdapsInfo 'dc.teste.local' $PortaTls '127.0.0.1'
    $d = New-PacoteSquid -Dom $dom -DcHost 'localhost' -DcIp '127.0.0.1' -Porta 636 -Transporte 'ssl' `
        -ContaDn 'CN=svc-squid-ldap,CN=Users,DC=teste,DC=local' -ContaUsuario 'svc-squid-ldap' -ContaSenha 'Aa1!senha-da-conta' `
        -Filtro '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
        -Setores $setores -CaPem (ConvertTo-Pem $i.Raiz.RawData) -Proxy $null
    $arq = Join-Path $WorkDir 'pacote.json'
    ($d | ConvertTo-Json -Depth 5) | Set-Content -Path $arq -Encoding ASCII
    $volta = Get-Content $arq -Raw | ConvertFrom-Json
    if ($volta.Setores.Count -ne 2 -or $volta.Servidor.Porta -ne 636) { throw 'estrutura errada' }
    "($arq)"
}

if ($script:falhas) { [Console]::WriteLine("RESULTADO AD: $($script:falhas) cenario(s) FALHARAM"); exit 1 }
[Console]::WriteLine('RESULTADO AD: todos os cenarios passaram')
