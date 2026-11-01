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
    # o certificado de teste traz o GUID de objeto do AD no SAN, como um DC real
    if ($i.Nomes -ne 'dc.teste.local, *.dcs.teste.local') { throw "a lista de nomes deveria ter so os nomes DNS: $($i.Nomes)" }
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
Cenario 'S numa pergunta de valor aceita o padrao (e nao vira valor)' {
    $ip = { param($v) $v -match '^\d+\.\d+\.\d+\.\d+$' }
    Responder @('s'); if ((Read-Valor 'ip' '172.16.10.7' $ip) -ne '172.16.10.7') { throw 's' }
    Responder @('Sim'); if ((Read-Valor 'ip' '172.16.10.7' $ip) -ne '172.16.10.7') { throw 'Sim' }
    Responder @('s'); if ((Read-Valor 'nome' 'svc' { $true }) -ne 's') { throw 'onde s e valido, vale o s' }
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

[Console]::WriteLine('6) IPs do controlador')
Cenario 'APIPA, loopback e repetidos ficam de fora' {
    $r = @(Select-IPv4Util @('169.254.155.128', '172.16.10.5', '127.0.0.1', '172.16.10.5', '', 'fe80::1', '10.0.0.2'))
    if (($r -join ',') -ne '172.16.10.5,10.0.0.2') { throw "resultado: $($r -join ',')" }
    'ok'
}
Cenario 'o IP da placa com gateway vem primeiro (LAN antes da VPN)' {
    $r = @(Sort-IpsPreferidos @('10.10.120.23', '172.16.10.7') @('172.16.10.7'))
    if (($r -join ',') -ne '172.16.10.7,10.10.120.23') { throw "resultado: $($r -join ',')" }
    if ((@(Sort-IpsPreferidos @('10.0.0.1', '10.0.0.2') @()) -join ',') -ne '10.0.0.1,10.0.0.2') { throw 'sem preferidos mudou a ordem' }
    'ok'
}
Cenario 'so APIPA -> lista vazia (o script pede o IP)' {
    if (@(Select-IPv4Util @('169.254.1.1')).Count -ne 0) { throw 'deveria ser vazia' }
    'ok'
}

[Console]::WriteLine('7) Setores por OU (v1.1)')
$acento = "Expedi$([char]0xE7)$([char]0xE3)o Instrumental"   # "Expedicao Instrumental" com cedilha e til
Cenario 'nome do setor: sem acento, maiusculo, so A-Z 0-9 _' {
    if ((ConvertTo-NomeSetor $acento) -ne 'EXPEDICAO_INSTRUMENTAL') { throw "resultado: $(ConvertTo-NomeSetor $acento)" }
    if ((ConvertTo-NomeSetor ' Suporte  Terceirizado ') -ne 'SUPORTE_TERCEIRIZADO') { throw 'espacos' }
    if ((ConvertTo-NomeSetor "Licita$([char]0xE7)$([char]0xE3)o") -ne 'LICITACAO') { throw 'licitacao' }
    'ok'
}
Cenario 'GUID no formato do objectGUID cru (o que o pfSense le pelo LDAP)' {
    $h = ConvertTo-GuidHex ([guid]'01234567-89ab-cdef-0123-456789abcdef')
    if ($h -ne '67452301ab89efcd0123456789abcdef') { throw "resultado: $h (a ordem dos bytes tem que ser a do AD)" }
    'ok'
}
Cenario 'espelhamento: entra quem esta na OU, sai quem saiu, [proxy-manual] fica' {
    $u = { param($dn, $d = '') [pscustomobject]@{ DistinguishedName = $dn; Description = $d; SamAccountName = ($dn -split ',')[0].Substring(3) } }
    $des = @((& $u 'CN=ana,OU=Fin'), (& $u 'CN=bia,OU=Fin'))
    $atu = @((& $u 'CN=bia,OU=Fin'), (& $u 'CN=caio,OU=Com'), (& $u 'CN=dani,OU=Dir' 'gerente [proxy-manual]'))
    $m = Get-MudancasMembros $des $atu
    if ((($m.Adicionar | ForEach-Object SamAccountName) -join ',') -ne 'ana') { throw "adicionar: $(($m.Adicionar | ForEach-Object SamAccountName) -join ',')" }
    if ((($m.Remover | ForEach-Object SamAccountName) -join ',') -ne 'caio') { throw "remover: $(($m.Remover | ForEach-Object SamAccountName) -join ',')" }
    $v = Get-MudancasMembros @() @()
    if ($v.Adicionar.Count -or $v.Remover.Count) { throw 'vazio' }
    'ok'
}

# ---- AD simulado em memoria para o Sync-SetoresAD ----
$script:AD = @{ OUs = New-Object System.Collections.ArrayList; Users = New-Object System.Collections.ArrayList; Groups = New-Object System.Collections.ArrayList }
function Novo-OU($dn) { [void]$script:AD.OUs.Add([pscustomobject]@{ Name = ($dn -split ',')[0].Substring(3); DistinguishedName = $dn }) }
function Novo-User($nome, $ou, $ativo = $true, $desc = '') { [void]$script:AD.Users.Add([pscustomobject]@{ Name = $nome; SamAccountName = $nome; DistinguishedName = "CN=$nome,$ou"; Enabled = $ativo; Description = $desc }) }
# Como no AD real: ao mover o usuario, a referencia nos grupos acompanha o novo DN.
function Mover-User($nome, $ou) {
    $u = $script:AD.Users | Where-Object SamAccountName -eq $nome
    $antigo = $u.DistinguishedName; $u.DistinguishedName = "CN=$nome,$ou"
    foreach ($g in $script:AD.Groups) { $i = $g.Members.IndexOf($antigo); if ($i -ge 0) { $g.Members[$i] = $u.DistinguishedName } }
}
function Pai($dn) { ($dn -split ',', 2)[1] }
function Get-ADOrganizationalUnit { param($SearchBase, $SearchScope, $Filter)
    @($script:AD.OUs | Where-Object { (Pai $_.DistinguishedName) -eq $SearchBase }) }
function Get-ADUser { param($SearchBase, $SearchScope, $Filter, $Properties, $Identity)
    if ($Identity) { return $script:AD.Users | Where-Object { $_.DistinguishedName -eq $Identity } }
    @($script:AD.Users | Where-Object { $_.Enabled -and $(if ($SearchScope -eq 'OneLevel') { (Pai $_.DistinguishedName) -eq $SearchBase } else { $_.DistinguishedName -like "*,$SearchBase" }) }) }
function Get-ADGroup { param($Filter, $Identity, $Properties, $ErrorAction)
    if ($Identity) { $dn = if ($Identity -is [string]) { $Identity } else { $Identity.DistinguishedName }; return $script:AD.Groups | Where-Object DistinguishedName -eq $dn }
    $n = [regex]::Match($Filter, "Name -eq '([^']+)'").Groups[1].Value
    $script:AD.Groups | Where-Object Name -eq $n }
function New-ADGroup { param($Name, $SamAccountName, $GroupCategory, $GroupScope, $Path, $Description, [switch]$PassThru)
    $g = [pscustomobject]@{ Name = $Name; DistinguishedName = "CN=$Name,$Path"; ObjectGUID = [guid]::NewGuid(); Members = (New-Object System.Collections.ArrayList) }
    [void]$script:AD.Groups.Add($g); $g }
function Get-ADGroupMember { param($Identity)
    @($Identity.Members | ForEach-Object { $dn = $_; [pscustomobject]@{ distinguishedName = $dn; objectClass = 'user' } }) }
function Add-ADGroupMember { param($Identity, $Members) foreach ($m in $Members) { [void]$Identity.Members.Add($m.DistinguishedName) } }
function Remove-ADGroupMember { param($Identity, $Members, $Confirm) foreach ($m in $Members) { $Identity.Members.Remove($m.DistinguishedName) } }
function Ok { param($m) }
$base = 'OU=AGF,DC=teste,DC=local'
Novo-OU "OU=Financeiro,$base"; Novo-OU "OU=Comercial,$base"; Novo-OU "OU=$acento,$base"
Novo-User 'ana' "OU=Financeiro,$base"; Novo-User 'bia' "OU=Financeiro,$base"; Novo-User 'caio' "OU=Comercial,$base"
Novo-User 'inativo' "OU=Comercial,$base" $false; Novo-User 'solto' $base

Cenario 'cria um grupo por OU, dentro da OU, com os usuarios ativos dela' {
    $r = Sync-SetoresAD $base 'NET_' $false
    $nomes = ($r.Grupos | ForEach-Object Name | Sort-Object) -join ','
    if ($nomes -ne 'NET_COMERCIAL,NET_EXPEDICAO_INSTRUMENTAL,NET_FINANCEIRO') { throw "grupos: $nomes" }
    $fin = $script:AD.Groups | Where-Object Name -eq 'NET_FINANCEIRO'
    if ($fin.DistinguishedName -ne "CN=NET_FINANCEIRO,OU=Financeiro,$base") { throw "lugar: $($fin.DistinguishedName)" }
    if (($fin.Members | Sort-Object) -join ';' -ne "CN=ana,OU=Financeiro,$base;CN=bia,OU=Financeiro,$base") { throw "membros: $($fin.Members -join ';')" }
    $com = $script:AD.Groups | Where-Object Name -eq 'NET_COMERCIAL'
    if ($com.Members.Count -ne 1) { throw 'inativo entrou no grupo' }
    "($($r.Log.Count) acao(oes))"
}
Cenario 'rodar de novo sem mudancas nao faz nada' {
    $r = Sync-SetoresAD $base 'NET_' $false
    if ($r.Log.Count) { throw "fez: $($r.Log -join ' | ')" }
    'ok'
}
Cenario 'usuario mudou de departamento: sai do grupo antigo, entra no novo' {
    Mover-User 'bia' "OU=Comercial,$base"
    $r = Sync-SetoresAD $base 'NET_' $false
    $fin = $script:AD.Groups | Where-Object Name -eq 'NET_FINANCEIRO'; $com = $script:AD.Groups | Where-Object Name -eq 'NET_COMERCIAL'
    if ($fin.Members -contains "CN=bia,OU=Comercial,$base" -or $fin.Members.Count -ne 1) { throw "financeiro: $($fin.Members -join ';')" }
    if (-not ($com.Members -contains "CN=bia,OU=Comercial,$base")) { throw 'nao entrou no comercial' }
    "($($r.Log -join ' | '))"
}
Cenario 'excecao manual: usuario de fora com [proxy-manual] nao e tirado' {
    Novo-User 'diretor' "OU=Diretoria,$base" $true 'Diretor [proxy-manual]'
    $fin = $script:AD.Groups | Where-Object Name -eq 'NET_FINANCEIRO'
    [void]$fin.Members.Add("CN=diretor,OU=Diretoria,$base")
    $r = Sync-SetoresAD $base 'NET_' $false
    if (-not ($fin.Members -contains "CN=diretor,OU=Diretoria,$base")) { throw 'tirou a excecao' }
    'ok'
}
Cenario 'OU nova de departamento ganha o grupo sozinha' {
    Novo-OU "OU=Qualidade,$base"; Novo-User 'quel' "OU=Qualidade,$base"
    $r = Sync-SetoresAD $base 'NET_' $false
    $q = $script:AD.Groups | Where-Object Name -eq 'NET_QUALIDADE'
    if (-not $q -or $q.Members.Count -ne 1) { throw 'grupo da OU nova' }
    "($($r.Log -join ' | '))"
}
Cenario 'OU recusada (N) fica lembrada e a tarefa automatica nao cria o grupo' {
    Novo-OU "OU=Computadores,$base"
    $script:Yes = $false
    # interativo: S para as outras perguntas que aparecerem, N para Computadores
    $script:fila.Clear(); 1..10 | ForEach-Object { $script:fila.Enqueue('n') }
    $r = Sync-SetoresAD $base 'NET_' $true
    if (@($r.Ignoradas) -notcontains "OU=Computadores,$base") { throw "nao lembrou: $($r.Ignoradas -join ';')" }
    if ($script:AD.Groups | Where-Object Name -eq 'NET_COMPUTADORES') { throw 'criou mesmo com N' }
    $r2 = Sync-SetoresAD $base 'NET_' $false @($r.Ignoradas)
    if ($script:AD.Groups | Where-Object Name -eq 'NET_COMPUTADORES') { throw 'a tarefa automatica criou a OU recusada' }
    'ok'
}
$script:SetoresTeste = @($script:AD.Groups)

[Console]::WriteLine('7b) Excecoes da GPO')
Cenario 'padrao sempre entra; extras somam sem repetir' {
    $p = '<local>;*.agfmedical.local;10.*;172.16.*;192.168.*'
    if ((Join-Excecoes $p '172.16.10.7') -ne "$p;172.16.10.7") { throw (Join-Excecoes $p '172.16.10.7') }
    if ((Join-Excecoes $p '') -ne $p) { throw 'sem extras' }
    if ((Join-Excecoes $p ' 172.16.* ; intranet.local;') -ne "$p;intranet.local") { throw (Join-Excecoes $p ' 172.16.* ; intranet.local;') }
    'ok'
}

[Console]::WriteLine('8) Arquivo para o pfSense (contrato com o squid-ad.php)')
Cenario 'New-PacoteSquid gera o JSON que o PHP le' {
    $dom = [pscustomobject]@{ DNSRoot = 'teste.local'; NetBIOSName = 'TESTE'; DistinguishedName = 'DC=teste,DC=local' }
    $setores = @($script:SetoresTeste | Sort-Object Name)   # os grupos criados pelo Sync-SetoresAD acima
    $i = Get-LdapsInfo 'dc.teste.local' $PortaTls '127.0.0.1'
    $d = New-PacoteSquid -Dom $dom -DcHost 'localhost' -DcIp '127.0.0.1' -Porta 636 -Transporte 'ssl' `
        -ContaDn 'CN=svc-squid-ldap,CN=Users,DC=teste,DC=local' -ContaUsuario 'svc-squid-ldap' -ContaSenha 'Aa1!senha-da-conta' `
        -Filtro '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
        -Setores $setores -CaPem (ConvertTo-Pem $i.Raiz.RawData) -Proxy $null -Sync ([ordered]@{ BaseOu = 'OU=AGF,DC=teste,DC=local'; Prefixo = 'NET_' })
    $arq = Join-Path $WorkDir 'pacote.json'
    ($d | ConvertTo-Json -Depth 5) | Set-Content -Path $arq -Encoding ASCII
    $volta = Get-Content $arq -Raw | ConvertFrom-Json
    if ($volta.Setores.Count -ne 4 -or $volta.Servidor.Porta -ne 636) { throw "estrutura errada ($($volta.Setores.Count) setores)" }
    if (@($volta.Setores | Where-Object { $_.Guid -notmatch '^[0-9a-f]{32}$' }).Count) { throw 'setor sem Guid' }
    if ($volta.Sync.Prefixo -ne 'NET_') { throw 'Sync' }
    "($arq)"
}

if ($script:falhas) { [Console]::WriteLine("RESULTADO AD: $($script:falhas) cenario(s) FALHARAM"); exit 1 }
[Console]::WriteLine('RESULTADO AD: todos os cenarios passaram')
