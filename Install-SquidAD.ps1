<#
.SYNOPSIS
    Prepara o Active Directory para o Squid do pfSense autenticar usuarios via LDAP.

.DESCRIPTION
    Roda no CONTROLADOR DE DOMINIO (ou num servidor com RSAT), como Administrador.
    Tudo e perguntado e explicado antes: o padrao aparece entre [colchetes] e
    ENTER aceita. Nada e criado ou alterado no AD sem um S.

      1. identifica o dominio
      2. escolhe o controlador de dominio (lista os DCs encontrados)
      3. confere o LDAPS (porta 636) e o certificado do DC
      4. descobre os grupos que parecem SETORES e pergunta quais usar
         (e pode criar grupos de setor novos)
      5. cria (ou reaproveita) a conta de servico SO LEITURA usada pelo pfSense
      6. testa o LDAP com essa conta - e, se quiser, com um usuario real
      7. (opcional) cria a GPO que configura o proxy nos PCs
      8. gera o arquivo squid-ad-<DOMINIO>.json para o script do pfSense

    Nesta versao TODOS os usuarios autenticados acessam tudo. Os setores ficam
    cadastrados para o relatorio de acessos (quem acessa o que, por setor) e
    para a restricao futura.

.PARAMETER OutFile
    Onde gravar o arquivo para o pfSense. Padrao: squid-ad-<DOMINIO>.json na
    pasta deste script.

.PARAMETER Yes
    Responde S para tudo que tem padrao S (automacao). Nao cria GPO nem grupos
    novos sem pergunta explicita.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-SquidAD.ps1

.NOTES
    Windows PowerShell 5.1, modulo ActiveDirectory (ja vem no DC). Arquivo em
    ASCII puro de proposito (PS 5.1 le .ps1 sem BOM como ANSI).
    Projeto: https://github.com/AlexandreAlan/pfSense-Squid-AD
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$VersaoProjeto = '1.0.0'
$Aqui = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Padroes que costumam indicar grupo de SETOR (ex.: SETOR-FINANCEIRO, DEP_COMPRAS)
$PadraoSetor = '^(SETOR|SET|DEP|DEPTO|DEPARTAMENTO|GRP|GG|GS)[-_ .]'

# ------------------------------ helpers -------------------------------
function Step([string]$m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor Cyan }
function Ok([string]$m)   { Write-Host "    OK  $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "    !!  $m" -ForegroundColor Yellow }
function Info([string]$m) { Write-Host "        $m" }

# Pergunta S/N com padrao. ENTER = padrao. Com -Yes, assume o padrao.
function Read-SimNao([string]$Pergunta, [bool]$Padrao = $true) {
    $sufixo = if ($Padrao) { '[S/n]' } else { '[s/N]' }
    if ($Yes) { Info "$Pergunta $sufixo -> $(if ($Padrao) { 'S' } else { 'N' }) (-Yes)"; return $Padrao }
    while ($true) {
        $r = Read-Host "    $Pergunta $sufixo"
        if ([string]::IsNullOrWhiteSpace($r)) { return $Padrao }
        if ($r -match '^[sSyY]') { return $true }
        if ($r -match '^[nN]')   { return $false }
        Warn 'responda S ou N (ou ENTER para o padrao).'
    }
}

# Pergunta um valor com padrao entre colchetes. ENTER mantem.
function Read-Valor([string]$Pergunta, [string]$Padrao, [scriptblock]$Valido = { $true }, [string]$Ajuda = 'valor invalido.') {
    if ($Yes -and $Padrao) { Info "$Pergunta [$Padrao] -> $Padrao (-Yes)"; return $Padrao }
    while ($true) {
        $r = Read-Host "    $Pergunta [$Padrao]"
        if ([string]::IsNullOrWhiteSpace($r)) { $r = $Padrao }
        $r = "$r".Trim()
        if ($r -and (& $Valido $r)) { return $r }
        Warn $Ajuda
    }
}

function New-SenhaForte([int]$Tamanho = 32) {
    # Sem aspas, barra invertida, espaco nem $: a senha vai parar no squid.conf
    # e em linhas de comando do pfSense.
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!@#%+='
    $bytes = New-Object byte[] $Tamanho
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $s = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    # garante as 4 classes que a politica de senha do AD costuma exigir
    return 'Aa1!' + $s.Substring(4)
}

function ConvertTo-Pem([byte[]]$Der) {
    $b64 = [Convert]::ToBase64String($Der)
    $linhas = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    return "-----BEGIN CERTIFICATE-----`n" + ($linhas -join "`n") + "`n-----END CERTIFICATE-----`n"
}

# Le o certificado do LDAPS do DC (sem validar ainda) e monta a cadeia.
# $Endereco: onde conectar (padrao: o proprio nome). O nome conferido no
# certificado e sempre $Servidor - e o nome que o pfSense vai usar.
function Get-LdapsInfo([string]$Servidor, [int]$Porta = 636, [string]$Endereco = '') {
    if (-not $Endereco) { $Endereco = $Servidor }
    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($Endereco, $Porta, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { throw "sem resposta em ${Servidor}:$Porta" }
        $tcp.EndConnect($ar)
        # Guarda a cadeia que o proprio servidor enviou na conexao (inclui a CA,
        # se o DC mandar). Copia os bytes: os objetos da cadeia somem depois.
        $script:CadeiaTls = @()
        $aceita = [Net.Security.RemoteCertificateValidationCallback]{
            param($s, $c, $ch, $e)
            if ($ch) { $script:CadeiaTls = @($ch.ChainElements | ForEach-Object { New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $_.Certificate.RawData) }) }
            $true
        }
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $aceita)
        try {
            $ssl.AuthenticateAsClient($Servidor, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        } finally { $ssl.Dispose() }
    } finally { $tcp.Close() }

    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $confiavel = $chain.Build($cert)
    # A CA que o pfSense precisa confiar: a raiz da cadeia. Prefere a cadeia que
    # o Windows montou; se ela parou no proprio certificado (CA nao instalada
    # aqui), usa a que veio na conexao; em ultimo caso, o proprio certificado
    # (autoassinado).
    $elementos = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    if ($elementos.Count -lt 2 -and @($script:CadeiaTls).Count -ge 2) { $elementos = @($script:CadeiaTls) }
    $raiz = if ($elementos.Count -gt 0) { $elementos[-1] } else { $cert }

    $nomes = @()
    $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($san) { $nomes = @(($san.Format($false) -split ',\s*') | ForEach-Object { ($_ -split '[=:]', 2)[-1].Trim() }) }
    $cn = ($cert.Subject -split ',\s*' | Where-Object { $_ -like 'CN=*' } | Select-Object -First 1)
    if ($cn) { $nomes += $cn.Substring(3) }
    # Nome exato, ou curinga (*.dominio.local) cobrindo o nome do servidor
    $confere = @($nomes | Where-Object { $_ -ieq $Servidor -or ($_.StartsWith('*.') -and $Servidor -like $_) }).Count -gt 0

    return [pscustomobject]@{
        Certificado   = $cert
        Raiz          = $raiz
        ConfiavelAqui = $confiavel
        NomeConfere   = $confere
        Nomes         = ($nomes | Select-Object -Unique) -join ', '
    }
}

# Testa um bind LDAP de verdade (o mesmo que o Squid vai fazer).
function Test-LdapBind([string]$Servidor, [int]$Porta, [bool]$Ssl, [string]$Usuario, [string]$Senha) {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Servidor, $Porta)
    $cred = New-Object System.Net.NetworkCredential($Usuario, $Senha)
    $con  = New-Object System.DirectoryServices.Protocols.LdapConnection($id, $cred, [System.DirectoryServices.Protocols.AuthType]::Basic)
    $con.SessionOptions.ProtocolVersion = 3
    if ($Ssl) { $con.SessionOptions.SecureSocketLayer = $true }
    $con.Timeout = New-TimeSpan -Seconds 10
    $con.Bind()
    return $con
}

function Search-Ldap($Con, [string]$Base, [string]$Filtro, [string[]]$Atributos) {
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest($Base, $Filtro, [System.DirectoryServices.Protocols.SearchScope]::Subtree, $Atributos)
    return @(($Con.SendRequest($req)).Entries)
}

# Escapa um valor para dentro de um filtro LDAP (RFC 4515).
function ConvertTo-LdapFiltro([string]$Valor) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Valor.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\5c') }  '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }  ')' { [void]$sb.Append('\29') }
            default { if ([int]$ch -eq 0) { [void]$sb.Append('\00') } else { [void]$sb.Append($ch) } }
        }
    }
    return $sb.ToString()
}

# O arquivo que o squid-ad.php (pfSense) le. O formato e conferido nos testes
# (tests/): o que sai daqui tem que ser aceito pelo sqad_ler_pacote() do PHP.
function New-PacoteSquid($Dom, [string]$DcHost, [string]$DcIp, [int]$Porta, [string]$Transporte,
                         [string]$ContaDn, [string]$ContaUsuario, [string]$ContaSenha,
                         [string]$Filtro, $Setores, [string]$CaPem, $Proxy) {
    return [ordered]@{
        Projeto  = 'pfSense-Squid-AD'
        Versao   = $VersaoProjeto
        GeradoEm = (Get-Date).ToString('s')
        Dominio  = [ordered]@{ Dns = [string]$Dom.DNSRoot; NetBios = [string]$Dom.NetBIOSName; Base = [string]$Dom.DistinguishedName }
        Servidor = [ordered]@{ Host = $DcHost; Ip = $DcIp; Porta = $Porta; Transporte = $Transporte }
        Conta    = [ordered]@{ Dn = $ContaDn; Usuario = $ContaUsuario; Senha = $ContaSenha }
        Filtro   = $Filtro
        Atributo = 'sAMAccountName'
        Setores  = @($Setores | ForEach-Object { [ordered]@{ Nome = [string]$_.Name; Dn = [string]$_.DistinguishedName } })
        CaPem    = $CaPem
        Proxy    = $Proxy
    }
}

# ---------------------------- pre-requisitos ---------------------------
Write-Host ''
Write-Host "  pfSense-Squid-AD $VersaoProjeto - preparar o AD para o login do Squid" -ForegroundColor White
Write-Host '  -----------------------------------------------------------------'
Write-Host '  Responda com S ou N. O padrao aparece entre [colchetes]: ENTER aceita.'
Write-Host '  Nada e criado ou alterado no AD sem voce responder S.'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Rode este script num PowerShell aberto como Administrador.'
}
if ($PSVersionTable.PSVersion.Major -ne 5) {
    throw "Use o Windows PowerShell 5.1 (powershell.exe). Versao atual: $($PSVersionTable.PSVersion)."
}
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { throw 'Modulo ActiveDirectory nao encontrado. Rode no controlador de dominio ou instale o RSAT (Ferramentas do AD DS).' }

# ------------------------------ 1. dominio -----------------------------
Step 'Dominio'
$dom = Get-ADDomain
Ok "$($dom.DNSRoot)  (NetBIOS $($dom.NetBIOSName), base $($dom.DistinguishedName))"
if (-not (Read-SimNao "Usar o dominio $($dom.DNSRoot)?" $true)) { throw 'Cancelado: dominio nao confirmado.' }

# --------------------------- 2. controlador ----------------------------
Step 'Controlador de dominio'
Info 'O pfSense vai consultar este servidor a cada login. Ele precisa ser alcancavel'
Info 'pelo pfSense (normalmente pela LAN).'
$dcs = @(Get-ADDomainController -Filter * | Sort-Object HostName)
$esteDc = $dcs | Where-Object { $_.Name -ieq $env:COMPUTERNAME } | Select-Object -First 1
$padraoDc = if ($esteDc) { [array]::IndexOf($dcs, $esteDc) + 1 } else { 1 }
for ($i = 0; $i -lt $dcs.Count; $i++) {
    $marca = if ($dcs[$i] -eq $esteDc) { '  (este servidor)' } else { '' }
    Info ("{0}. {1}  -  {2}  (site {3}){4}" -f ($i + 1), $dcs[$i].HostName, $dcs[$i].IPv4Address, $dcs[$i].Site, $marca)
}
$n = Read-Valor 'Numero do controlador' "$padraoDc" { param($v) $v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le $dcs.Count } "digite um numero de 1 a $($dcs.Count)."
$dc = $dcs[[int]$n - 1]
$dcHost = [string]$dc.HostName
$dcIp   = [string]$dc.IPv4Address
Ok "controlador: $dcHost ($dcIp)"

# ------------------------------ 3. LDAPS -------------------------------
Step "LDAPS (porta 636) em $dcHost"
Info 'O pfSense vai mandar as senhas dos usuarios para o AD. Com LDAPS isso vai'
Info 'criptografado. LDAPS exige um certificado no controlador de dominio.'
$transporte = 'ssl'; $porta = 636; $caPem = ''
$ldaps = $null
try { $ldaps = Get-LdapsInfo $dcHost 636 } catch { Warn "LDAPS nao respondeu: $($_.Exception.Message)" }
if ($ldaps) {
    Ok "certificado: $($ldaps.Certificado.Subject)"
    Info "nomes no certificado: $($ldaps.Nomes)"
    Info "valido ate: $($ldaps.Certificado.NotAfter.ToString('dd/MM/yyyy'))   emitido por: $($ldaps.Raiz.Subject)"
    if (-not $ldaps.NomeConfere) { Warn "o certificado NAO tem o nome '$dcHost' - o pfSense vai recusar a conexao. Reemita o certificado do DC com esse nome." }
    if ($ldaps.Certificado.NotAfter -lt (Get-Date).AddDays(30)) { Warn 'o certificado vence em menos de 30 dias.' }
    $caPem = ConvertTo-Pem $ldaps.Raiz.RawData
    Ok 'a CA do certificado vai junto no arquivo, para o pfSense confiar nela.'
} else {
    Write-Host ''
    Warn 'Sem LDAPS, as senhas trafegam SEM criptografia entre o pfSense e o AD.'
    Info 'Para ter LDAPS, o controlador precisa de um certificado de servidor. O jeito'
    Info 'mais comum e instalar a funcao "Servicos de Certificados do AD" (AD CS) como'
    Info 'CA corporativa: os DCs recebem o certificado sozinhos. Veja docs/ad.md.'
    if (-not (Read-SimNao 'Continuar usando LDAP SEM criptografia (porta 389)?' $false)) {
        throw 'Cancelado: habilite o LDAPS no controlador e rode de novo (docs/ad.md).'
    }
    $transporte = 'standard'; $porta = 389
    Warn 'usando LDAP sem criptografia (389).'
}

# ------------------------------ 4. setores -----------------------------
Step 'Setores (grupos do AD)'
Info 'Cada setor e um grupo do AD. Nesta versao TODOS acessam tudo: os setores'
Info 'servem para o relatorio (quem acessa o que, por setor) e para restringir depois.'
Info 'Quem nao estiver em nenhum setor tambem acessa tudo, e aparece no relatorio'
Info 'como "SEM SETOR".'
$setores = New-Object System.Collections.Generic.List[object]
$todosGrupos = @(Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties Description, Members |
    Where-Object { $_.DistinguishedName -notlike '*,CN=Builtin,*' -and $_.SID.Value -match '-\d{4,}$' } | Sort-Object Name)
$candidatos = @($todosGrupos | Where-Object { $_.Name -match $PadraoSetor -or $_.Description -match 'setor|departamento' })
if ($candidatos.Count -gt 0) {
    Ok "$($candidatos.Count) grupo(s) que parecem setores:"
    foreach ($g in $candidatos) {
        if (Read-SimNao ("Usar '{0}' ({1} membro(s))?" -f $g.Name, @($g.Members).Count) $true) { $setores.Add($g) }
    }
} else {
    Info 'nenhum grupo com cara de setor encontrado (ex.: SETOR-FINANCEIRO).'
}
$outros = @($todosGrupos | Where-Object { $candidatos -notcontains $_ })
if ($outros.Count -gt 0 -and (Read-SimNao "Ver os outros $($outros.Count) grupo(s) de seguranca para escolher?" $false)) {
    foreach ($g in $outros) {
        if (Read-SimNao ("Usar '{0}' ({1} membro(s))?" -f $g.Name, @($g.Members).Count) $false) { $setores.Add($g) }
    }
}
if (Read-SimNao 'Criar grupos de setor novos?' $false) {
    $ouPadrao = "OU=Setores,$($dom.DistinguishedName)"
    $ou = Read-Valor 'Em qual OU criar os grupos' $ouPadrao
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        if (Read-SimNao "A OU '$ou' nao existe. Criar?" $true) {
            $partes = $ou -split ',', 2
            New-ADOrganizationalUnit -Name ($partes[0] -replace '^OU=', '') -Path $partes[1] -ProtectedFromAccidentalDeletion $true
            Ok "OU criada: $ou"
        } else { throw 'Cancelado: OU dos grupos nao existe.' }
    }
    $nomes = Read-Valor 'Nomes dos grupos, separados por virgula' 'SETOR-FINANCEIRO, SETOR-COMPRAS, SETOR-CONTABILIDADE' { param($v) $v -match '\S' }
    foreach ($nome in ($nomes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $existe = Get-ADGroup -Filter "Name -eq '$nome'" -ErrorAction SilentlyContinue
        if ($existe) { Ok "'$nome' ja existe - usando"; $setores.Add($existe); continue }
        if (Read-SimNao "Criar o grupo '$nome'?" $true) {
            $g = New-ADGroup -Name $nome -SamAccountName $nome -GroupCategory Security -GroupScope Global -Path $ou `
                -Description 'Setor - acesso a internet pelo proxy (pfSense-Squid-AD)' -PassThru
            Ok "grupo criado: $nome  (coloque os usuarios do setor nele)"
            $setores.Add($g)
        }
    }
}
$setores = @($setores | Sort-Object DistinguishedName -Unique)
if ($setores.Count -eq 0) { Warn 'nenhum setor escolhido: todos aparecem como "SEM SETOR" no relatorio (e acessam tudo).' }
else { Ok "setores: $(($setores | ForEach-Object { $_.Name }) -join ', ')" }

# ------------------------- 5. conta de servico -------------------------
Step 'Conta de servico (so leitura)'
Info 'O pfSense usa uma conta propria para procurar o usuario no AD antes de conferir'
Info 'a senha dele. Ela so LE o AD: nao e admin e nao precisa de permissao especial.'
$svcNome = Read-Valor 'Nome da conta de servico' 'svc-squid-ldap' { param($v) $v -match '^[A-Za-z0-9._-]{3,20}$' } 'use 3 a 20 caracteres: letras, numeros, . _ -'
$svc = Get-ADUser -Filter "SamAccountName -eq '$svcNome'" -ErrorAction SilentlyContinue
$svcSenha = $null
if ($svc) {
    Ok "a conta '$svcNome' ja existe: $($svc.DistinguishedName)"
    if (Read-SimNao 'Gerar uma senha nova para ela? (o pfSense recebe a nova pelo arquivo)' $true) {
        $svcSenha = New-SenhaForte
        Set-ADAccountPassword -Identity $svc -Reset -NewPassword (ConvertTo-SecureString $svcSenha -AsPlainText -Force)
        Ok 'senha nova gerada e aplicada.'
    } else {
        $sec = Read-Host "    Senha atual da conta '$svcNome'" -AsSecureString
        $svcSenha = (New-Object System.Net.NetworkCredential('', $sec)).Password
    }
} else {
    $cont = "CN=Users,$($dom.DistinguishedName)"
    Info "vai ser criada em $cont, com senha aleatoria de 32 caracteres que nao expira"
    Info 'e que o usuario nao pode trocar (senao o pfSense para de conseguir logar).'
    if (-not (Read-SimNao "Criar a conta '$svcNome'?" $true)) { throw 'Cancelado: a conta de servico e obrigatoria.' }
    $svcSenha = New-SenhaForte
    New-ADUser -Name $svcNome -SamAccountName $svcNome -UserPrincipalName "$svcNome@$($dom.DNSRoot)" -Path $cont `
        -AccountPassword (ConvertTo-SecureString $svcSenha -AsPlainText -Force) -Enabled $true `
        -PasswordNeverExpires $true -CannotChangePassword $true `
        -Description 'Conta SO LEITURA do Squid (pfSense) para consultar o AD. Nao usar para login.'
    $svc = Get-ADUser -Identity $svcNome
    Ok "conta criada: $($svc.DistinguishedName)"
}

# ------------------------------ 6. teste --------------------------------
Step "Testando o LDAP como o pfSense vai fazer ($transporte, porta $porta)"
$filtro = '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
try {
    $con = Test-LdapBind $dcHost $porta ($transporte -eq 'ssl') $svc.DistinguishedName $svcSenha
    Ok "login da conta de servico OK ($dcHost`:$porta)"
    $ativos = Search-Ldap $con $dom.DistinguishedName '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName')
    Ok "$($ativos.Count) usuario(s) ativo(s) poderao logar no proxy"
    foreach ($s in $setores) {
        $q = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=' + (ConvertTo-LdapFiltro $s.DistinguishedName) + '))'
        Info ("setor {0}: {1} usuario(s) (contando grupos dentro de grupos)" -f $s.Name, (Search-Ldap $con $dom.DistinguishedName $q @('sAMAccountName')).Count)
    }
} catch {
    throw "o teste de LDAP falhou: $($_.Exception.Message). Confira o LDAPS/porta e rode de novo."
}
if (-not $Yes -and (Read-SimNao 'Testar o login com um usuario real do AD?' $true)) {
    $u = Read-Valor 'Usuario (sAMAccountName, ex.: joao.silva)' '' { param($v) $v -match '^[^\s]+$' }
    $sec = Read-Host "    Senha de '$u'" -AsSecureString
    $senhaU = (New-Object System.Net.NetworkCredential('', $sec)).Password
    $achou = Search-Ldap $con $dom.DistinguishedName ($filtro.Replace('%s', (ConvertTo-LdapFiltro $u))) @('distinguishedName')
    if ($achou.Count -ne 1) {
        Warn "o usuario '$u' nao foi encontrado (ou esta desativado) - ele NAO conseguiria logar no proxy."
    } else {
        try {
            $cu = Test-LdapBind $dcHost $porta ($transporte -eq 'ssl') $achou[0].DistinguishedName $senhaU
            $cu.Dispose()
            $dele = @($setores | Where-Object {
                $q = '(&(sAMAccountName=' + (ConvertTo-LdapFiltro $u) + ')(memberOf:1.2.840.113556.1.4.1941:=' + (ConvertTo-LdapFiltro $_.DistinguishedName) + '))'
                (Search-Ldap $con $dom.DistinguishedName $q @('sAMAccountName')).Count -gt 0 } | ForEach-Object { $_.Name })
            Ok "login de '$u' OK - setor(es): $(if ($dele) { $dele -join ', ' } else { 'SEM SETOR (acessa tudo)' })"
        } catch { Warn "senha recusada para '$u': $($_.Exception.Message)" }
    }
    $senhaU = $null
}
$con.Dispose()

# ------------------------------ 7. GPO ----------------------------------
Step 'GPO do proxy (opcional)'
Info 'O proxy com login NAO funciona em modo transparente: cada PC precisa apontar'
Info 'para o pfSense. A GPO faz isso sozinha. Ela e criada SEM vinculo: voce escolhe'
Info 'em quais OUs ligar (setor por setor) - aqui ou depois, no Gerenciamento de GPO.'
$proxy = $null
if (Read-SimNao 'Criar a GPO que configura o proxy nos PCs?' $false) {
    Import-Module GroupPolicy -ErrorAction Stop
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $ipProxy = Read-Valor 'IP do pfSense na LAN (endereco do proxy)' "$gw" { param($v) $v -match '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$' } 'digite um IPv4 valido (ex.: 172.16.10.1).'
    $portaProxy = Read-Valor 'Porta do proxy do Squid' '3128' { param($v) $v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le 65535 } 'porta de 1 a 65535.'
    $excecoes = Read-Valor 'Excecoes (nao passam pelo proxy)' "<local>;*.$($dom.DNSRoot);10.*;172.16.*;192.168.*"
    $gpoNome = Read-Valor 'Nome da GPO' 'Proxy Squid - pfSense'
    $gpo = Get-GPO -Name $gpoNome -ErrorAction SilentlyContinue
    if ($gpo) { Ok "a GPO '$gpoNome' ja existe - atualizando os valores" }
    else { $gpo = New-GPO -Name $gpoNome -Comment 'Proxy do Squid no pfSense (pfSense-Squid-AD)'; Ok "GPO criada: $gpoNome" }
    # Preferencias de registro (configuracao de USUARIO): valem para Edge,
    # Chrome e tudo que usa o proxy do Windows.
    $chave = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    foreach ($v in 'ProxyEnable', 'ProxyServer', 'ProxyOverride') {
        # rodando de novo: remove o item antigo antes, para nao duplicar
        Remove-GPPrefRegistryValue -Name $gpoNome -Context User -Key $chave -ValueName $v -ErrorAction SilentlyContinue | Out-Null
    }
    Set-GPPrefRegistryValue -Name $gpoNome -Context User -Action Update -Key $chave -ValueName 'ProxyEnable'   -Type DWord  -Value 1 | Out-Null
    Set-GPPrefRegistryValue -Name $gpoNome -Context User -Action Update -Key $chave -ValueName 'ProxyServer'   -Type String -Value "${ipProxy}:$portaProxy" | Out-Null
    Set-GPPrefRegistryValue -Name $gpoNome -Context User -Action Update -Key $chave -ValueName 'ProxyOverride' -Type String -Value $excecoes | Out-Null
    Ok "proxy ${ipProxy}:$portaProxy, excecoes: $excecoes"
    $proxy = [ordered]@{ Endereco = $ipProxy; Porta = [int]$portaProxy; Gpo = $gpoNome }
    if (Read-SimNao 'Vincular a GPO a alguma OU agora?' $false) {
        $ous = @(Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName)
        for ($i = 0; $i -lt $ous.Count; $i++) { Info ("{0}. {1}" -f ($i + 1), $ous[$i].DistinguishedName) }
        $sel = Read-Valor 'Numeros das OUs, separados por virgula' '' { param($v) @($v -split ',' | Where-Object { $_.Trim() -notmatch '^\d+$' -or [int]$_ -lt 1 -or [int]$_ -gt $ous.Count }).Count -eq 0 } 'use numeros da lista, ex.: 2,5'
        foreach ($x in ($sel -split ',' | ForEach-Object { [int]$_.Trim() })) {
            $alvo = $ous[$x - 1].DistinguishedName
            if (Read-SimNao "Vincular a '$alvo'?" $true) {
                New-GPLink -Name $gpoNome -Target $alvo -ErrorAction SilentlyContinue | Out-Null
                Ok "vinculada: $alvo (vale no proximo logon / gpupdate)"
            }
        }
    } else { Info 'sem vinculo: ligue depois em Gerenciamento de Politica de Grupo.' }
}

# --------------------------- 8. arquivo ---------------------------------
Step 'Arquivo para o pfSense'
if (-not $OutFile) { $OutFile = Join-Path $Aqui ("squid-ad-{0}.json" -f $dom.NetBIOSName) }
Info 'O arquivo leva tudo o que o script do pfSense precisa: servidor, base, conta de'
Info 'servico, setores e a CA do LDAPS.'
$incluiSenha = Read-SimNao 'Incluir a senha da conta de servico no arquivo? (senao o pfSense pergunta)' $true
$dados = New-PacoteSquid -Dom $dom -DcHost $dcHost -DcIp $dcIp -Porta $porta -Transporte $transporte `
    -ContaDn $svc.DistinguishedName -ContaUsuario $svcNome -ContaSenha $(if ($incluiSenha) { $svcSenha } else { '' }) `
    -Filtro $filtro -Setores $setores -CaPem $caPem -Proxy $proxy
($dados | ConvertTo-Json -Depth 5) | Set-Content -Path $OutFile -Encoding ASCII
# So Administradores e SYSTEM leem o arquivo (ele pode ter a senha da conta).
& icacls.exe $OutFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' /Q | Out-Null
Ok "gravado: $OutFile"
if ($incluiSenha) { Warn 'o arquivo tem a senha da conta de servico: apague-o depois de usar no pfSense.' }
$svcSenha = $null

Write-Host ''
Write-Host 'Pronto no AD. Proximo passo, no pfSense (docs/pfsense.md):' -ForegroundColor Cyan
Write-Host '    1. Diagnostics > Command Prompt > Upload File: envie o squid-ad.php e o .json'
Write-Host '    2. Por SSH (recomendado, interativo):'
Write-Host "         php /tmp/squid-ad.php aplicar /tmp/$(Split-Path $OutFile -Leaf)"
Write-Host '       ou na tela Command Prompt (sem perguntas): primeiro "simular", depois "aplicar ... --sim"'
