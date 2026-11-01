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
      4. SETORES: cada OU de departamento ganha um grupo SO de internet
         (NET_<DEPARTAMENTO>), com os usuarios da OU (espelhado)
      5. cria (ou reaproveita) a conta de servico SO LEITURA usada pelo pfSense
      6. testa o LDAP com essa conta - e, se quiser, com um usuario real
      7. (opcional) cria a GPO que configura o proxy nos PCs
      8. (opcional) instala no pfSense uma chave SSH restrita aos comandos "ssl-*"
         (fase 2: inspecao SSL), para este servidor poder rodar la sem ter a senha admin
      9. gera o arquivo squid-ad-<DOMINIO>.json para o script do pfSense
     10. (opcional) tarefa agendada que mantem os grupos em dia a cada 15 min

    No fim mostra a senha da conta de servico (quando ela foi criada/trocada)
    para o administrador guardar no cofre de senhas.

.PARAMETER Sincronizar
    Modo sem perguntas, usado pela tarefa agendada: para cada OU de
    departamento, cria o grupo de internet que faltar e espelha os membros
    (usuario que mudou de OU sai do grupo antigo e entra no novo). Excecao:
    usuario com [proxy-manual] na Descricao nunca e removido.
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
    [switch]$Yes,
    [switch]$Sincronizar
)

$ErrorActionPreference = 'Stop'
$VersaoProjeto = '1.3.0'
$Aqui = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Padroes que costumam indicar grupo de SETOR (ex.: SETOR-FINANCEIRO, DEP_COMPRAS)
$PadraoSetor = '^(SETOR|SET|DEP|DEPTO|DEPARTAMENTO|GRP|GG|GS)[-_ .]'

# ------------------------------ helpers -------------------------------
$script:Passo = 0
$script:TotalPassos = 10
# Cabecalho de passo: numerado e separado por linhas, para a pessoa saber onde esta.
function Step([string]$m) {
    $script:Passo++
    $linha = '  ' + ('-' * 72)
    Write-Host ''
    Write-Host ''
    Write-Host $linha -ForegroundColor DarkCyan
    Write-Host ("   PASSO {0} de {1}  -  {2}" -f $script:Passo, $script:TotalPassos, $m) -ForegroundColor Cyan
    Write-Host $linha -ForegroundColor DarkCyan
}

# Explicacao padrao de cada passo: o que e, por que, o que acontece. Cada parte
# aceita varias linhas. Fica entre linhas em branco, separada das perguntas.
function Explicar([string[]]$OQue, [string[]]$PorQue, [string[]]$Acontece) {
    Write-Host ''
    foreach ($par in @(@('O QUE E:', $OQue), @('POR QUE:', $PorQue), @('O QUE ACONTECE:', $Acontece))) {
        $texto = @($par[1] | Where-Object { $_ })
        if (-not $texto.Count) { continue }
        Write-Host ("   {0,-17}" -f $par[0]) -NoNewline -ForegroundColor White
        Write-Host $texto[0] -ForegroundColor Gray
        foreach ($l in @($texto | Select-Object -Skip 1)) { Write-Host ("   {0,-17}{1}" -f '', $l) -ForegroundColor Gray }
    }
    Write-Host ''
}
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
        # "S" / "sim" numa pergunta de valor = "aceito o padrao" (todo mundo faz isso)
        if ($Padrao -and $r -match '^(s|sim|y|yes)$' -and -not (& $Valido $r)) { $r = $Padrao }
        if ($r -and (& $Valido $r)) { return $r }
        Warn $Ajuda
    }
}

function New-SenhaForte([int]$Tamanho = 32) {
    # Sem aspas, barra invertida, espaco nem $: a senha vai parar no squid.conf
    # e em linhas de comando do pfSense.
    # So letras, numeros e - _ . : seguro em qualquer arquivo de configuracao
    # (o squidGuard 1.4, por exemplo, quebrava com ! e @). 32 caracteres assim
    # sao mais que suficientes, e cobrem 3 das 4 classes que o AD exige.
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.'
    $bytes = New-Object byte[] $Tamanho
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $s = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    # garante maiuscula, minuscula, numero e simbolo (politica de senha do AD)
    return 'Aa1-' + $s.Substring(4)
}

# Chave SSH restrita (fase 2: inspecao SSL) no pfSense, so para os comandos "ssl-*" - nunca
# da senha admin completa para a automacao, so uma chave que o pfSense aceita rodar com elas.
# A senha admin do pfSense e usada SO aqui, na hora, para instalar a chave; nunca e salva.
function Install-SquidSslAcessoRemoto {
    $dirChave = Join-Path $env:ProgramData 'pfSense-Squid-AD'
    if (-not (Test-Path $dirChave)) { New-Item -ItemType Directory -Force $dirChave | Out-Null }
    & icacls.exe $dirChave /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q | Out-Null

    $ipFw = Read-Valor 'IP (ou nome) do pfSense' '' { param($v) -not [string]::IsNullOrWhiteSpace($v) } 'informe o IP ou nome do pfSense.'
    $portaFw = Read-Valor 'Porta do SSH do pfSense' '22' { param($v) $v -match '^\d+$' } 'porta numerica.'
    $userFw = Read-Valor 'Usuario do pfSense que vai receber a chave restrita' 'admin'

    $arqChave = Join-Path $dirChave 'ssl-remoto'
    if (Test-Path $arqChave) {
        Warn "ja existe uma chave em $arqChave; reaproveitando (apague o arquivo para gerar uma nova)."
    } else {
        & ssh-keygen.exe -t ed25519 -f $arqChave -N '""' -C 'squid-ad-ssl@ad' -q
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $arqChave)) { throw 'ssh-keygen falhou (o OpenSSH Client do Windows esta instalado?).' }
        Ok "chave gerada: $arqChave (privada) / $arqChave.pub (publica)"
    }

    if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        Warn 'modulo Posh-SSH nao encontrado - nao consigo instalar a chave automaticamente agora.'
        Info 'instale com: Install-Module Posh-SSH -Scope CurrentUser'
        Info 'ou faca manualmente, por SSH admin no pfSense (ver docs/pfsense.md):'
        Info "  1. envie $arqChave.pub para o pfSense"
        Info "  2. php /root/squid-ad.php ssl-chave-remota $userFw <arquivo.pub>"
        return [ordered]@{ ChavePrivada = $arqChave; Instalada = $false }
    }
    Import-Module Posh-SSH -ErrorAction Stop

    $senhaAdmin = Read-Host "    Senha ADMIN do pfSense (usuario '$userFw', so usada agora, nao e salva)" -AsSecureString
    $cred = New-Object System.Management.Automation.PSCredential($userFw, $senhaAdmin)
    $ssh = $null; $sftp = $null
    try {
        $ssh = New-SSHSession -ComputerName $ipFw -Port $portaFw -Credential $cred -AcceptKey -ErrorAction Stop
        $sftp = New-SFTPSession -ComputerName $ipFw -Port $portaFw -Credential $cred -AcceptKey -ErrorAction Stop
        Set-SFTPFile -SessionId $sftp.SessionId -LocalFile "$arqChave.pub" -RemotePath '/tmp/ssl-remoto.pub' -Overwrite | Out-Null
        $scriptLocal = Join-Path $Aqui 'pfsense\squid-ad.php'
        if (Test-Path $scriptLocal) {
            Set-SFTPFile -SessionId $sftp.SessionId -LocalFile $scriptLocal -RemotePath '/tmp/squid-ad.php' -Overwrite | Out-Null
        }
        $cmd = "cp /tmp/squid-ad.php /root/squid-ad.php 2>/dev/null; /usr/local/bin/php /root/squid-ad.php ssl-chave-remota $userFw /tmp/ssl-remoto.pub --sim"
        $saida = Invoke-SSHCommand -SSHSession $ssh -Command $cmd
        foreach ($l in @($saida.Output)) { Info $l }
        if ($saida.ExitStatus -ne 0) { throw "ssl-chave-remota terminou com erro (codigo $($saida.ExitStatus)); confira a mensagem acima." }
        Ok 'chave instalada no pfSense (acesso restrito aos comandos ssl-*).'
    } finally {
        if ($sftp) { Remove-SFTPSession -SessionId $sftp.SessionId -ErrorAction SilentlyContinue | Out-Null }
        if ($ssh)  { Remove-SSHSession  -SessionId $ssh.SessionId  -ErrorAction SilentlyContinue | Out-Null }
        $senhaAdmin = $null; $cred = $null
    }
    Warn 'restrinja agora o SSH desse usuario a rede interna (System > Advanced > Admin Access) - nunca deixe aberto na WAN.'
    return [ordered]@{ ChavePrivada = $arqChave; Instalada = $true; FirewallHost = $ipFw; FirewallPorta = [int]$portaFw; FirewallUsuario = $userFw }
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
    if ($san) {
        # So nomes DNS e IPs. O SAN de DC tambem traz o GUID do objeto
        # ("Guia de Objeto DS=04 10 ...") - isso nao e nome e fica de fora.
        $nomes = @(($san.Format($false) -split ',\s*') | ForEach-Object { ($_ -split '[=:]', 2)[-1].Trim() } |
            Where-Object { $_ -match '^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$' })
    }
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
                         [string]$Filtro, $Setores, [string]$CaPem, $Proxy, $Sync = $null) {
    return [ordered]@{
        Projeto  = 'pfSense-Squid-AD'
        Versao   = $VersaoProjeto
        GeradoEm = (Get-Date).ToString('s')
        Dominio  = [ordered]@{ Dns = [string]$Dom.DNSRoot; NetBios = [string]$Dom.NetBIOSName; Base = [string]$Dom.DistinguishedName }
        Servidor = [ordered]@{ Host = $DcHost; Ip = $DcIp; Porta = $Porta; Transporte = $Transporte }
        Conta    = [ordered]@{ Dn = $ContaDn; Usuario = $ContaUsuario; Senha = $ContaSenha }
        Filtro   = $Filtro
        Atributo = 'sAMAccountName'
        Setores  = @($Setores | ForEach-Object { [ordered]@{ Nome = [string]$_.Name; Dn = [string]$_.DistinguishedName; Guid = (ConvertTo-GuidHex $_.ObjectGUID)
                                                       Membros = @(Get-MembrosAtivos $_) } })
        CaPem    = $CaPem
        Proxy    = $Proxy
        # BaseOu/Prefixo: o pfSense usa para buscar os grupos de setor sozinho (cron)
        Sync     = $Sync
    }
}

# IPv4 que o pfSense pode usar: tira APIPA (169.254.x.x = placa sem cabo/sem
# DHCP), loopback e repetidos.
function Select-IPv4Util([string[]]$Ips) {
    return @($Ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' -and $_ -notlike '127.*' } | Select-Object -Unique)
}

# Ordena os IPs deixando primeiro os "preferidos" (os da placa com gateway, que
# e a que fala com o pfSense). Sem preferidos, mantem a ordem.
function Sort-IpsPreferidos([string[]]$Ips, [string[]]$Preferidos) {
    $Ips = @($Ips); $Preferidos = @($Preferidos)
    return @(@($Ips | Where-Object { $Preferidos -contains $_ }) + @($Ips | Where-Object { $Preferidos -notcontains $_ }))
}

# Registros A de um nome NO SERVIDOR DNS (vazio se nao resolver). -DnsOnly e
# -NoHostsFile: consulta o DNS de verdade, sem o arquivo hosts e sem a resolucao
# local do Windows (que no proprio DC devolve os IPs de TODAS as placas).
function Get-RegistrosA([string]$Nome) {
    try { return @(Resolve-DnsName -Name $Nome -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) }
    catch { return @() }
}

# Nome do setor a partir do nome da OU: sem acento, maiusculo, so A-Z 0-9 _.
# (ex.: a OU "Expedicao Instrumental", com acentos -> EXPEDICAO_INSTRUMENTAL)
function ConvertTo-NomeSetor([string]$Nome) {
    $d = $Nome.Normalize([Text.NormalizationForm]::FormD)
    $sem = -join ($d.ToCharArray() | Where-Object { [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark })
    return (($sem.ToUpperInvariant() -replace '[^A-Z0-9]+', '_').Trim('_'))
}

# sAMAccountName dos membros ATIVOS do grupo (inclusive por grupo dentro de grupo).
# Vao no arquivo para o pfSense montar a regra do setor no SquidGuard.
function Get-MembrosAtivos($Grupo) {
    return @(Get-ADGroupMember -Identity $Grupo -Recursive | Where-Object { $_.objectClass -eq 'user' } |
        ForEach-Object { Get-ADUser -Identity $_.distinguishedName } | Where-Object { $_.Enabled } |
        ForEach-Object { [string]$_.SamAccountName } | Sort-Object -Unique)
}

# Junta as excecoes do proxy (padrao + extras), sem repetir e sem itens vazios.
function Join-Excecoes([string]$Padrao, [string]$Extras) {
    $itens = New-Object System.Collections.Generic.List[string]
    foreach ($x in (("$Padrao;$Extras") -split ';')) {
        $x = $x.Trim()
        if ($x -and -not ($itens | Where-Object { $_ -ieq $x })) { $itens.Add($x) }
    }
    return ($itens -join ';')
}

# GUID no MESMO formato que o pfSense le pelo LDAP (bytes crus do objectGUID em
# hexa). Guid.ToString() usa outra ordem de bytes e quebraria a sincronizacao.
function ConvertTo-GuidHex([guid]$Guid) {
    return (([BitConverter]::ToString($Guid.ToByteArray())) -replace '-', '').ToLowerInvariant()
}

# Quem entra e quem sai do grupo para ele espelhar a OU. $Desejados = usuarios
# ativos da OU; $Atuais = usuarios que sao membros diretos hoje. Usuario com
# [proxy-manual] na Descricao e excecao: nunca e removido.
function Get-MudancasMembros($Desejados, $Atuais) {
    $des = @{}; foreach ($u in @($Desejados)) { if ($u) { $des[[string]$u.DistinguishedName] = $true } }
    $atu = @{}; foreach ($u in @($Atuais))    { if ($u) { $atu[[string]$u.DistinguishedName] = $true } }
    $add = @(@($Desejados) | Where-Object { $_ -and -not $atu.ContainsKey([string]$_.DistinguishedName) })
    $rem = @(@($Atuais) | Where-Object { $_ -and -not $des.ContainsKey([string]$_.DistinguishedName) -and "$($_.Description)" -notmatch '\[proxy-manual\]' })
    return [pscustomobject]@{ Adicionar = $add; Remover = $rem }
}

# Para cada OU de departamento dentro de $BaseOu: garante o grupo
# <Prefixo><NOME DA OU> (dentro da propria OU) e espelha os membros.
# $Interativo: pergunta antes de criar/alterar. Sem isso (tarefa agendada),
# aplica direto e devolve o que fez em .Log.
# $Ignorar: DNs de OUs que o administrador recusou (ex.: Computadores). Ficam
# gravadas na configuracao e a tarefa agendada nunca cria grupo para elas.
function Sync-SetoresAD([string]$BaseOu, [string]$Prefixo, [bool]$Interativo, [string[]]$Ignorar = @()) {
    $log = New-Object System.Collections.Generic.List[string]
    $grupos = New-Object System.Collections.Generic.List[object]
    $ignoradas = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Ignorar)) { if ($x) { $ignoradas.Add($x) } }
    $ous = @(Get-ADOrganizationalUnit -SearchBase $BaseOu -SearchScope OneLevel -Filter * | Sort-Object Name)
    foreach ($ou in $ous) {
        if ($ignoradas -contains [string]$ou.DistinguishedName) { continue }
        if ($Interativo) { Write-Host '' }
        $nome = $Prefixo + (ConvertTo-NomeSetor $ou.Name)
        $usuarios = @(Get-ADUser -SearchBase $ou.DistinguishedName -SearchScope Subtree -Filter 'Enabled -eq $true' -Properties Description)
        $g = Get-ADGroup -Filter "Name -eq '$nome'" -ErrorAction SilentlyContinue
        if (-not $g) {
            if ($Interativo -and -not (Read-SimNao ("Criar o grupo '{0}' na OU '{1}' ({2} usuario(s) nela)?" -f $nome, $ou.Name, $usuarios.Count) $true)) {
                $ignoradas.Add([string]$ou.DistinguishedName)   # lembrada: a sincronizacao nao cria depois
                Info "    OU '$($ou.Name)' fica fora dos setores (a sincronizacao automatica respeita isso)"
                continue
            }
            $g = New-ADGroup -Name $nome -SamAccountName $nome -GroupCategory Security -GroupScope Global -Path $ou.DistinguishedName `
                -Description ("Internet (proxy) - setor {0} - pfSense-Squid-AD" -f $ou.Name) -PassThru
            $log.Add("grupo criado: $nome (OU $($ou.Name))")
            if ($Interativo) { Ok "grupo criado: $nome" }
        } elseif ($Interativo) { Ok "grupo '$nome' ja existe - usando" }
        $atuais = @(Get-ADGroupMember -Identity $g | Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object { Get-ADUser -Identity $_.distinguishedName -Properties Description })
        $m = Get-MudancasMembros $usuarios $atuais
        if ($m.Adicionar.Count -or $m.Remover.Count) {
            $resumo = "{0}: +{1} / -{2}" -f $nome, $m.Adicionar.Count, $m.Remover.Count
            $pergunta = "Espelhar a OU no grupo '$nome'? (entra(m) $($m.Adicionar.Count), sai(em) $($m.Remover.Count))"
            if (-not $Interativo -or (Read-SimNao $pergunta $true)) {
                if ($m.Adicionar.Count) { Add-ADGroupMember -Identity $g -Members $m.Adicionar }
                if ($m.Remover.Count)   { Remove-ADGroupMember -Identity $g -Members $m.Remover -Confirm:$false }
                $sairam = if ($m.Remover.Count) { ' (sairam: ' + (($m.Remover | ForEach-Object { $_.SamAccountName }) -join ', ') + ')' } else { '' }
                $log.Add("membros $resumo$sairam")
                if ($Interativo) { Ok "membros atualizados ($resumo)" }
            }
        }
        $grupos.Add((Get-ADGroup -Identity $g -Properties ObjectGUID))
    }
    # .ToArray(): @() de List<T> dentro de [pscustomobject]@{} dispara 'Argument types do not match'
    return [pscustomobject]@{ Grupos = $grupos.ToArray(); Log = $log.ToArray(); Ignoradas = $ignoradas.ToArray() }
}

if ($Sincronizar) {
    # Tarefa agendada (SYSTEM, sem perguntas). Le a configuracao gravada pelo
    # modo interativo e registra o resultado em log + Log de Aplicativo.
    $cfgSync = Join-Path $Aqui 'sincronizacao.json'
    $logSync = Join-Path $Aqui 'sincronizacao.log'
    $fonte = 'pfSense-Squid-AD'
    function Write-LogSync([string]$m) {
        if ((Test-Path $logSync) -and (Get-Item $logSync).Length -gt 2MB) { Move-Item $logSync "$logSync.old" -Force }
        Add-Content -Path $logSync -Value ("{0}  {1}" -f (Get-Date).ToString('s'), $m)
    }
    try {
        if (-not [Diagnostics.EventLog]::SourceExists($fonte)) { New-EventLog -LogName Application -Source $fonte }
        Import-Module ActiveDirectory -ErrorAction Stop
        $c = Get-Content $cfgSync -Raw | ConvertFrom-Json
        $r = Sync-SetoresAD $c.BaseOu $c.Prefixo $false @($c.Ignorar)
        if ($r.Log.Count) {
            foreach ($l in $r.Log) { Write-LogSync $l }
            Write-EventLog -LogName Application -Source $fonte -EventId 2000 -EntryType Information -Message ("Setores sincronizados:`n" + ($r.Log -join "`n"))
        }
        exit 0
    } catch {
        Write-LogSync "ERRO: $($_.Exception.Message)"
        try { Write-EventLog -LogName Application -Source $fonte -EventId 2001 -EntryType Error -Message "Sincronizacao dos setores FALHOU: $($_.Exception.Message)" } catch {}
        exit 1
    }
}

Write-Host ''
Write-Host ''
Write-Host '  ========================================================================' -ForegroundColor DarkCyan
Write-Host "   pfSense-Squid-AD $VersaoProjeto  -  preparar o AD para o login do proxy" -ForegroundColor White
Write-Host '  ========================================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '   Sao 9 passos. Em cada um aparece o que vai ser feito e por que.'
Write-Host '   Responda com S (sim) ou N (nao). O padrao aparece entre [colchetes]:'
Write-Host '   apertar ENTER aceita o padrao.'
Write-Host ''
Write-Host '   Nada e criado ou alterado no AD sem voce responder S.' -ForegroundColor Yellow

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
Step 'Dominio do Active Directory'
Explicar -OQue 'O dominio do AD onde estao os usuarios da empresa.' `
         -PorQue 'E nele que o pfSense vai conferir o usuario e a senha de quem navega.' `
         -Acontece 'So leitura. Nada e alterado.'
$dom = Get-ADDomain
Ok "$($dom.DNSRoot)  (NetBIOS $($dom.NetBIOSName), base $($dom.DistinguishedName))"
if (-not (Read-SimNao "Usar o dominio $($dom.DNSRoot)?" $true)) { throw 'Cancelado: dominio nao confirmado.' }

# --------------------------- 2. controlador ----------------------------
Step 'Controlador de dominio'
Explicar -OQue 'O servidor do AD que o pfSense vai consultar a cada login.' `
         -PorQue @('Ele precisa ser alcancavel pelo pfSense, normalmente pela LAN.',
                   '("site" na lista e o Site do AD - local fisico em Sites e Servicos -',
                   ' nao um site da internet.)') `
         -Acontece 'So leitura. O nome e o IP escolhidos vao no arquivo para o pfSense.'
$dcs = @(Get-ADDomainController -Filter * | Sort-Object HostName)
$esteDc = $dcs | Where-Object { $_.Name -ieq $env:COMPUTERNAME } | Select-Object -First 1
$padraoDc = if ($esteDc) { [array]::IndexOf($dcs, $esteDc) + 1 } else { 1 }
$ipsDc = @{}
# IPs das placas deste servidor que tem gateway (a LAN): sao os preferidos.
$ipsGateway = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway } |
    ForEach-Object { $_.IPv4Address.IPAddress })
for ($i = 0; $i -lt $dcs.Count; $i++) {
    $d = $dcs[$i]
    # Todos os IPs do DC: o que o AD informa + os registros A no DNS (+ as placas
    # deste servidor, se for ele). 169.254.x.x (APIPA) nunca serve para o pfSense.
    $todos = @([string]$d.IPv4Address) + @(Get-RegistrosA $d.HostName)
    if ($d -eq $esteDc) {
        $todos += @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress })
    }
    $ipsDc[$d.HostName] = @(Sort-IpsPreferidos (Select-IPv4Util $todos) $ipsGateway)
    $dnsBruto = @(Get-RegistrosA $d.HostName)
    $noDns = @(Select-IPv4Util $dnsBruto)
    # So reclama do 169.254 se ele estiver REGISTRADO no DNS. Em placa local
    # (ex.: VPN ainda sem IP) ele so e ignorado.
    $apipa = @($dnsBruto | Where-Object { $_ -like '169.254.*' } | Select-Object -Unique)
    $marca = if ($d -eq $esteDc) { '  (este servidor)' } else { '' }
    $mostra = if ($ipsDc[$d.HostName].Count) { $ipsDc[$d.HostName] -join ', ' } else { 'sem IP utilizavel' }
    Info ("{0}. {1}  -  {2}  (site do AD: {3}){4}" -f ($i + 1), $d.HostName, $mostra, $d.Site, $marca)
    if ($apipa) {
        Warn ("{0} tem o IP {1} (169.254 = placa de rede sem cabo ou sem IP) registrado no DNS do AD." -f $d.Name, ($apipa -join ', '))
        Info '    PCs e o pfSense podem tentar esse IP e falhar. Corrija no DC: desative a placa sem uso, ou'
        Info '    nas propriedades dela > IPv4 > Avancado > DNS, desmarque "Registrar os enderecos desta conexao no DNS".'
        Info '    Depois: ipconfig /registerdns e apague o registro 169.254 no Gerenciador de DNS.'
    }
    if ($noDns.Count -gt 1) {
        Warn ("{0} tem {1} IPs no DNS do AD ({2}). Normalmente e placa de VPN registrando o IP dela" -f $d.Name, $noDns.Count, ($noDns -join ', '))
        Info '    (ex.: Pritunl/OpenVPN). Um DC deve registrar so o IP da LAN: desmarque o registro no DNS nas outras placas.'
    }
}
$escolha = Read-Valor 'Controlador (numero ou nome)' "$padraoDc" {
    param($v) ($v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le $dcs.Count) -or
              @($dcs | Where-Object { $_.Name -ieq $v -or $_.HostName -ieq $v }).Count -eq 1
} "digite o numero (1 a $($dcs.Count)) ou o nome do controlador."
$dc = if ($escolha -match '^\d+$') { $dcs[[int]$escolha - 1] } else { $dcs | Where-Object { $_.Name -ieq $escolha -or $_.HostName -ieq $escolha } | Select-Object -First 1 }
$dcHost = [string]$dc.HostName
$ips = @($ipsDc[$dcHost])
Write-Host ''
Info 'Agora o IP do controlador que o pfSense vai usar (o da LAN, ex.: 172.16.10.x):'
$dcIp = Read-Valor 'IP do controlador' $(if ($ips.Count) { $ips[0] } else { '' }) {
    param($v) $v -match '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$' -and $v -notlike '169.254.*' -and $v -notlike '127.*'
} 'digite o IPv4 da LAN do controlador (nao vale 169.254.x.x nem 127.x.x.x).'
Ok "controlador: $dcHost ($dcIp)"

# ------------------------------ 3. LDAPS -------------------------------
Step "LDAPS - conexao criptografada com $dcHost"
Explicar -OQue 'A conexao criptografada (porta 636) entre o pfSense e o AD.' `
         -PorQue @('O pfSense envia a senha de cada usuario para o AD conferir.',
                   'Ela nao pode trafegar aberta na rede.') `
         -Acontece @('So leitura. Confere o certificado do controlador e copia a CA',
                     '(quem emitiu o certificado) para o pfSense confiar nela.')
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
Step 'Setores (grupos de internet)'
Explicar -OQue @('Cada OU de departamento vira um SETOR, com um grupo so de internet',
                 '(ex.: OU Financeiro -> grupo NET_FINANCEIRO, criado dentro da OU).') `
         -PorQue @('Fica separado dos grupos de pastas (GR_/GRE_): dar acesso a uma pasta',
                   'nao muda a internet de ninguem.') `
         -Acontece @('Para cada OU voce responde S ou N. O grupo recebe os usuarios que',
                     'estao na OU. Nesta versao TODOS acessam tudo: no pfSense cada setor',
                     'vira uma regra no SquidGuard que libera tudo, pronta para restringir.',
                     'Quem estiver fora dos departamentos aparece como "SEM SETOR".')
$setores = New-Object System.Collections.Generic.List[object]
$sync = $null
$topo = @(Get-ADOrganizationalUnit -SearchBase $dom.DistinguishedName -SearchScope OneLevel -Filter * |
    Where-Object { $_.Name -ne 'Domain Controllers' } | Sort-Object Name)
if ($topo.Count) {
    $maisFilhas = 0; $padraoOu = 1
    for ($i = 0; $i -lt $topo.Count; $i++) {
        $f = @(Get-ADOrganizationalUnit -SearchBase $topo[$i].DistinguishedName -SearchScope OneLevel -Filter *).Count
        if ($f -gt $maisFilhas) { $maisFilhas = $f; $padraoOu = $i + 1 }
        Info ("{0}. {1}  ({2} OU(s) dentro)" -f ($i + 1), $topo[$i].Name, $f)
    }
    $nOu = Read-Valor 'OU da empresa (onde ficam as OUs de departamento)' "$padraoOu" { param($v) $v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le $topo.Count } "digite um numero de 1 a $($topo.Count)."
    $empresa = $topo[[int]$nOu - 1]
    $deps = @(Get-ADOrganizationalUnit -SearchBase $empresa.DistinguishedName -SearchScope OneLevel -Filter * | Sort-Object Name)
    Write-Host ''
    Info ("Departamentos encontrados em '{0}':" -f $empresa.Name)
    foreach ($dp in $deps) { Info "    - $($dp.Name)" }
    Write-Host ''
    if ($deps.Count -and (Read-SimNao "Cada OU dentro de '$($empresa.Name)' e um departamento (setor)?" $true)) {
        $prefixo = Read-Valor 'Prefixo dos grupos de internet' 'NET_' { param($v) $v -match '^[A-Za-z][A-Za-z0-9_-]{0,9}$' } 'use ate 10 caracteres: letras, numeros, _ ou -, comecando com letra.'
        Write-Host ''
        Info 'Agora, departamento por departamento. Dica: responda N para OUs que nao sao'
        Info 'de pessoas (ex.: Computadores). Usuario com [proxy-manual] na Descricao nunca'
        Info 'e tirado de um grupo.'
        # Rodando de novo: respeita as OUs recusadas antes (configuracao da tarefa)
        $ignorarAntes = @()
        $cfgAntiga = Join-Path (Join-Path $env:ProgramData 'pfSense-Squid-AD') 'sincronizacao.json'
        if (Test-Path $cfgAntiga) { try { $ignorarAntes = @((Get-Content $cfgAntiga -Raw | ConvertFrom-Json).Ignorar) } catch {} }
        $r = Sync-SetoresAD $empresa.DistinguishedName $prefixo $true $ignorarAntes
        foreach ($g in $r.Grupos) { $setores.Add($g) }
        $sync = [ordered]@{ BaseOu = [string]$empresa.DistinguishedName; Prefixo = $prefixo; Ignorar = @($r.Ignoradas) }
        if ($r.Ignoradas.Count) { Info ('OUs fora dos setores: ' + (($r.Ignoradas | ForEach-Object { ($_ -split ',')[0] -replace '^OU=' }) -join ', ')) }
        $soltos = @(Get-ADUser -SearchBase $empresa.DistinguishedName -SearchScope OneLevel -Filter 'Enabled -eq $true')
        if ($soltos.Count) {
            Warn ("{0} usuario(s) direto em '{1}', fora dos departamentos: ficam SEM SETOR (acessam" -f $soltos.Count, $empresa.Name)
            Info ('    tudo e aparecem destacados no relatorio). Mova para a OU do departamento: ' + ((($soltos | Select-Object -First 12) | ForEach-Object { $_.Name }) -join ', ') + $(if ($soltos.Count -gt 12) { ', ...' } else { '' }))
        }
    }
}
if (-not $sync) {
Info 'Sem OUs de departamento: escolha grupos que ja existem no AD para servir de setor.'

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
}
$setores = @($setores | Sort-Object DistinguishedName -Unique)
if ($setores.Count -eq 0) { Warn 'nenhum setor escolhido: todos aparecem como "SEM SETOR" no relatorio (e acessam tudo).' }
else { Ok "setores: $(($setores | ForEach-Object { $_.Name }) -join ', ')" }

# ------------------------- 5. conta de servico -------------------------
Step 'Conta de servico do pfSense (so leitura)'
Explicar -OQue 'Uma conta propria do pfSense no AD (padrao: svc-squid-ldap).' `
         -PorQue @('O pfSense usa essa conta para procurar o usuario no AD antes de',
                   'conferir a senha dele.') `
         -Acontece @('Ela so LE o AD: nao e admin. Se for gerada uma senha nova, ela',
                     'aparece no FIM do script para voce guardar, e o pfSense recebe a',
                     'nova pelo arquivo. Para manter a senha atual, responda N e digite-a.')
$svcNome = Read-Valor 'Nome da conta de servico' 'svc-squid-ldap' { param($v) $v -match '^[A-Za-z0-9._-]{3,20}$' } 'use 3 a 20 caracteres: letras, numeros, . _ -'
$svc = Get-ADUser -Filter "SamAccountName -eq '$svcNome'" -ErrorAction SilentlyContinue
$svcSenha = $null
if ($svc) {
    Ok "a conta '$svcNome' ja existe: $($svc.DistinguishedName)"
    if (Read-SimNao 'Gerar uma senha nova para ela? (o pfSense recebe a nova pelo arquivo)' $true) {
        $svcSenha = New-SenhaForte
        $senhaParaMostrar = $svcSenha
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
    $senhaParaMostrar = $svcSenha
    New-ADUser -Name $svcNome -SamAccountName $svcNome -UserPrincipalName "$svcNome@$($dom.DNSRoot)" -Path $cont `
        -AccountPassword (ConvertTo-SecureString $svcSenha -AsPlainText -Force) -Enabled $true `
        -PasswordNeverExpires $true -CannotChangePassword $true `
        -Description 'Conta SO LEITURA do Squid (pfSense) para consultar o AD. Nao usar para login.'
    $svc = Get-ADUser -Identity $svcNome
    Ok "conta criada: $($svc.DistinguishedName)"
}

# ------------------------------ 6. teste --------------------------------
Step "Teste de login (como o pfSense vai fazer)"
Explicar -OQue "Um login de verdade no AD ($transporte, porta $porta), igual ao que o pfSense fara." `
         -PorQue 'Achar um problema aqui e muito mais facil do que depois, no firewall.' `
         -Acontece @('So leitura. Se quiser, testa tambem com um usuario real e mostra o',
                     'setor dele. A senha digitada nao e gravada.')
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
        } catch {
            Warn "o AD encontrou '$u', mas RECUSOU a senha. Causas mais comuns:"
            Info '    senha digitada errada; "o usuario deve alterar a senha no proximo logon" marcado;'
            Info '    conta bloqueada por tentativas; senha expirada. (Detalhe: ' + $_.Exception.InnerException.Message + ')'
            Info '    Depois de corrigir, teste no pfSense: php squid-ad.php testar <usuario>'
        }
    }
    $senhaU = $null
}
$con.Dispose()

# ------------------------------ 7. GPO ----------------------------------
Step 'GPO do proxy nos PCs (opcional)'
Explicar -OQue 'Uma politica de grupo que configura o proxy (IP do pfSense:3128) nos PCs.' `
         -PorQue @('Proxy com login nao funciona em modo transparente: cada PC precisa',
                   'apontar para o pfSense.') `
         -Acontece @('A GPO e criada SEM vinculo: nada muda nos PCs ate voce liga-la numa',
                     'OU (setor por setor), aqui ou depois no Gerenciamento de GPO.')
$proxy = $null
if (Read-SimNao 'Criar a GPO que configura o proxy nos PCs?' $false) {
    Import-Module GroupPolicy -ErrorAction Stop
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $ipProxy = Read-Valor 'IP do pfSense na LAN (endereco do proxy)' "$gw" { param($v) $v -match '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$' } 'digite um IPv4 valido (ex.: 172.16.10.1).'
    $portaProxy = Read-Valor 'Porta do proxy do Squid' '3128' { param($v) $v -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le 65535 } 'porta de 1 a 65535.'
    # O padrao SEMPRE entra (rede local e dominio nao passam pelo proxy); aqui so
    # se acrescenta o que for extra. Antes, digitar algo substituia o padrao.
    $padraoExc = "<local>;*.$($dom.DNSRoot);10.*;172.16.*;192.168.*"
    Info "excecoes padrao (nao passam pelo proxy): $padraoExc"
    $extras = ''
    if (-not $Yes) { $extras = ("" + (Read-Host '    Excecoes EXTRAS, separadas por ; (ENTER = nenhuma)')).Trim().Trim(';') }
    $excecoes = Join-Excecoes $padraoExc $extras
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

# ---------------- 7b. acesso remoto para a inspecao SSL (opcional) -----------------
Step 'Acesso remoto ao pfSense para a inspecao SSL (opcional)'
Explicar -OQue 'Uma chave SSH restrita, instalada no pfSense, so para os comandos "ssl-*" (fase 2: inspecao SSL).' `
         -PorQue @('Hoje o Servidor AD nao tem nenhum acesso ao firewall; so um humano com a senha',
                   'admin consegue rodar "ssl-aplicar" (System > Cert. Manager / Services > Squid).',
                   'Essa chave deixa isso automatizavel sem dar a senha admin completa para a automacao.') `
         -Acontece @('Gera uma chave SSH aqui no Servidor AD, pede a senha ADMIN do pfSense SO AGORA',
                     '(nunca e salva) e manda o pfSense instalar o acesso restrito: so os comandos',
                     'ssl-simular/ssl-aplicar/ssl-testar/ssl-status/ssl-desfazer passam por essa chave,',
                     'mesmo que o shell do pfSense seja root. Precisa do modulo PowerShell Posh-SSH.')
$sslRemoto = $null
if (Read-SimNao 'Configurar agora o acesso remoto para a inspecao SSL?' $false) {
    $sslRemoto = Install-SquidSslAcessoRemoto
}

# --------------------------- 9. arquivo ---------------------------------
Step 'Arquivo para o pfSense'
Explicar -OQue "O arquivo squid-ad-$($dom.NetBIOSName).json, com tudo que o script do pfSense precisa." `
         -PorQue 'Leva servidor, conta, setores e a CA do LDAPS: nada para digitar no pfSense.' `
         -Acontece @('Gravado ao lado deste script, so Administradores leem. Se levar a senha',
                     'da conta de servico, apague o arquivo depois de usar no pfSense.')
if (-not $OutFile) { $OutFile = Join-Path $Aqui ("squid-ad-{0}.json" -f $dom.NetBIOSName) }
$incluiSenha = Read-SimNao 'Incluir a senha da conta de servico no arquivo? (senao o pfSense pergunta)' $true
$dados = New-PacoteSquid -Dom $dom -DcHost $dcHost -DcIp $dcIp -Porta $porta -Transporte $transporte `
    -ContaDn $svc.DistinguishedName -ContaUsuario $svcNome -ContaSenha $(if ($incluiSenha) { $svcSenha } else { '' }) `
    -Filtro $filtro -Setores $setores -CaPem $caPem -Proxy $proxy -Sync $sync
($dados | ConvertTo-Json -Depth 5) | Set-Content -Path $OutFile -Encoding ASCII
# So Administradores e SYSTEM leem o arquivo (ele pode ter a senha da conta).
& icacls.exe $OutFile /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' /Q | Out-Null
Ok "gravado: $OutFile"
if ($incluiSenha) { Warn 'o arquivo tem a senha da conta de servico: apague-o depois de usar no pfSense.' }
$svcSenha = $null

# --------------------- 10. sincronizacao automatica ----------------------
if ($sync) {
    Step 'Sincronizacao automatica (opcional)'
    Explicar -OQue 'Uma tarefa agendada no Windows (a cada 15 min, como SYSTEM).' `
             -PorQue 'Manter os setores em dia sem precisar rodar este script de novo.' `
             -Acontece @('OU de departamento nova   -> ganha o grupo de internet dela',
                         'usuario novo ou que mudou -> entra no grupo do departamento',
                         'de departamento              (e sai do antigo)',
                         'OUs que voce recusou      -> nunca ganham grupo',
                         'O pfSense, por sua vez, traz os grupos novos para o SquidGuard.')
    if (Read-SimNao 'Criar a tarefa agendada de sincronizacao (a cada 15 min)?' $true) {
        $dirSync = Join-Path $env:ProgramData 'pfSense-Squid-AD'
        if (-not (Test-Path $dirSync)) { New-Item -ItemType Directory -Force $dirSync | Out-Null }
        # Trava so a pasta (SYSTEM + Administradores); o conteudo herda dela.
        & icacls.exe $dirSync /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q | Out-Null
        Copy-Item $MyInvocation.MyCommand.Definition (Join-Path $dirSync 'Install-SquidAD.ps1') -Force
        ($sync | ConvertTo-Json) | Set-Content -Path (Join-Path $dirSync 'sincronizacao.json') -Encoding ASCII
        & icacls.exe (Join-Path $dirSync '*') /reset /T /C /Q | Out-Null
        $tarefa = 'pfSense-Squid-AD - Sincronizar setores'
        $acao = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $dirSync 'Install-SquidAD.ps1') + '" -Sincronizar'
        & schtasks.exe /Create /F /TN $tarefa /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 15 /TR $acao | Out-Null
        if ($LASTEXITCODE -ne 0) { Warn "nao consegui criar a tarefa (schtasks exit $LASTEXITCODE)." }
        else {
            Ok "tarefa '$tarefa' criada (a cada 15 min)"
            Info "log: $(Join-Path $dirSync 'sincronizacao.log')  |  eventos 2000 (ok) / 2001 (erro), origem pfSense-Squid-AD"
        }
    }
}

Write-Host ''
Write-Host 'Pronto no AD. Proximo passo, no pfSense (docs/pfsense.md):' -ForegroundColor Cyan
Write-Host '    1. Diagnostics > Command Prompt > Upload File: envie o squid-ad.php e o .json'
Write-Host '    2. Por SSH (recomendado, interativo):'
Write-Host "         php /tmp/squid-ad.php aplicar /tmp/$(Split-Path $OutFile -Leaf)"
Write-Host '       ou na tela Command Prompt (sem perguntas): primeiro "simular", depois "aplicar ... --sim"'
if ($sslRemoto) {
    if ($sslRemoto.Instalada) {
        Write-Host "    3. Inspecao SSL: chave instalada em $($sslRemoto.FirewallUsuario)@$($sslRemoto.FirewallHost):$($sslRemoto.FirewallPorta)."
        Write-Host "       Teste com: ssh -i $($sslRemoto.ChavePrivada) $($sslRemoto.FirewallUsuario)@$($sslRemoto.FirewallHost) -p $($sslRemoto.FirewallPorta) ssl-status"
    } else {
        Write-Host "    3. Inspecao SSL: chave gerada em $($sslRemoto.ChavePrivada), mas NAO instalada no pfSense ainda (ver aviso acima)."
    }
}

# --------------------------- senha gerada --------------------------------
# Por ultimo, para ser a ultima coisa na tela.
if ($senhaParaMostrar) {
    Write-Host ''
    Write-Host '  =====================================================================' -ForegroundColor Yellow
    Write-Host "   SENHA DA CONTA DE SERVICO '$svcNome' - GUARDE NO COFRE DE SENHAS" -ForegroundColor Yellow
    Write-Host '  =====================================================================' -ForegroundColor Yellow
    Write-Host "      $senhaParaMostrar" -ForegroundColor White
    Write-Host '   Ela foi gerada agora e NAO fica gravada em log. Voce vai precisar dela'
    Write-Host '   se reinstalar o pfSense sem o arquivo .json, ou para conferir a conta.'
    Write-Host '  =====================================================================' -ForegroundColor Yellow
    $senhaParaMostrar = $null
}
