<?php
/*
 * pfSense-Squid-AD - login do Squid (pfSense CE 2.7) via LDAP no Active Directory.
 * https://github.com/AlexandreAlan/pfSense-Squid-AD
 *
 * Uso (no pfSense, como root - SSH opcao 8, ou Diagnostics > Command Prompt):
 *
 *   php squid-ad.php simular   <arquivo.json>         mostra o que vai ser feito, NAO muda nada
 *   php squid-ad.php aplicar   <arquivo.json> [--sim] aplica (pergunta S/N; --sim = S para tudo)
 *   php squid-ad.php testar    <usuario>              testa o login de um usuario no AD
 *   php squid-ad.php relatorio [--dias N] [--usuario X] [--csv arquivo]
 *   php squid-ad.php sincronizar [--forcar]          traz do AD os grupos de setor (NET_*) para o SquidGuard
 *   php squid-ad.php status
 *   php squid-ad.php desfazer  [--sim]                volta tudo como estava antes do projeto
 *
 * O <arquivo.json> e gerado pelo Install-SquidAD.ps1 no servidor AD.
 * Nesta versao todo usuario autenticado acessa tudo. Cada setor (grupo NET_ do
 * AD) vira uma regra no SquidGuard (Groups ACL) que LIBERA TUDO; para restringir,
 * edite a regra na tela e escolha as Target categories - a sincronizacao nunca
 * mexe nisso, so na origem (quem e o setor).
 */

const SQAD_VERSAO    = '1.2.0';
const SQAD_MARCA_INI = '# >>> pfSense-Squid-AD (gerado automaticamente - nao edite este bloco) >>>';
const SQAD_MARCA_FIM = '# <<< pfSense-Squid-AD <<<';
const SQAD_PROMPT    = 'Proxy da empresa: use seu usuario e senha do Windows';
const SQAD_MARCA_ACL = 'pfSense-Squid-AD';            // descricao das regras criadas no SquidGuard
const SQAD_APAGADO   = '(grupo apagado no AD)';
const SQAD_CRON      = '/usr/local/bin/php /root/squid-ad.php sincronizar --cron';
/* Caminhos do pfSense. Os testes (tests/) definem antes, apontando para pastas temporarias. */
foreach ([
	'SQAD_DIR'         => '/usr/local/etc/squid-ad',
	'SQAD_BACKUPS'     => '/root/squid-ad-backups',
	'SQAD_LDAPCONF'    => '/usr/local/etc/openldap/ldap.conf',
	'SQAD_HELPER'      => '/usr/local/libexec/squid/basic_ldap_auth',
	'SQAD_SQUIDCONF'   => '/usr/local/etc/squid/squid.conf',
	'SQAD_SQUIDINC'    => '/usr/local/pkg/squid.inc',
	'SQAD_ACCESSLOG'   => '/var/squid/logs/access.log',
	'SQAD_CONFIGXML'   => '/cf/conf/config.xml',
	'SQAD_VERSIONFILE' => '/etc/version',
	'SQAD_SQUIDGUARDINC' => '/usr/local/pkg/squidguard.inc',
	'SQAD_SCRIPT_FIXO' => '/root/squid-ad.php',
] as $c => $v) {
	if (!defined($c)) { define($c, $v); }
}
define('SQAD_ESTADO', SQAD_DIR . '/estado.json');
define('SQAD_CA', SQAD_DIR . '/ca-ad.pem');
define('SQAD_LOCK', SQAD_DIR . '/sincronizar.lock');

/* ======================================================================
 *  Funcoes puras (sem pfSense): testadas no CI em tests/
 * ====================================================================== */

/* Le e valida o arquivo gerado pelo Install-SquidAD.ps1. */
function sqad_ler_pacote(string $arquivo): array {
	if (!is_readable($arquivo)) {
		throw new RuntimeException("arquivo nao encontrado: {$arquivo}");
	}
	$txt = file_get_contents($arquivo);
	$txt = preg_replace('/^\xEF\xBB\xBF/', '', $txt);   // BOM, se o Windows colocou
	$p = json_decode($txt, true);
	if (!is_array($p)) {
		throw new RuntimeException("o arquivo nao e um JSON valido: {$arquivo}");
	}
	if (($p['Projeto'] ?? '') !== 'pfSense-Squid-AD') {
		throw new RuntimeException('o arquivo nao foi gerado pelo Install-SquidAD.ps1');
	}
	foreach (['Servidor.Host', 'Servidor.Porta', 'Servidor.Transporte', 'Dominio.Base', 'Conta.Dn', 'Filtro', 'Atributo'] as $campo) {
		[$a, $b] = array_pad(explode('.', $campo), 2, null);
		$v = $b === null ? ($p[$a] ?? '') : ($p[$a][$b] ?? '');
		if ($v === '' || $v === null) {
			throw new RuntimeException("campo obrigatorio vazio no arquivo: {$campo}");
		}
	}
	if (!in_array($p['Servidor']['Transporte'], ['ssl', 'standard'], true)) {
		throw new RuntimeException('Servidor.Transporte deve ser "ssl" ou "standard"');
	}
	if ($p['Servidor']['Transporte'] === 'ssl' && strpos($p['CaPem'] ?? '', 'BEGIN CERTIFICATE') === false) {
		throw new RuntimeException('LDAPS sem a CA no arquivo (CaPem): gere o arquivo de novo no AD');
	}
	$p['Setores'] = array_values(array_filter($p['Setores'] ?? [], function ($s) {
		return is_array($s) && !empty($s['Nome']) && !empty($s['Dn']);
	}));
	// v1.1: setores espelhando as OUs + sincronizacao (opcional no arquivo)
	if (!empty($p['Sync'])) {
		if (empty($p['Sync']['BaseOu']) || empty($p['Sync']['Prefixo'])) {
			throw new RuntimeException('Sync.BaseOu e Sync.Prefixo sao obrigatorios quando ha sincronizacao');
		}
		foreach ($p['Setores'] as $s) {
			if (!preg_match('/^[0-9a-f]{32}$/', $s['Guid'] ?? '')) {
				throw new RuntimeException("setor {$s['Nome']} sem o Guid do AD: gere o arquivo de novo com o Install-SquidAD.ps1 1.1");
			}
		}
	} else {
		$p['Sync'] = null;
	}
	return $p;
}

/*
 * Monta a configuracao de autenticacao do Squid (installedpackages/squidauth).
 * Preserva tudo que nao e do LDAP (redes sem autenticacao, limites etc.).
 */
function sqad_campos_auth(array $p, array $atual, string $senha): array {
	$novo = $atual;
	$novo['auth_method']        = 'ldap';
	$novo['auth_server']        = $p['Servidor']['Host'];
	$novo['auth_server_port']   = (string)$p['Servidor']['Porta'];
	$novo['ldap_version']       = '3';
	$novo['ldap_urltype']       = $p['Servidor']['Transporte'];
	$novo['ldap_user']          = $p['Conta']['Dn'];
	$novo['ldap_pass']          = $senha;
	$novo['ldap_basedomain']    = $p['Dominio']['Base'];
	$novo['ldap_userattribute'] = $p['Atributo'];
	$novo['ldap_filter']        = $p['Filtro'];
	$novo['ldap_noreferrals']   = 'on';   // AD devolve referrals que so atrasam o login
	if (empty($novo['auth_prompt']) || $novo['auth_prompt'] === 'Please enter your credentials to access the proxy') {
		$novo['auth_prompt'] = SQAD_PROMPT;
	}
	if (empty($novo['auth_processes'])) { $novo['auth_processes'] = '5'; }
	if (empty($novo['auth_ttl']))       { $novo['auth_ttl'] = '5'; }
	return $novo;
}

/* Lista legivel do que muda (para o "simular" e para a confirmacao). */
function sqad_diferencas(array $antes, array $depois): array {
	$linhas = [];
	foreach ($depois as $k => $v) {
		$a = $antes[$k] ?? '';
		if ((string)$a === (string)$v) { continue; }
		if ($k === 'ldap_pass') {
			$linhas[] = sprintf('  %-20s %s', $k, $a === '' ? '(vazio) -> (senha da conta de servico)' : '(alterada)');
		} else {
			$linhas[] = sprintf('  %-20s %s -> %s', $k, $a === '' ? '(vazio)' : $a, $v);
		}
	}
	return $linhas;
}

/* Coloca/troca/remove o bloco do projeto dentro do ldap.conf, sem mexer no resto. */
function sqad_bloco_ldapconf(string $conteudo, ?string $cacert): string {
	$ini = preg_quote(SQAD_MARCA_INI, '/');
	$fim = preg_quote(SQAD_MARCA_FIM, '/');
	$sem = preg_replace("/\n?{$ini}.*?{$fim}\n?/s", "\n", $conteudo);
	$sem = rtrim($sem, "\n");
	if ($cacert === null) {
		return $sem === '' ? '' : $sem . "\n";
	}
	$bloco = SQAD_MARCA_INI . "\n"
		. "# CA do Active Directory para o LDAPS do Squid (basic_ldap_auth)\n"
		. "TLS_CACERT {$cacert}\n"
		. "TLS_REQCERT demand\n"
		. SQAD_MARCA_FIM . "\n";
	return ($sem === '' ? '' : $sem . "\n\n") . $bloco;
}

/* Escapa um valor para dentro de um filtro LDAP (RFC 4515). */
function sqad_escape_filtro(string $v): string {
	return strtr($v, ['\\' => '\5c', '*' => '\2a', '(' => '\28', ')' => '\29', "\0" => '\00']);
}

/* URL do servidor LDAP no formato que o Squid usa. */
function sqad_url_ldap(array $p): string {
	$proto = $p['Servidor']['Transporte'] === 'ssl' ? 'ldaps://' : 'ldap://';
	return $proto . $p['Servidor']['Host'] . ':' . $p['Servidor']['Porta'];
}

/*
 * Argumentos do basic_ldap_auth - os MESMOS que o pacote Squid do pfSense 2.7
 * monta em squid_resync_auth(), para o teste ser fiel ao uso real. A senha vai
 * por arquivo (-W) e nao na linha de comando.
 */
function sqad_args_helper(array $p, string $arquivo_senha): array {
	return ['-v', '3', '-b', $p['Dominio']['Base'], '-R', '-D', $p['Conta']['Dn'], '-W', $arquivo_senha,
		'-f', $p['Filtro'], '-u', $p['Atributo'], '-P', '-H', sqad_url_ldap($p)];
}

/*
 * Uma linha do access.log do Squid (formato nativo):
 *   1730000000.123  45 172.16.10.50 TCP_TUNNEL/200 3920 CONNECT www.bb.com.br:443 joao.silva HIER_DIRECT/1.2.3.4 -
 * Devolve null para linhas que nao sao de acesso.
 */
function sqad_parse_linha(string $linha): ?array {
	$c = preg_split('/\s+/', trim($linha));
	if (count($c) < 8 || !is_numeric($c[0])) { return null; }
	[$acao, $codigo] = array_pad(explode('/', $c[3], 2), 2, '');
	$metodo = $c[5];
	$url = $c[6];
	if ($metodo === 'CONNECT') {
		$host = preg_replace('/:\d+$/', '', $url);
	} else {
		$host = parse_url($url, PHP_URL_HOST) ?: $url;
	}
	$host = strtolower(trim($host, '[]'));
	return [
		'ts'      => (float)$c[0],
		'ip'      => $c[2],
		'acao'    => $acao,
		'codigo'  => $codigo,
		'bytes'   => (int)$c[4],
		'usuario' => $c[7] === '-' ? '' : strtolower(rawurldecode($c[7])),
		'site'    => sqad_site_base($host),
		'negado'  => strpos($acao, 'DENIED') !== false || $codigo === '407',
	];
}

/* www.bb.com.br -> bb.com.br ; cdn.x.google.com -> google.com (agrupa por site). */
function sqad_site_base(string $host): string {
	if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) { return $host; }
	$p = explode('.', $host);
	$n = count($p);
	if ($n <= 2) { return $host; }
	// sufixos de 2 niveis comuns (com.br, gov.br, co.uk...)
	$dois = in_array($p[$n - 2], ['com', 'gov', 'org', 'net', 'edu', 'co', 'ind', 'adv', 'jus', 'mil'], true) && strlen($p[$n - 1]) === 2;
	return implode('.', array_slice($p, $dois ? -3 : -2));
}

/* Agrega o log por usuario: total, negados e sites mais acessados. */
function sqad_agregar(iterable $linhas, float $desde = 0, string $so_usuario = ''): array {
	$u = [];
	foreach ($linhas as $l) {
		$r = sqad_parse_linha($l);
		if ($r === null || $r['ts'] < $desde) { continue; }
		if ($r['codigo'] === '407') { continue; }   // pedido de senha do proprio proxy, nao e acesso
		$nome = $r['usuario'] !== '' ? $r['usuario'] : '(sem login) ' . $r['ip'];
		if ($so_usuario !== '' && $nome !== strtolower($so_usuario)) { continue; }
		if (!isset($u[$nome])) { $u[$nome] = ['acessos' => 0, 'negados' => 0, 'bytes' => 0, 'sites' => [], 'ultimo' => 0]; }
		$u[$nome]['acessos']++;
		$u[$nome]['bytes'] += $r['bytes'];
		$u[$nome]['ultimo'] = max($u[$nome]['ultimo'], $r['ts']);
		if ($r['negado']) { $u[$nome]['negados']++; }
		if ($r['site'] !== '') { $u[$nome]['sites'][$r['site']] = ($u[$nome]['sites'][$r['site']] ?? 0) + 1; }
	}
	foreach ($u as &$d) { arsort($d['sites']); }
	unset($d);
	ksort($u);
	return $u;
}

/* Texto do relatorio. $setores = [usuario => ['SETOR-X', ...]] */
function sqad_texto_relatorio(array $agg, array $setores, int $top = 5): string {
	$out = [];
	$sem = [];
	foreach ($agg as $usr => $d) {
		$s = $setores[$usr] ?? [];
		$rotulo = $s ? implode(', ', $s) : (strpos($usr, '(sem login)') === 0 ? '-' : 'SEM SETOR - acessando tudo');
		if (!$s && strpos($usr, '(sem login)') !== 0) { $sem[] = $usr; }
		$tops = [];
		foreach (array_slice($d['sites'], 0, $top, true) as $site => $n) { $tops[] = "{$site} ({$n})"; }
		$out[] = sprintf("%-24s %-28s %7d acessos %5d negados  %s", $usr, $rotulo, $d['acessos'], $d['negados'], implode(', ', $tops));
	}
	$cab = sprintf("%-24s %-28s %15s %13s  %s", 'USUARIO', 'SETOR', '', '', 'SITES MAIS ACESSADOS');
	$txt = $cab . "\n" . str_repeat('-', 120) . "\n" . implode("\n", $out) . "\n";
	if ($sem) {
		$txt .= "\n!! " . count($sem) . " usuario(s) SEM SETOR acessando tudo: " . implode(', ', $sem) . "\n"
			. "   Coloque-os no grupo do setor no AD (vale no proximo login).\n";
	}
	return $txt;
}


/* ----------------------------------------------------------------------
 *  SquidGuard (Groups ACL) - funcoes puras
 * ---------------------------------------------------------------------- */

/*
 * Nome da regra no SquidGuard a partir do grupo. O SquidGuard do pfSense 2.7
 * aceita 2 a 16 caracteres [a-zA-Z0-9_-], comecando com letra, e reserva
 * alguns nomes. NET_EXPEDICAO_INSTRUMENTAL -> EXPEDICAO_INSTR
 */
function sqad_nome_acl(string $grupo, string $prefixo, array $usados): string {
	$base = $grupo;
	if ($prefixo !== '' && stripos($base, $prefixo) === 0) { $base = substr($base, strlen($prefixo)); }
	$base = preg_replace('/[^A-Za-z0-9_-]+/', '_', $base);
	$base = trim($base, '_-');
	if ($base === '' || !preg_match('/^[A-Za-z]/', $base)) { $base = 'S' . $base; }
	$reservados = ['acl', 'all', 'allow', 'dbhome', 'default', 'dest', 'in-addr', 'log', 'logdir', 'none', 'pass', 'rew', 'src', 'squidstatus', 'url', 'user'];
	if (in_array(strtolower($base), $reservados, true)) { $base = 'S_' . $base; }
	$base = substr($base, 0, 16);
	if (strlen($base) < 2) { $base = str_pad($base, 2, '_'); }
	$usados_min = array_map('strtolower', $usados);
	$nome = $base;
	for ($i = 2; in_array(strtolower($nome), $usados_min, true); $i++) {
		$suf = (string)$i;
		$nome = substr($base, 0, 16 - strlen($suf)) . $suf;
	}
	return $nome;
}

/* Codifica para URL LDAP: mantem so os caracteres seguros e o %s do SquidGuard. */
function sqad_url_codifica(string $s, string $manter): string {
	$partes = explode('%s', $s);
	foreach ($partes as &$pt) {
		$out = '';
		foreach (str_split($pt) as $ch) {
			$out .= (ctype_alnum($ch) || strpos($manter, $ch) !== false) ? $ch : sprintf('%%%02x', ord($ch));
		}
		$pt = $out;
	}
	unset($pt);
	return implode('%s', $partes);
}

/*
 * Linha de origem do Groups ACL: o SquidGuard procura o usuario (%s) no AD e
 * confere se ele e membro do grupo (inclusive grupo dentro de grupo).
 * Mesmo formato do exemplo da tela do pfSense (virgulas do DN como %2c).
 */
function sqad_linha_ldapusersearch(array $p, string $grupo_dn): string {
	$filtro = '(&(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=' . sqad_escape_filtro($grupo_dn) . '))';
	return 'ldapusersearch ' . sqad_url_ldap($p) . '/' . sqad_url_codifica($p['Dominio']['Base'], '=,._-')
		. '?sAMAccountName?sub?' . sqad_url_codifica($filtro, '()&=:!*._-');
}

function sqad_marca_acl(string $guid, string $grupo): string {
	return SQAD_MARCA_ACL . " id={$guid} grupo={$grupo}";
}

/* id (GUID do grupo no AD) e nome do grupo gravados na descricao da regra; null se a regra nao e do projeto. */
function sqad_info_acl(array $acl): ?array {
	if (!preg_match('/^' . preg_quote(SQAD_MARCA_ACL, '/') . ' id=([0-9a-f]+) grupo=(\S+)/', $acl['description'] ?? '', $m)) { return null; }
	return ['guid' => $m[1], 'grupo' => $m[2]];
}

function sqad_acl_nova(string $nome, string $origem, string $descricao): array {
	// mesmos campos que a tela grava; destino "all" = libera tudo
	return ['disabled' => '', 'name' => $nome, 'source' => $origem, 'time' => '', 'dest' => 'all [ all]',
		'notallowingip' => '', 'redirect_mode' => 'rmod_none', 'redirect' => '', 'safesearch' => '',
		'rewrite' => '', 'overrewrite' => '', 'description' => $descricao, 'enablelog' => 'on'];
}

/*
 * Sincroniza as regras com os grupos do AD. $grupos = [['Nome','Dn','Guid'], ...]
 * - grupo novo            -> regra nova (libera tudo)
 * - grupo renomeado/movido-> atualiza so a origem (destino/horario ficam)
 * - grupo recriado (mesmo nome, GUID novo) -> reaproveita a regra
 * - grupo apagado         -> desativa a regra (nao apaga)
 * Regras que nao sao do projeto nunca sao tocadas. Devolve [acls, mudancas].
 */
function sqad_sincronizar_acls(array $acls, array $grupos, array $p, string $prefixo): array {
	$mud = [];
	$usados = array_column($acls, 'name');
	$vistos = [];
	foreach ($grupos as $g) {
		$origem = sqad_linha_ldapusersearch($p, $g['Dn']);
		$achou = null;
		foreach ($acls as $i => $a) { $inf = sqad_info_acl($a); if ($inf && $inf['guid'] === $g['Guid']) { $achou = $i; break; } }
		if ($achou === null) {
			foreach ($acls as $i => $a) {
				$inf = sqad_info_acl($a);
				if ($inf && strcasecmp($inf['grupo'], $g['Nome']) === 0 && !in_array($i, $vistos, true)) { $achou = $i; $mud[] = "regra {$a['name']}: grupo {$g['Nome']} foi recriado no AD - regra reaproveitada"; break; }
			}
		}
		if ($achou === null) {
			$nome = sqad_nome_acl($g['Nome'], $prefixo, $usados);
			$usados[] = $nome;
			$acls[] = sqad_acl_nova($nome, $origem, sqad_marca_acl($g['Guid'], $g['Nome']));
			$vistos[] = count($acls) - 1;
			$mud[] = "regra {$nome}: CRIADA para o grupo {$g['Nome']} (libera tudo)";
			continue;
		}
		$vistos[] = $achou;
		$a = &$acls[$achou];
		if ($a['source'] !== $origem) { $a['source'] = $origem; $mud[] = "regra {$a['name']}: origem atualizada (grupo {$g['Nome']} mudou de lugar/nome no AD)"; }
		$desc = sqad_marca_acl($g['Guid'], $g['Nome']);
		if (($a['disabled'] ?? '') === 'on' && strpos($a['description'] ?? '', SQAD_APAGADO) !== false) { $a['disabled'] = ''; $mud[] = "regra {$a['name']}: REATIVADA (grupo {$g['Nome']} voltou no AD)"; }
		$a['description'] = $desc;   // marca atualizada (nome novo do grupo, sem o "apagado")
		unset($a);
	}
	foreach ($acls as $i => &$a) {
		$inf = sqad_info_acl($a);
		if (!$inf || in_array($i, $vistos, true) || ($a['disabled'] ?? '') === 'on') { continue; }
		$a['disabled'] = 'on';
		$a['description'] = sqad_marca_acl($inf['guid'], $inf['grupo']) . ' ' . SQAD_APAGADO;
		$mud[] = "regra {$a['name']}: DESATIVADA (grupo {$inf['grupo']} nao existe mais no AD)";
	}
	unset($a);
	return [$acls, $mud];
}

/* Liga o LDAP nas General settings do SquidGuard (necessario para o ldapusersearch). */
function sqad_sg_geral(array $atual, array $p, string $senha): array {
	$n = $atual;
	$n['ldap_enable']   = 'on';
	$n['ldapbinddn']    = $p['Conta']['Dn'];
	$n['ldapbindpass']  = $senha;
	$n['ldapversion']   = '3';
	if (empty($n['ldapcachetime'])) { $n['ldapcachetime'] = '300'; }   // 5 min, igual ao cache do login
	return $n;
}

/* ======================================================================
 *  Interacao
 * ====================================================================== */

function sqad_msg(string $tipo, string $m): void {
	if ($tipo === 'passo') {   // cabecalho de etapa, separado por linhas e espaco
		$linha = '  ' . str_repeat('-', 72);
		fwrite(STDOUT, "\n\n{$linha}\n   {$m}\n{$linha}\n\n");
		return;
	}
	$pre = ['ok' => '    OK  ', 'aviso' => '    !!  ', 'info' => '        '][$tipo] ?? '';
	fwrite(STDOUT, $pre . $m . "\n");
}

function sqad_pergunta(string $texto, bool $padrao, array $opt): bool {
	$suf = $padrao ? '[S/n]' : '[s/N]';
	if (!empty($opt['sim'])) { sqad_msg('info', "{$texto} {$suf} -> S (--sim)"); return true; }
	while (true) {
		fwrite(STDOUT, "    {$texto} {$suf} ");
		$r = fgets(STDIN);
		if ($r === false) { throw new RuntimeException('sem terminal para responder: rode por SSH, ou use --sim depois de conferir com "simular"'); }
		$r = trim($r);
		if ($r === '') { return $padrao; }
		if (preg_match('/^[sSyY]/', $r)) { return true; }
		if (preg_match('/^[nN]/', $r)) { return false; }
		sqad_msg('aviso', 'responda S ou N (ou ENTER para o padrao).');
	}
}

function sqad_ler_texto(string $texto, bool $oculto = false): string {
	fwrite(STDOUT, "    {$texto}: ");
	if ($oculto) { @shell_exec('stty -echo 2>/dev/null'); }
	$r = fgets(STDIN);
	if ($oculto) { @shell_exec('stty echo 2>/dev/null'); fwrite(STDOUT, "\n"); }
	if ($r === false) { throw new RuntimeException('sem terminal para digitar: rode por SSH'); }
	return rtrim($r, "\r\n");
}

/* ======================================================================
 *  pfSense
 * ====================================================================== */

function sqad_carregar_pfsense(): void {
	if (defined('SQAD_TESTE')) { return; }   // nos testes, as funcoes do pfSense sao simuladas
	foreach (['config.inc', 'util.inc', 'functions.inc', 'pkg-utils.inc', 'certs.inc', 'services.inc'] as $inc) {
		require_once($inc);
	}
}

function sqad_versao_pfsense(): string {
	return trim((string)@file_get_contents(SQAD_VERSIONFILE));
}

/* Confere o ambiente. Devolve avisos (nao fatais); lanca excecao nos fatais. */
function sqad_verificar_ambiente(): array {
	$avisos = [];
	$v = sqad_versao_pfsense();
	if (strpos($v, '2.7') !== 0) {
		$avisos[] = "este projeto foi feito para o pfSense CE 2.7 (este e {$v}). Confira o resultado com cuidado.";
	}
	if (!file_exists(SQAD_SQUIDINC) || !is_array(config_get_path('installedpackages/squid/config/0'))) {
		throw new RuntimeException('o pacote Squid nao esta instalado/configurado (System > Package Manager > squid, depois Services > Squid Proxy Server)');
	}
	if (!file_exists(SQAD_HELPER)) {
		throw new RuntimeException('o helper ' . SQAD_HELPER . ' nao existe (pacote Squid incompleto?)');
	}
	if (config_get_path('installedpackages/squid/config/0/enable_squid') !== 'on') {
		$avisos[] = 'o Squid esta DESLIGADO (Services > Squid Proxy Server > Enable). A configuracao fica pronta, mas so vale quando ligar.';
	}
	if (config_get_path('installedpackages/squid/config/0/transparent_proxy') === 'on') {
		$avisos[] = 'o modo TRANSPARENTE esta ligado: o login so vale para os PCs configurados para usar o proxy (porta '
			. (config_get_path('installedpackages/squid/config/0/proxy_port') ?: '3128') . '). Trafego transparente nao pede senha.';
	}
	return $avisos;
}

function sqad_resolve(string $host): bool {
	return gethostbyname($host) !== $host;
}

/* Cria Host Override no DNS do pfSense para o nome do DC (com permissao). */
function sqad_host_override(array $p): string {
	[$h, $d] = array_pad(explode('.', $p['Servidor']['Host'], 2), 2, '');
	$item = ['host' => $h, 'domain' => $d, 'ip' => $p['Servidor']['Ip'], 'descr' => 'pfSense-Squid-AD: controlador de dominio', 'aliases' => ['item' => []]];   // mesmo formato da tela
	if (config_path_enabled('unbound')) {
		$hosts = config_get_path('unbound/hosts', []);
		$hosts[] = $item;
		config_set_path('unbound/hosts', $hosts);
		write_config('pfSense-Squid-AD: host override do controlador de dominio');
		services_unbound_configure();   // services.inc
		return 'DNS Resolver (unbound)';
	}
	if (config_path_enabled('dnsmasq')) {
		$hosts = config_get_path('dnsmasq/hosts', []);
		$hosts[] = $item;
		config_set_path('dnsmasq/hosts', $hosts);
		write_config('pfSense-Squid-AD: host override do controlador de dominio');
		services_dnsmasq_configure();
		return 'DNS Forwarder (dnsmasq)';
	}
	throw new RuntimeException('nem o DNS Resolver nem o DNS Forwarder estao ativos: crie a entrada DNS na mao');
}

/* Roda o basic_ldap_auth como o Squid roda. Devolve [ok(bool), resposta]. */
function sqad_testar_login(array $p, string $senha_conta, string $usuario, string $senha_usuario): array {
	$tmp = tempnam('/tmp', 'sqad');
	chmod($tmp, 0600);
	file_put_contents($tmp, $senha_conta);
	try {
		$cmd = escapeshellarg(SQAD_HELPER);
		foreach (sqad_args_helper($p, $tmp) as $a) { $cmd .= ' ' . escapeshellarg($a); }
		$proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($proc)) { throw new RuntimeException('nao consegui executar ' . SQAD_HELPER); }
		// o helper le "usuario senha" codificados como URL (opcao -P nao muda isso)
		fwrite($pipes[0], rawurlencode($usuario) . ' ' . rawurlencode($senha_usuario) . "\n");
		fclose($pipes[0]);
		$resp = trim(stream_get_contents($pipes[1]));
		$erro = trim(stream_get_contents($pipes[2]));
		fclose($pipes[1]); fclose($pipes[2]);
		proc_close($proc);
	} finally {
		@unlink($tmp);
	}
	return [strpos($resp, 'OK') === 0, $resp . ($erro !== '' ? " | {$erro}" : '')];
}

/* Setores de cada usuario (consulta o AD pela extensao ldap do PHP). */
function sqad_setores_dos_usuarios(array $estado, array $usuarios): array {
	$res = [];
	if (empty($estado['Setores']) || !function_exists('ldap_connect')) { return $res; }
	$auth = config_get_path('installedpackages/squidauth/config/0', []);
	if (($estado['Servidor']['Transporte'] ?? '') === 'ssl') {
		ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, SQAD_CA);
		ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND);
	}
	$l = @ldap_connect(sqad_url_ldap($estado));
	if (!$l) { return $res; }
	ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($l, LDAP_OPT_REFERRALS, 0);
	ldap_set_option($l, LDAP_OPT_NETWORK_TIMEOUT, 10);
	if (!@ldap_bind($l, $auth['ldap_user'] ?? '', $auth['ldap_pass'] ?? '')) {
		sqad_msg('aviso', 'nao consegui consultar os setores no AD: ' . ldap_error($l));
		return $res;
	}
	foreach ($usuarios as $u) {
		if ($u === '' || strpos($u, '(sem login)') === 0) { continue; }
		foreach ($estado['Setores'] as $s) {
			$f = '(&(sAMAccountName=' . sqad_escape_filtro($u) . ')(memberOf:1.2.840.113556.1.4.1941:=' . sqad_escape_filtro($s['Dn']) . '))';
			$r = @ldap_search($l, $estado['Dominio']['Base'], $f, ['sAMAccountName'], 0, 1);
			if ($r && ldap_count_entries($l, $r) > 0) { $res[$u][] = $s['Nome']; }
		}
	}
	@ldap_unbind($l);
	return $res;
}


/* SquidGuard instalado e configurado ao menos uma vez? */
function sqad_sg_instalado(): bool {
	return file_exists(SQAD_SQUIDGUARDINC) && is_array(config_get_path('installedpackages/squidguardgeneral/config/0'));
}

/*
 * Grupos de setor no AD: grupos cujo nome comeca com o prefixo (NET_), dentro
 * da OU da empresa. Consulta por LDAPS com a conta de servico. Lanca excecao se
 * o AD nao responder - quem chama NAO muda nada nesse caso.
 */
function sqad_ad_grupos(array $p, string $dn_conta, string $senha, string $base_ou, string $prefixo, string $cafile): array {
	if (isset($GLOBALS['sqad_fake_ad_grupos'])) {   // testes
		if ($GLOBALS['sqad_fake_ad_grupos'] === 'erro') { throw new RuntimeException('AD fora do ar (simulado)'); }
		return $GLOBALS['sqad_fake_ad_grupos'];
	}
	if (!function_exists('ldap_connect')) { throw new RuntimeException('extensao ldap do PHP ausente'); }
	if (($p['Servidor']['Transporte'] ?? '') === 'ssl') {
		ldap_set_option(null, LDAP_OPT_X_TLS_CACERTFILE, $cafile);
		ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_DEMAND);
	}
	$l = @ldap_connect(sqad_url_ldap($p));
	if (!$l) { throw new RuntimeException('nao consegui abrir a conexao LDAP'); }
	ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
	ldap_set_option($l, LDAP_OPT_REFERRALS, 0);
	ldap_set_option($l, LDAP_OPT_NETWORK_TIMEOUT, 15);
	if (!@ldap_bind($l, $dn_conta, $senha)) { throw new RuntimeException('login LDAP recusado: ' . ldap_error($l)); }
	$r = @ldap_search($l, $base_ou, '(&(objectClass=group)(cn=' . sqad_escape_filtro($prefixo) . '*))', ['cn', 'distinguishedName', 'objectGUID']);
	if (!$r) { throw new RuntimeException('busca de grupos falhou: ' . ldap_error($l)); }
	$e = ldap_get_entries($l, $r);
	$g = [];
	for ($i = 0; $i < $e['count']; $i++) {
		$g[] = ['Nome' => $e[$i]['cn'][0], 'Dn' => $e[$i]['distinguishedname'][0], 'Guid' => bin2hex($e[$i]['objectguid'][0])];
	}
	@ldap_unbind($l);
	usort($g, function ($a, $b) { return strcasecmp($a['Nome'], $b['Nome']); });
	return $g;
}

function sqad_log(string $m): void {
	if (function_exists('log_error')) { log_error('pfSense-Squid-AD: ' . $m); }
}

/* Sincroniza o SquidGuard com os grupos de setor do AD (usado pelo cron a cada 15 min). */
function sqad_cmd_sincronizar(array $opt): int {
	sqad_carregar_pfsense();
	$cron = !empty($opt['cron']);
	$estado = json_decode((string)@file_get_contents(SQAD_ESTADO), true);
	if (!$estado || empty($estado['Sync'])) { throw new RuntimeException('a sincronizacao nao esta configurada: rode o "aplicar" com o arquivo gerado pela versao 1.1 do Install-SquidAD.ps1'); }
	if (!sqad_sg_instalado()) { throw new RuntimeException('o SquidGuard nao esta instalado/configurado'); }
	@mkdir(SQAD_DIR, 0755, true);
	$lock = fopen(SQAD_LOCK, 'c');
	if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) { if (!$cron) { sqad_msg('aviso', 'ja existe uma sincronizacao rodando.'); } return 0; }
	try {
		$auth = config_get_path('installedpackages/squidauth/config/0', []);
		$p = ['Servidor' => $estado['Servidor'], 'Dominio' => $estado['Dominio']];
		$grupos = sqad_ad_grupos($p, $auth['ldap_user'] ?? '', $auth['ldap_pass'] ?? '', $estado['Sync']['BaseOu'], $estado['Sync']['Prefixo'], SQAD_CA);
		if (!$grupos && !empty($estado['Setores']) && empty($opt['forcar'])) {
			throw new RuntimeException("o AD devolveu 0 grupos {$estado['Sync']['Prefixo']}* (antes eram " . count($estado['Setores']) . '). Nada foi alterado. Se for isso mesmo, use --forcar');
		}
		$acls = config_get_path('installedpackages/squidguardacl/config', []);
		if (!is_array($acls)) { $acls = []; }
		[$novas, $mud] = sqad_sincronizar_acls($acls, $grupos, $p, $estado['Sync']['Prefixo']);
		$estado['Setores'] = array_map(function ($g) { return ['Nome' => $g['Nome'], 'Dn' => $g['Dn']]; }, $grupos);
		$estado['UltimaSync'] = date('c');
		$estado['UltimaSyncMudancas'] = count($mud);
		file_put_contents(SQAD_ESTADO, json_encode($estado, JSON_PRETTY_PRINT));
		if ($mud) {
			config_set_path('installedpackages/squidguardacl/config', $novas);
			write_config('pfSense-Squid-AD: sincronizacao com o AD (' . count($mud) . ' mudanca(s))');
			require_once(SQAD_SQUIDGUARDINC);
			squidguard_resync();
			foreach ($mud as $m) { sqad_msg('ok', $m); sqad_log($m); }
		} elseif (!$cron) {
			sqad_msg('ok', 'nada mudou: ' . count($grupos) . ' setor(es) do AD ja estao no SquidGuard.');
		}
	} catch (Throwable $e) {
		sqad_log('sincronizacao falhou (nada foi alterado): ' . $e->getMessage());
		throw $e;
	} finally {
		flock($lock, LOCK_UN);
		fclose($lock);
	}
	return 0;
}

/* ======================================================================
 *  Comandos
 * ====================================================================== */

function sqad_cmd_aplicar(string $arquivo, array $opt, bool $simular): int {
	sqad_carregar_pfsense();
	sqad_msg('passo', 'Ambiente');
	sqad_msg('ok', 'pfSense ' . sqad_versao_pfsense());
	foreach (sqad_verificar_ambiente() as $a) { sqad_msg('aviso', $a); }

	sqad_msg('passo', "Arquivo do AD: {$arquivo}");
	$p = sqad_ler_pacote($arquivo);
	sqad_msg('ok', "dominio {$p['Dominio']['Dns']}, controlador {$p['Servidor']['Host']} ({$p['Servidor']['Ip']})");
	sqad_msg('ok', 'conexao: ' . sqad_url_ldap($p) . ($p['Servidor']['Transporte'] === 'ssl' ? ' (criptografada)' : ' (SEM criptografia)'));
	sqad_msg('ok', 'setores: ' . ($p['Setores'] ? implode(', ', array_column($p['Setores'], 'Nome')) : 'nenhum (todos aparecem como SEM SETOR no relatorio)'));
	sqad_msg('info', 'nesta versao TODO usuario autenticado acessa tudo; quem nao tem setor aparece destacado no relatorio.');

	$senha = (string)($p['Conta']['Senha'] ?? '');
	if ($senha === '') {
		if ($simular || !empty($opt['sim'])) { throw new RuntimeException('o arquivo nao tem a senha da conta de servico: rode por SSH (ela sera perguntada)'); }
		$senha = sqad_ler_texto("Senha da conta {$p['Conta']['Usuario']}", true);
	}

	sqad_msg('passo', 'DNS: o pfSense precisa resolver o nome do controlador');
	if (sqad_resolve($p['Servidor']['Host'])) {
		sqad_msg('ok', "{$p['Servidor']['Host']} -> " . gethostbyname($p['Servidor']['Host']));
	} else {
		sqad_msg('aviso', "o pfSense NAO resolve {$p['Servidor']['Host']}. Sem isso o LDAPS falha (o certificado tem o nome, nao o IP).");
		if ($simular) {
			sqad_msg('info', "o 'aplicar' vai oferecer criar um Host Override {$p['Servidor']['Host']} -> {$p['Servidor']['Ip']}.");
		} elseif (sqad_pergunta("Criar Host Override no DNS do pfSense: {$p['Servidor']['Host']} -> {$p['Servidor']['Ip']}?", true, $opt)) {
			sqad_msg('ok', 'criado no ' . sqad_host_override($p));
			if (!sqad_resolve($p['Servidor']['Host'])) { throw new RuntimeException('o nome ainda nao resolve: confira Services > DNS Resolver'); }
		} else {
			throw new RuntimeException('cancelado: crie a entrada DNS do controlador e rode de novo');
		}
	}

	$atual = config_get_path('installedpackages/squidauth/config/0', []);
	if (!is_array($atual)) { $atual = []; }
	$novo = sqad_campos_auth($p, $atual, $senha);
	sqad_msg('passo', 'O que muda em Services > Squid Proxy Server > Authentication');
	$dif = sqad_diferencas($atual, $novo);
	fwrite(STDOUT, ($dif ? implode("\n", $dif) : '  (nada: ja esta igual)') . "\n");
	if ($p['Servidor']['Transporte'] === 'ssl') {
		sqad_msg('info', 'tambem: CA do AD em ' . SQAD_CA . ' e TLS_CACERT no ' . SQAD_LDAPCONF . ' (bloco marcado)');
	}
	$sg = !empty($p['Sync']) && sqad_sg_instalado();
	if ($sg) {
		sqad_msg('passo', 'SquidGuard: setores do AD (grupos ' . $p['Sync']['Prefixo'] . '* em ' . $p['Sync']['BaseOu'] . ')');
		[, $prev] = sqad_sincronizar_acls(config_get_path('installedpackages/squidguardacl/config', []) ?: [], $p['Setores'], $p, $p['Sync']['Prefixo']);
		fwrite(STDOUT, ($prev ? '  ' . implode("\n  ", $prev) : '  (nada: as regras ja existem)') . "\n");
		sqad_msg('info', 'tambem: LDAP ligado nas General settings do SquidGuard e sincronizacao automatica a cada 15 min.');
		sqad_msg('info', 'suas regras (ex.: setor-davs) e a Default nao sao alteradas.');
	} elseif (!empty($p['Sync'])) {
		sqad_msg('info', 'SquidGuard nao instalado: os setores ficam so no relatorio.');
	}
	if ($simular) {
		sqad_msg('passo', 'SIMULACAO: nada foi alterado.');
		sqad_msg('info', "Para aplicar: php squid-ad.php aplicar {$arquivo}" . (stream_isatty(STDIN) ? '' : ' --sim'));
		return 0;
	}
	if (!sqad_pergunta('Aplicar essas mudancas?', true, $opt)) { sqad_msg('aviso', 'cancelado, nada foi alterado.'); return 1; }

	sqad_msg('passo', 'Backup');
	@mkdir(SQAD_BACKUPS, 0700, true);
	$ts = date('Y-m-d_His');
	copy(SQAD_CONFIGXML, SQAD_BACKUPS . "/config-{$ts}.xml");
	file_put_contents(SQAD_BACKUPS . "/squidauth-{$ts}.json", json_encode(['squidauth' => $atual,
		'ldapconf' => (string)@file_get_contents(SQAD_LDAPCONF),
		'squidguardgeneral' => config_get_path('installedpackages/squidguardgeneral/config/0'),
		'squidguardacl' => config_get_path('installedpackages/squidguardacl/config')], JSON_PRETTY_PRINT));
	chmod(SQAD_BACKUPS . "/squidauth-{$ts}.json", 0600);
	sqad_msg('ok', SQAD_BACKUPS . "/config-{$ts}.xml (config.xml inteiro) e squidauth-{$ts}.json");
	// O "desfazer" volta para ANTES do projeto: se ja foi aplicado antes, o
	// backup de referencia continua sendo o da primeira vez.
	$estado_ant = json_decode((string)@file_get_contents(SQAD_ESTADO), true);
	$backup_original = (is_array($estado_ant) && is_readable($estado_ant['Backup'] ?? '')) ? $estado_ant['Backup'] : SQAD_BACKUPS . "/squidauth-{$ts}.json";
	$aplicado_original = (is_array($estado_ant) && !empty($estado_ant['AplicadoEm'])) ? $estado_ant['AplicadoEm'] : date('c');

	@mkdir(SQAD_DIR, 0755, true);
	if ($p['Servidor']['Transporte'] === 'ssl') {
		sqad_msg('passo', 'CA do Active Directory (LDAPS)');
		file_put_contents(SQAD_CA, $p['CaPem']);
		chmod(SQAD_CA, 0644);
		@mkdir(dirname(SQAD_LDAPCONF), 0755, true);
		file_put_contents(SQAD_LDAPCONF, sqad_bloco_ldapconf((string)@file_get_contents(SQAD_LDAPCONF), SQAD_CA));
		sqad_msg('ok', SQAD_CA . ' + TLS_CACERT em ' . SQAD_LDAPCONF);
	}

	sqad_msg('passo', 'Teste: o mesmo helper do Squid, com a conta de servico');
	[$ok, $resp] = sqad_testar_login($p, $senha, $p['Conta']['Usuario'], $senha);
	if (!$ok) {
		throw new RuntimeException("o AD recusou a conta de servico ({$resp}). Nada foi aplicado no Squid. Confira DNS, LDAPS e a senha.");
	}
	sqad_msg('ok', 'login LDAP funcionando a partir do pfSense');
	if (stream_isatty(STDIN) && empty($opt['sim']) && sqad_pergunta('Testar tambem com um usuario real do AD?', true, $opt)) {
		$u = sqad_ler_texto('Usuario (ex.: joao.silva)');
		[$okU, $respU] = sqad_testar_login($p, $senha, $u, sqad_ler_texto("Senha de {$u}", true));
		$okU ? sqad_msg('ok', "login de {$u} OK") : sqad_msg('aviso', "login de {$u} recusado ({$respU}): ele nao navegaria pelo proxy");
	}

	sqad_msg('passo', 'Aplicando no Squid');
	config_set_path('installedpackages/squidauth/config/0', $novo);
	write_config('pfSense-Squid-AD: autenticacao LDAP no Active Directory');
	file_put_contents(SQAD_ESTADO, json_encode([
		'Versao' => SQAD_VERSAO, 'AplicadoEm' => $aplicado_original, 'AtualizadoEm' => date('c'), 'Backup' => $backup_original,
		'Dominio' => $p['Dominio'], 'Servidor' => $p['Servidor'], 'Setores' => array_map(function ($g) { return ['Nome' => $g['Nome'], 'Dn' => $g['Dn']]; }, $p['Setores']),
		'Sync' => $p['Sync'] ?? null,
	], JSON_PRETTY_PRINT));
	require_once(SQAD_SQUIDINC);
	squid_resync();
	$conf = (string)@file_get_contents(SQAD_SQUIDCONF);
	if (strpos($conf, 'basic_ldap_auth') === false) {
		sqad_msg('aviso', 'o squid.conf nao tem o basic_ldap_auth: confira Services > Squid Proxy Server > Authentication');
	} else {
		sqad_msg('ok', 'squid.conf regenerado com o login LDAP');
	}
	sqad_msg('ok', is_process_running('squid') ? 'Squid rodando' : 'Squid NAO esta rodando (ligue em Services > Squid Proxy Server)');

	if ($sg) {
		sqad_msg('passo', 'SquidGuard: LDAP + uma regra por setor (libera tudo)');
		if (sqad_pergunta('Ligar o LDAP no SquidGuard e criar/atualizar as regras dos setores?', true, $opt)) {
			config_set_path('installedpackages/squidguardgeneral/config/0',
				sqad_sg_geral(config_get_path('installedpackages/squidguardgeneral/config/0', []), $p, $senha));
			write_config('pfSense-Squid-AD: LDAP no SquidGuard');
			// Confere tambem a consulta que o cron vai fazer. Se o AD nao responder
			// por aqui, usa a lista que veio do arquivo e avisa.
			$grupos = $p['Setores'];
			try {
				$grupos = sqad_ad_grupos($p, $p['Conta']['Dn'], $senha, $p['Sync']['BaseOu'], $p['Sync']['Prefixo'], SQAD_CA);
				sqad_msg('ok', 'consulta de grupos no AD funcionando (' . count($grupos) . ' setor(es))');
			} catch (Throwable $e) {
				sqad_msg('aviso', 'a consulta de grupos pelo pfSense falhou (' . $e->getMessage() . '): usando a lista do arquivo. A sincronizacao automatica vai falhar ate isso ser corrigido.');
			}
			[$novas, $mud] = sqad_sincronizar_acls(config_get_path('installedpackages/squidguardacl/config', []) ?: [], $grupos, $p, $p['Sync']['Prefixo']);
			config_set_path('installedpackages/squidguardacl/config', $novas);
			write_config('pfSense-Squid-AD: regras dos setores no SquidGuard');
			require_once(SQAD_SQUIDGUARDINC);
			squidguard_resync();
			foreach ($mud as $m) { sqad_msg('ok', $m); }
			if (!$mud) { sqad_msg('ok', 'as regras dos setores ja existiam.'); }
			if (config_get_path('installedpackages/squidguardgeneral/config/0/squidguard_enable') !== 'on') {
				sqad_msg('aviso', 'o SquidGuard esta DESLIGADO (Services > SquidGuard Proxy Filter > Enable): as regras so valem quando ligar.');
			}

			if (sqad_pergunta('Sincronizar automaticamente com o AD a cada 15 minutos (cron)?', true, $opt)) {
				if (realpath(__FILE__) !== SQAD_SCRIPT_FIXO) { copy(__FILE__, SQAD_SCRIPT_FIXO); chmod(SQAD_SCRIPT_FIXO, 0700); }
				install_cron_job(SQAD_CRON, true, '*/15');
				sqad_msg('ok', 'cron instalado: ' . SQAD_CRON . ' (a cada 15 min). Grupo NET_ novo no AD vira regra sozinho.');
			}
		}
	}

	sqad_msg('passo', 'Pronto');
	sqad_msg('info', 'Os PCs que usam o proxy vao pedir usuario e senha do Windows.');
	sqad_msg('info', 'Acompanhe quem acessa o que:  php ' . basename(__FILE__) . ' relatorio');
	sqad_msg('info', 'Para voltar como estava:    php ' . basename(__FILE__) . ' desfazer');
	return 0;
}

function sqad_cmd_testar(string $usuario): int {
	sqad_carregar_pfsense();
	$estado = json_decode((string)@file_get_contents(SQAD_ESTADO), true);
	$auth = config_get_path('installedpackages/squidauth/config/0', []);
	if (!$estado || ($auth['auth_method'] ?? '') !== 'ldap') { throw new RuntimeException('o login LDAP ainda nao foi aplicado (use "aplicar")'); }
	$p = ['Servidor' => $estado['Servidor'], 'Dominio' => $estado['Dominio'], 'Conta' => ['Dn' => $auth['ldap_user']],
		'Filtro' => $auth['ldap_filter'], 'Atributo' => $auth['ldap_userattribute']];
	[$ok, $resp] = sqad_testar_login($p, $auth['ldap_pass'], $usuario, sqad_ler_texto("Senha de {$usuario}", true));
	if (!$ok) { sqad_msg('aviso', "login de {$usuario} RECUSADO ({$resp})"); return 1; }
	$s = sqad_setores_dos_usuarios($estado, [strtolower($usuario)]);
	sqad_msg('ok', "login de {$usuario} OK - setor(es): " . (empty($s) ? 'SEM SETOR (acessa tudo)' : implode(', ', reset($s))));
	return 0;
}

function sqad_cmd_relatorio(array $opt): int {
	sqad_carregar_pfsense();
	$estado = json_decode((string)@file_get_contents(SQAD_ESTADO), true) ?: [];
	$dias = (int)($opt['dias'] ?? 1);
	$desde = time() - max(1, $dias) * 86400;
	if (!is_readable(SQAD_ACCESSLOG)) { throw new RuntimeException('log de acesso nao encontrado: ' . SQAD_ACCESSLOG . ' (ligue "Enable Access Logging" no Squid)'); }
	$fh = fopen(SQAD_ACCESSLOG, 'r');
	$linhas = (function () use ($fh) { while (($l = fgets($fh)) !== false) { yield $l; } })();
	$agg = sqad_agregar($linhas, $desde, (string)($opt['usuario'] ?? ''));
	fclose($fh);
	$setores = sqad_setores_dos_usuarios($estado, array_keys($agg));
	sqad_msg('passo', "Acessos pelo proxy nos ultimos {$dias} dia(s) - " . count($agg) . ' usuario(s)');
	fwrite(STDOUT, sqad_texto_relatorio($agg, $setores));
	if (!empty($opt['csv'])) {
		$f = fopen($opt['csv'], 'w');
		fputcsv($f, ['usuario', 'setor', 'acessos', 'negados', 'site', 'acessos_no_site'], ';');
		foreach ($agg as $u => $d) {
			$s = implode(', ', $setores[$u] ?? []) ?: 'SEM SETOR';
			foreach ($d['sites'] as $site => $n) { fputcsv($f, [$u, $s, $d['acessos'], $d['negados'], $site, $n], ';'); }
		}
		fclose($f);
		sqad_msg('ok', "CSV (abre no Excel): {$opt['csv']}");
	}
	return 0;
}

function sqad_cmd_status(): int {
	sqad_carregar_pfsense();
	$auth = config_get_path('installedpackages/squidauth/config/0', []);
	$estado = json_decode((string)@file_get_contents(SQAD_ESTADO), true);
	sqad_msg('passo', 'Status');
	sqad_msg('info', 'pfSense:      ' . sqad_versao_pfsense());
	sqad_msg('info', 'autenticacao: ' . ($auth['auth_method'] ?? 'none') . (($auth['auth_method'] ?? '') === 'ldap' ? " ({$auth['ldap_urltype']}://{$auth['auth_server']}:{$auth['auth_server_port']})" : ''));
	sqad_msg('info', 'Squid:        ' . (is_process_running('squid') ? 'rodando' : 'PARADO'));
	sqad_msg('info', 'ldap.conf:    ' . (strpos((string)@file_get_contents(SQAD_LDAPCONF), SQAD_MARCA_INI) !== false ? 'com o bloco do projeto' : 'sem o bloco do projeto'));
	if ($estado) {
		sqad_msg('info', "aplicado em:  {$estado['AplicadoEm']} (backup: {$estado['Backup']})");
		sqad_msg('info', 'setores:      ' . ($estado['Setores'] ? implode(', ', array_column($estado['Setores'], 'Nome')) : 'nenhum'));
		if (!empty($estado['Sync'])) {
			sqad_msg('info', "sincronizacao: grupos {$estado['Sync']['Prefixo']}* em {$estado['Sync']['BaseOu']}");
			sqad_msg('info', 'ultima:       ' . ($estado['UltimaSync'] ?? 'ainda nao rodou') . (isset($estado['UltimaSyncMudancas']) ? " ({$estado['UltimaSyncMudancas']} mudanca(s))" : ''));
			$tem_cron = false;
			foreach (config_get_path('cron/item', []) ?: [] as $c) { if (strpos($c['command'] ?? '', 'squid-ad.php sincronizar') !== false) { $tem_cron = true; } }
			sqad_msg('info', 'cron:         ' . ($tem_cron ? 'a cada 15 min' : 'NAO instalado'));
		}
	} else {
		sqad_msg('info', 'este projeto ainda nao foi aplicado aqui.');
	}
	return 0;
}

function sqad_cmd_desfazer(array $opt): int {
	sqad_carregar_pfsense();
	$estado = json_decode((string)@file_get_contents(SQAD_ESTADO), true);
	if (!$estado || !is_readable($estado['Backup'] ?? '')) { throw new RuntimeException('nao achei o backup do "aplicar" (' . SQAD_ESTADO . ')'); }
	$b = json_decode(file_get_contents($estado['Backup']), true);
	sqad_msg('passo', "Desfazer: voltar a autenticacao do Squid como estava ANTES de {$estado['AplicadoEm']}");
	sqad_msg('info', 'metodo de autenticacao volta para: ' . ($b['squidauth']['auth_method'] ?? 'none'));
	if (!sqad_pergunta('Desfazer agora?', true, $opt)) { return 1; }
	config_set_path('installedpackages/squidauth/config/0', $b['squidauth'] ?: ['auth_method' => 'none']);
	// SquidGuard: tira so as regras criadas pelo projeto e volta o LDAP das General settings
	$sg_mexeu = false;
	$acls = config_get_path('installedpackages/squidguardacl/config', []);
	if (is_array($acls)) {
		$sobra = array_values(array_filter($acls, function ($a) { return sqad_info_acl($a) === null; }));
		if (count($sobra) !== count($acls)) {
			config_set_path('installedpackages/squidguardacl/config', $sobra);
			sqad_msg('ok', (count($acls) - count($sobra)) . ' regra(s) do projeto removida(s) do SquidGuard (as suas ficaram).');
			$sg_mexeu = true;
		}
	}
	if (array_key_exists('squidguardgeneral', $b) && is_array($b['squidguardgeneral'])) {
		config_set_path('installedpackages/squidguardgeneral/config/0', $b['squidguardgeneral']);
		$sg_mexeu = true;
	}
	if (function_exists('install_cron_job')) { install_cron_job(SQAD_CRON, false); }
	write_config('pfSense-Squid-AD: desfeito (autenticacao restaurada)');
	if ($sg_mexeu && file_exists(SQAD_SQUIDGUARDINC)) { require_once(SQAD_SQUIDGUARDINC); squidguard_resync(); }
	file_put_contents(SQAD_LDAPCONF, sqad_bloco_ldapconf((string)@file_get_contents(SQAD_LDAPCONF), null));
	require_once(SQAD_SQUIDINC);
	squid_resync();
	@unlink(SQAD_ESTADO);
	sqad_msg('ok', 'autenticacao restaurada e Squid reiniciado. A CA ficou em ' . SQAD_CA . ' (inofensiva).');
	return 0;
}

/* ======================================================================
 *  main
 * ====================================================================== */

function sqad_opcoes(array $argv): array {
	$o = ['pos' => []];
	for ($i = 1; $i < count($argv); $i++) {
		$a = $argv[$i];
		if ($a === '--sim' || $a === '-y') { $o['sim'] = true; }
		elseif ($a === '--cron') { $o['cron'] = true; $o['sim'] = true; }
		elseif ($a === '--forcar') { $o['forcar'] = true; }
		elseif (preg_match('/^--(dias|usuario|csv)$/', $a, $m)) { $o[$m[1]] = $argv[++$i] ?? ''; }
		else { $o['pos'][] = $a; }
	}
	return $o;
}

function sqad_main(array $argv): int {
	$o = sqad_opcoes($argv);
	$cmd = $o['pos'][0] ?? '';
	if (($o['pos'][0] ?? '') !== 'sincronizar' || empty($o['cron'])) {
		$l = '  ' . str_repeat('=', 72);
		fwrite(STDOUT, "\n{$l}\n   pfSense-Squid-AD " . SQAD_VERSAO . "  -  login do proxy (Squid) no Active Directory\n{$l}\n");
	}
	try {
		switch ($cmd) {
			case 'simular':   return sqad_cmd_aplicar($o['pos'][1] ?? '', $o, true);
			case 'aplicar':   return sqad_cmd_aplicar($o['pos'][1] ?? '', $o, false);
			case 'testar':    return sqad_cmd_testar($o['pos'][1] ?? sqad_ler_texto('Usuario'));
			case 'relatorio': return sqad_cmd_relatorio($o);
			case 'status':    return sqad_cmd_status();
			case 'sincronizar': return sqad_cmd_sincronizar($o);
			case 'desfazer':  return sqad_cmd_desfazer($o);
			default:
				fwrite(STDOUT, "\n  Uso: php squid-ad.php simular|aplicar <arquivo.json> [--sim]\n"
					. "       php squid-ad.php testar <usuario> | relatorio [--dias N] [--usuario X] [--csv arq] | status | desfazer\n"
					. "       php squid-ad.php sincronizar [--forcar]   (o cron roda a cada 15 min)\n");
				return $cmd === '' ? 0 : 2;
		}
	} catch (Throwable $e) {
		sqad_msg('aviso', 'ERRO: ' . $e->getMessage());
		return 1;
	}
}

if (PHP_SAPI === 'cli' && !defined('SQAD_TESTE') && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
	exit(sqad_main($argv));
}
