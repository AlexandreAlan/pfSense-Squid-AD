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
 * Inspecao SSL (fase 2, docs/roadmap.md): bump so no necessario, splice por padrao.
 *   php squid-ad.php ssl-simular                      mostra o que a inspecao SSL vai mudar, NAO muda nada
 *   php squid-ad.php ssl-aplicar [--sim]               cria a CA, liga o SSL bump (splice por padrao)
 *   php squid-ad.php ssl-testar  <usuario>             testa os sites criticos (banco, gov.br...) pelo proxy
 *   php squid-ad.php ssl-status
 *   php squid-ad.php ssl-desfazer [--sim]              desliga a inspecao SSL, volta como estava
 * ssl-aplicar e ssl-desfazer (fora de --sim) pedem a frase digitada "CONFIRMO INSPECAO SSL" antes de
 * mexer em certificado/trafego criptografado. Com --sim, passe --confirmo="CONFIRMO INSPECAO SSL".
 *
 * O <arquivo.json> e gerado pelo Install-SquidAD.ps1 no servidor AD.
 * Nesta versao todo usuario autenticado acessa tudo. Cada setor (grupo NET_ do
 * AD) vira uma regra no SquidGuard (Groups ACL) que LIBERA TUDO; para restringir,
 * edite a regra na tela e escolha as Target categories - a sincronizacao nunca
 * mexe nisso, so na origem (quem e o setor).
 */

const SQAD_VERSAO    = '1.3.0';
const SQAD_MARCA_INI = '# >>> pfSense-Squid-AD (gerado automaticamente - nao edite este bloco) >>>';
const SQAD_MARCA_FIM = '# <<< pfSense-Squid-AD <<<';
const SQAD_PROMPT    = 'Proxy da empresa: use seu usuario e senha do Windows';
const SQAD_MARCA_ACL = 'pfSense-Squid-AD';            // descricao das regras criadas no SquidGuard
const SQAD_APAGADO   = '(grupo apagado no AD)';
const SQAD_VAZIO     = '(grupo sem membros)';
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
	'SQAD_SG_BIN'      => '/usr/local/bin/squidGuard',
	'SQAD_SG_CONF'     => '/usr/local/etc/squidGuard/squidGuard.conf',
] as $c => $v) {
	if (!defined($c)) { define($c, $v); }
}
define('SQAD_ESTADO', SQAD_DIR . '/estado.json');
define('SQAD_CA', SQAD_DIR . '/ca-ad.pem');
define('SQAD_LOCK', SQAD_DIR . '/sincronizar.lock');

/* --- Inspecao SSL (fase 2, docs/roadmap.md) --- */
const SQAD_SSL_CA_DESCR = 'pfSense-Squid-AD SSL Proxy CA';
const SQAD_SSL_CA_DIAS  = 3650;        // 10 anos
const SQAD_SSL_CA_BITS  = 2048;
/* ssl-aplicar e ssl-desfazer mexem em certificado e passam a interceptar trafego
 * criptografado da rede inteira: acesso de admin ao pfSense ja basta para rodar o resto
 * do projeto, mas aqui pedimos essa frase digitada por extenso, de proposito, para nao
 * acontecer por engano (Enter sem querer num terminal, script automatizado errado). */
const SQAD_SSL_FRASE = 'CONFIRMO INSPECAO SSL';
define('SQAD_SSL_ESTADO', SQAD_DIR . '/ssl-estado.json');
define('SQAD_SSL_CA_EXPORT', SQAD_DIR . '/ssl-ca.crt');   // so o certificado publico, para distribuir por GPO
/* Chave SSH remota (Servidor AD -> pfSense): comando forcado, so os subcomandos ssl-* passam,
 * nada mais - mesmo que o shell do pfSense seja root, essa chave so executa o wrapper abaixo. */
define('SQAD_SSL_WRAPPER', '/root/squid-ad-ssl-remoto.sh');

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
		foreach ($p['Setores'] as &$s) {
			if (!isset($s['Membros']) || !is_array($s['Membros'])) { $s['Membros'] = []; }   // arquivo antigo, sem membros
			if (!preg_match('/^[0-9a-f]{32}$/', $s['Guid'] ?? '')) {
				throw new RuntimeException("setor {$s['Nome']} sem o Guid do AD: gere o arquivo de novo com o Install-SquidAD.ps1 1.1");
			}
		}
		unset($s);
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

/*
 * Origem da regra: a LISTA de usuarios do setor, no mesmo formato da tela
 * ('fulano' 'ciclano'). A sincronizacao (cron, 15 min) consulta o AD por LDAPS
 * e reescreve a lista. Por que nao ldapusersearch: o squidGuard 1.4 do pfSense
 * 2.7 nao faz LDAPS (so LDAP sem criptografia) e quebra com senha que tenha
 * certos caracteres - assim ele nem precisa falar com o AD.
 * So entram nomes que o pfSense aceita ([a-zA-Z0-9_.-]); os outros vao em $fora.
 */
function sqad_origem_usuarios(array $membros, ?array &$fora = null): string {
	$ok = [];
	$fora = [];
	foreach ($membros as $m) {
		$m = strtolower(trim((string)$m));
		if ($m === '') { continue; }
		if (preg_match('/^[a-z0-9_.-]+$/', $m)) { $ok[$m] = true; } else { $fora[] = $m; }
	}
	ksort($ok);
	return implode(' ', array_map(function ($u) { return "'{$u}'"; }, array_keys($ok)));
}

/* Usuarios que estao na origem de uma regra ('a' 'b' -> [a, b]). */
function sqad_usuarios_da_origem(string $src): array {
	preg_match_all("/'([^']+)'/", $src, $m);
	return $m[1];
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
 * Sincroniza as regras com os grupos do AD.
 * $grupos = [['Nome','Dn','Guid','Membros' => [sAMAccountName...]], ...]
 * - grupo novo             -> regra nova (libera tudo), origem = membros
 * - membros mudaram        -> atualiza so a origem (destino/horario ficam)
 * - grupo sem membros      -> desativa (um bloco vazio quebraria o squidGuard)
 * - grupo recriado (mesmo nome, GUID novo) -> reaproveita a regra
 * - grupo apagado          -> desativa a regra (nao apaga)
 * Regra desativada pelo ADMIN (sem as marcas do projeto) continua desativada.
 * Regras que nao sao do projeto nunca sao tocadas. Devolve [acls, mudancas];
 * usuarios com nome invalido para o SquidGuard vao em $avisos.
 */
function sqad_sincronizar_acls(array $acls, array $grupos, string $prefixo, ?array &$avisos = null): array {
	$mud = [];
	$avisos = [];
	$usados = array_column($acls, 'name');
	$vistos = [];
	foreach ($grupos as $g) {
		$fora = [];
		$origem = sqad_origem_usuarios($g['Membros'] ?? [], $fora);
		foreach ($fora as $f) { $avisos[] = "usuario '{$f}' (grupo {$g['Nome']}): nome com caractere que o SquidGuard nao aceita - fica fora da regra"; }
		$vazio = ($origem === '');
		$qtd = count(sqad_usuarios_da_origem($origem));
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
			$nova = sqad_acl_nova($nome, $origem, sqad_marca_acl($g['Guid'], $g['Nome']) . ($vazio ? ' ' . SQAD_VAZIO : ''));
			if ($vazio) { $nova['disabled'] = 'on'; }
			$acls[] = $nova;
			$vistos[] = count($acls) - 1;
			$mud[] = "regra {$nome}: CRIADA para o grupo {$g['Nome']} (" . ($vazio ? 'sem membros: fica desativada ate ter alguem' : "{$qtd} usuario(s), libera tudo") . ')';
			continue;
		}
		$vistos[] = $achou;
		$a = &$acls[$achou];
		if (($a['source'] ?? '') !== $origem) {
			if (strpos($a['source'] ?? '', 'ldapusersearch') === 0) {
				$mud[] = "regra {$a['name']}: origem trocada para a lista de usuarios do grupo ({$qtd})";
			} else {
				$antes = sqad_usuarios_da_origem($a['source'] ?? '');
				$depois = sqad_usuarios_da_origem($origem);
				$ent = array_values(array_diff($depois, $antes));
				$sai = array_values(array_diff($antes, $depois));
				$mud[] = "regra {$a['name']}: membros atualizados" . ($ent ? ' | entrou: ' . implode(', ', $ent) : '') . ($sai ? ' | saiu: ' . implode(', ', $sai) : '');
			}
			$a['source'] = $origem;
		}
		$auto = strpos($a['description'] ?? '', SQAD_APAGADO) !== false || strpos($a['description'] ?? '', SQAD_VAZIO) !== false;
		$desc = sqad_marca_acl($g['Guid'], $g['Nome']);
		if ($vazio) {
			if (($a['disabled'] ?? '') !== 'on') {
				$a['disabled'] = 'on';
				$mud[] = "regra {$a['name']}: DESATIVADA (grupo {$g['Nome']} ficou sem membros)";
				$desc .= ' ' . SQAD_VAZIO;
			} elseif ($auto) {
				$desc .= ' ' . SQAD_VAZIO;
			}
		} elseif (($a['disabled'] ?? '') === 'on' && $auto) {
			$motivo = strpos($a['description'] ?? '', SQAD_APAGADO) !== false ? 'voltou no AD' : 'tem membros de novo';
			$a['disabled'] = '';
			$mud[] = "regra {$a['name']}: REATIVADA (grupo {$g['Nome']} {$motivo})";
		}
		$a['description'] = $desc;
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

/*
 * O squidGuard nao precisa mais do LDAP (as regras levam a lista de usuarios).
 * Se uma versao anterior do projeto ligou o LDAP com a conta de servico, desliga
 * - a senha no squidGuard.conf com '!' ou '@' deixava o squidGuard em erro.
 * LDAP configurado pelo admin com outra conta fica como esta.
 */
function sqad_sg_geral(array $atual, array $p): array {
	$n = $atual;
	if (($n['ldapbinddn'] ?? '') === $p['Conta']['Dn']) {
		$n['ldap_enable'] = '';
		$n['ldapbinddn'] = '';
		$n['ldapbindpass'] = '';
	}
	return $n;
}

/*
 * Confere a configuracao com o squidGuard de verdade (o que o Apply gerou). Erro
 * de sintaxe faz o squidGuard entrar em modo de emergencia e liberar TUDO, sem
 * aviso na tela. Devolve null se OK, ou a mensagem de erro.
 */
function sqad_sg_conf_erro(): ?string {
	if (!is_executable(SQAD_SG_BIN) || !is_readable(SQAD_SG_CONF)) { return null; }
	$saida = (string)shell_exec('echo "http://teste.invalid/ 127.0.0.1/- pfsense-squid-ad GET" | '
		. escapeshellarg(SQAD_SG_BIN) . ' -d -c ' . escapeshellarg(SQAD_SG_CONF) . ' 2>&1');
	foreach (explode("\n", $saida) as $l) {
		if (stripos($l, 'syntax error') !== false || stripos($l, 'emergency') !== false) { return trim($l); }
	}
	return null;
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

/* Trava extra para ssl-aplicar/ssl-desfazer: tem que digitar a frase exata, ENTER nao vale
 * como "sim" (diferente de sqad_pergunta). Em --sim, a frase tem que vir em --confirmo=,
 * para automacao continuar possivel sem abrir mao da intencao explicita. */
function sqad_confirmar_ssl(array $opt): void {
	if (!empty($opt['sim'])) {
		if (($opt['confirmo'] ?? '') === SQAD_SSL_FRASE) { return; }
		throw new RuntimeException('--sim exige --confirmo="' . SQAD_SSL_FRASE . '" (exatamente assim) para mexer em certificado/inspecao SSL.');
	}
	fwrite(STDOUT, "\n    Isso muda como o trafego criptografado da rede e tratado. Para confirmar, digite "
		. 'exatamente: ' . SQAD_SSL_FRASE . "\n");
	while (true) {
		fwrite(STDOUT, '    > ');
		$r = fgets(STDIN);
		if ($r === false) { throw new RuntimeException('sem terminal para confirmar: rode por SSH.'); }
		if (trim($r) === SQAD_SSL_FRASE) { return; }
		sqad_msg('aviso', 'nao bateu. Digite exatamente "' . SQAD_SSL_FRASE . '", ou Ctrl+C para cancelar.');
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
		$dn = $e[$i]['distinguishedname'][0];
		// membros ATIVOS do grupo, inclusive por grupo dentro de grupo
		$fm = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=' . sqad_escape_filtro($dn) . ')'
			. '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
		$rm = @ldap_search($l, $p['Dominio']['Base'], $fm, ['sAMAccountName']);
		if (!$rm) { throw new RuntimeException("busca de membros de {$e[$i]['cn'][0]} falhou: " . ldap_error($l)); }
		$em = ldap_get_entries($l, $rm);
		$membros = [];
		for ($j = 0; $j < $em['count']; $j++) { $membros[] = $em[$j]['samaccountname'][0]; }
		$g[] = ['Nome' => $e[$i]['cn'][0], 'Dn' => $dn, 'Guid' => bin2hex($e[$i]['objectguid'][0]), 'Membros' => $membros];
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
		[$novas, $mud] = sqad_sincronizar_acls($acls, $grupos, $estado['Sync']['Prefixo'], $avisos);
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
			if ($erro = sqad_sg_conf_erro()) { sqad_msg('aviso', "o squidGuard recusou a configuracao: {$erro}"); sqad_log("squidGuard recusou a configuracao: {$erro}"); }
		} elseif (!$cron) {
			sqad_msg('ok', 'nada mudou: ' . count($grupos) . ' setor(es) do AD ja estao no SquidGuard.');
		}
		foreach ($avisos as $av) { if (!$cron) { sqad_msg('aviso', $av); } sqad_log($av); }
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
		[, $prev] = sqad_sincronizar_acls(config_get_path('installedpackages/squidguardacl/config', []) ?: [], $p['Setores'], $p['Sync']['Prefixo']);
		fwrite(STDOUT, ($prev ? '  ' . implode("\n  ", $prev) : '  (nada: as regras ja existem)') . "\n");
		sqad_msg('info', 'cada regra recebe a lista de usuarios do grupo; sincronizacao automatica a cada 15 min.');
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
		sqad_msg('passo', 'SquidGuard: uma regra por setor, com os usuarios do grupo (libera tudo)');
		sqad_msg('info', 'Cada regra recebe a lista de usuarios do grupo no AD (atualizada a cada 15 min).');
		sqad_msg('info', 'O squidGuard nao consulta o AD: o do pfSense 2.7 nao faz LDAPS.');
		if (sqad_pergunta('Criar/atualizar as regras dos setores no SquidGuard?', true, $opt)) {
			config_set_path('installedpackages/squidguardgeneral/config/0',
				sqad_sg_geral(config_get_path('installedpackages/squidguardgeneral/config/0', []), $p));
			// Membros vem do AD (a mesma consulta que o cron faz). Se o AD nao
			// responder por aqui, usa a lista que veio do arquivo e avisa.
			$grupos = $p['Setores'];
			$avisos = [];
			try {
				$grupos = sqad_ad_grupos($p, $p['Conta']['Dn'], $senha, $p['Sync']['BaseOu'], $p['Sync']['Prefixo'], SQAD_CA);
				sqad_msg('ok', 'consulta de grupos no AD funcionando (' . count($grupos) . ' setor(es))');
			} catch (Throwable $e) {
				sqad_msg('aviso', 'a consulta de grupos pelo pfSense falhou (' . $e->getMessage() . '): usando a lista do arquivo. A sincronizacao automatica vai falhar ate isso ser corrigido.');
			}
			[$novas, $mud] = sqad_sincronizar_acls(config_get_path('installedpackages/squidguardacl/config', []) ?: [], $grupos, $p['Sync']['Prefixo'], $avisos);
			config_set_path('installedpackages/squidguardacl/config', $novas);
			write_config('pfSense-Squid-AD: regras dos setores no SquidGuard');
			require_once(SQAD_SQUIDGUARDINC);
			squidguard_resync();
			foreach ($mud as $m) { sqad_msg('ok', $m); }
			if (!$mud) { sqad_msg('ok', 'as regras dos setores ja existiam.'); }
			foreach ($avisos as $av) { sqad_msg('aviso', $av); }
			if ($erro = sqad_sg_conf_erro()) {
				sqad_msg('aviso', "o squidGuard RECUSOU a configuracao ({$erro}): ele fica em modo de emergencia e libera tudo. Confira Services > SquidGuard.");
			} else {
				sqad_msg('ok', 'configuracao conferida com o squidGuard: OK');
			}
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
 *  Inspecao SSL (fase 2, docs/roadmap.md)
 *  Bump so no necessario: splice por padrao (sslproxy_mitm_mode=splicewhitelist),
 *  so o que esta na Whitelist passa sem abrir. Nunca aceita certificado com erro.
 * ====================================================================== */

/* Lista padrao do que NUNCA deve ser inspecionado (splice): bancos, governo/ICP-Brasil
 * (login por certificado A1/A3 nao atravessa um proxy que inspeciona), Windows
 * Update/Microsoft e antivirus. Uma linha por dominio; squid_nac aceita regex tambem,
 * mas aqui ficamos com sufixo de dominio simples (mais facil de auditar e manter). */
function sqad_ssl_lista_padrao(): array {
	return [
		// bancos e meios de pagamento
		'bb.com.br', 'caixa.gov.br', 'itau.com.br', 'bradesco.com.br', 'santander.com.br',
		'sicoob.com.br', 'sicredi.com.br', 'nubank.com.br', 'inter.co', 'pagseguro.uol.com.br',
		'mercadopago.com.br', 'picpay.com',
		// governo e certificado digital ICP-Brasil
		'gov.br', 'receita.fazenda.gov.br', 'nfe.fazenda.gov.br', 'esocial.gov.br',
		'conectividade.caixa.gov.br', 'certisign.com.br', 'serasa.com.br', 'soluti.com.br',
		'valid.com.br', 'iti.gov.br',
		// Windows Update, Microsoft 365/Teams, antivirus
		'windowsupdate.com', 'update.microsoft.com', 'microsoft.com', 'office.com',
		'office365.com', 'live.com', 'sfx.ms',
		'avast.com', 'avg.com', 'kaspersky.com', 'eset.com', 'trendmicro.com',
		'mcafee.com', 'symantec.com', 'bitdefender.com',
	];
}

/* Texto da Whitelist do Squid (squid_nac): um dominio por linha, "extras" do cliente
 * no fim (editavel por fora da lista padrao, sem misturar as duas). */
function sqad_ssl_whitelist_texto(array $padrao, array $extras = []): string {
	$linhas = array_values(array_unique(array_merge($padrao, $extras)));
	sort($linhas);
	return implode("\n", $linhas) . "\n";
}

/* Campos que vao para Services > Squid Proxy Server > General (SSL) e > ACLs (Whitelist).
 * interception_checks fica VAZIO de proposito: aceitar erro de certificado ou nao verificar
 * esconderia um ataque man-in-the-middle de verdade - e exatamente o que o proxy tem que
 * barrar. interception_adapt recebe os 3 (imita o certificado original: datas e CN), para
 * o navegador mostrar dados coerentes do site real quando um dominio for mesmo inspecionado. */
function sqad_ssl_campos_squid(string $caref): array {
	return [
		'ssl_proxy'            => 'on',
		'ssl_active_interface' => 'lan',
		'dca'                  => $caref,
		'sslproxy_mitm_mode'   => 'splicewhitelist',
		'interception_checks'  => '',
		'interception_adapt'   => 'setValidAfter,setValidBefore,setCommonName',
	];
}

/* ---------------------------- pfSense ---------------------------------- */

/* Todas as CAs do pfSense (System > Cert. Manager > CAs), para o usuario escolher: este
 * script pode rodar em clientes diferentes, cada um com sua propria pratica de CA (uma ja
 * emitida para outra coisa, nomes proprios, validade proprias). Nunca assumimos uma CA
 * "do projeto" fixa. */
function sqad_ssl_listar_cas(): array {
	return config_get_path('ca', []) ?: [];
}

/* Cria uma CA nova (RSA ou tamanho/validade escolhidos) e adiciona ao Cert. Manager. */
function sqad_ssl_ca_criar(string $nome, int $bits, int $dias): array {
	$dn = ['countryName' => 'BR', 'organizationName' => 'pfSense-Squid-AD', 'commonName' => $nome];
	$ca = ['refid' => uniqid(), 'descr' => $nome];
	if (!ca_create($ca, $bits, $dias, $dn)) {
		throw new RuntimeException('nao consegui gerar a CA (openssl falhou)');
	}
	config_set_path('ca/' . count(config_get_path('ca', []) ?: []), $ca);
	return $ca;
}

/* Pergunta interativa: usar uma CA que ja existe no pfSense, ou criar uma nova (com nome,
 * tamanho de chave e validade escolhidos na hora, sem valor fixo do projeto). Em --sim
 * (sem terminal, ex.: Command Prompt do pfSense) cria uma nova com os valores padrao, para
 * nao escolher uma CA existente sem o usuario ter visto a lista. */
function sqad_ssl_escolher_ca(array $opt): array {
	$cas = sqad_ssl_listar_cas();
	if (!empty($opt['sim'])) {
		sqad_msg('info', '--sim: criando CA nova "' . SQAD_SSL_CA_DESCR . '" (RSA ' . SQAD_SSL_CA_BITS . ' bits, ' . SQAD_SSL_CA_DIAS . ' dias). Para usar uma CA existente, rode sem --sim.');
		return sqad_ssl_ca_criar(SQAD_SSL_CA_DESCR, SQAD_SSL_CA_BITS, SQAD_SSL_CA_DIAS);
	}
	if ($cas) {
		fwrite(STDOUT, "\n    CAs que ja existem neste pfSense (System > Cert. Manager):\n");
		foreach ($cas as $i => $ca) {
			fwrite(STDOUT, sprintf("      %d) %s\n", $i + 1, $ca['descr'] ?? '(sem nome)'));
		}
		fwrite(STDOUT, "      0) criar uma CA nova\n");
		while (true) {
			$r = trim(sqad_ler_texto('Numero da CA a usar (0 para criar nova)'));
			if ($r === '0') { break; }
			if (ctype_digit($r) && isset($cas[(int)$r - 1])) {
				$escolhida = $cas[(int)$r - 1];
				sqad_msg('ok', 'usando a CA existente: ' . ($escolhida['descr'] ?? $escolhida['refid']));
				return $escolhida;
			}
			sqad_msg('aviso', 'numero invalido, tente de novo.');
		}
	} else {
		sqad_msg('info', 'nao ha nenhuma CA ainda neste pfSense; vamos criar uma.');
	}
	$nome = sqad_ler_texto('Nome da nova CA') ?: SQAD_SSL_CA_DESCR;
	if ($nome === '') { $nome = SQAD_SSL_CA_DESCR; }
	$bits = (int)(sqad_ler_texto('Tamanho da chave em bits (ENTER = ' . SQAD_SSL_CA_BITS . ')') ?: SQAD_SSL_CA_BITS);
	$dias = (int)(sqad_ler_texto('Validade em dias (ENTER = ' . SQAD_SSL_CA_DIAS . ', ~' . round(SQAD_SSL_CA_DIAS / 365) . ' anos)') ?: SQAD_SSL_CA_DIAS);
	$ca = sqad_ssl_ca_criar($nome, $bits, $dias);
	sqad_msg('ok', "CA criada: {$nome} (RSA {$bits} bits, {$dias} dias)");
	return $ca;
}

/* So o certificado publico (sem a chave privada) - e isso que vai para a GPO/Firefox,
 * nunca o .pem inteiro. */
function sqad_ssl_ca_exportar(array $ca, string $destino): void {
	$pem = base64_decode($ca['crt']);
	if ($pem === false || $pem === '') { throw new RuntimeException('CA sem certificado para exportar'); }
	file_put_contents($destino, $pem);
	chmod($destino, 0644);   // publico de proposito: e so o certificado, sem segredo
}

function sqad_ssl_backup(array $nac_antes, array $squid_antes): string {
	@mkdir(SQAD_BACKUPS, 0700, true);
	$ts = date('Ymd-His');
	$arq = SQAD_BACKUPS . "/ssl-{$ts}.json";
	file_put_contents($arq, json_encode(['squidnac' => $nac_antes, 'squid_ssl' => $squid_antes], JSON_PRETTY_PRINT));
	chmod($arq, 0600);
	copy(SQAD_CONFIGXML, SQAD_BACKUPS . "/config-ssl-{$ts}.xml");
	return $arq;
}

/* Sites criticos testados de verdade pelo proxy (sem bump, tem que fechar sem erro de
 * certificado) antes de qualquer setor ser ligado. */
function sqad_ssl_sites_teste(): array {
	return [
		'https://www.bb.com.br',
		'https://gov.br',
		'https://www.gov.br',
		'https://cav.receita.fazenda.gov.br',
		'https://www.esocial.gov.br',
		'https://www.microsoft.com',
		'https://login.microsoftonline.com',
	];
}

/* Testa cada site atraves do proxy local (com a autenticacao do usuario informado) e
 * devolve [site => [ok, detalhe]]. ok=true exige HTTP respondido E certificado validado
 * pelo curl (sem -k): e a prova de que o site saiu em splice, com o certificado real. */
function sqad_ssl_testar_sites(string $usuario, string $senha, int $porta, array $sites): array {
	$resultado = [];
	foreach ($sites as $site) {
		$cmd = sprintf(
			'curl -s -o /dev/null -w "%%{http_code} %%{ssl_verify_result}" --max-time 12 -x %s %s 2>&1',
			escapeshellarg(sprintf('http://%s:%s@127.0.0.1:%d', rawurlencode($usuario), rawurlencode($senha), $porta)),
			escapeshellarg($site)
		);
		$saida = trim((string)shell_exec($cmd));
		[$codigo, $verify] = array_pad(explode(' ', $saida), 2, '');
		$ok = ($codigo !== '' && (int)$codigo < 400 && $verify === '0');
		$resultado[$site] = [$ok, $ok ? "HTTP {$codigo}, certificado OK" : "HTTP {$codigo}, ssl_verify_result={$verify}"];
	}
	return $resultado;
}

/* ---------------------------- comandos ---------------------------------- */

function sqad_cmd_ssl_aplicar(array $opt, bool $simular): int {
	sqad_carregar_pfsense();
	$padrao = sqad_ssl_lista_padrao();
	sqad_msg('passo', 'Lista "nunca inspecionar" (splice), ' . count($padrao) . ' dominios');
	sqad_msg('info', 'bancos, gov.br/e-CAC/SEFAZ/eSocial, Windows Update, Microsoft 365, antivirus - ver docs/roadmap.md');

	$nac_antes = config_get_path('installedpackages/squidnac/config/0', []) ?: [];
	$squid_antes_full = config_get_path('installedpackages/squid/config/0', []) ?: [];
	$squid_antes = array_intersect_key($squid_antes_full, sqad_ssl_campos_squid('x'));

	if ($simular) {
		sqad_msg('passo', 'CA do proxy (cada cliente escolhe a sua ao rodar "ssl-aplicar" de verdade)');
		$cas = sqad_ssl_listar_cas();
		if ($cas) {
			sqad_msg('info', 'CAs ja existentes neste pfSense: ' . implode(', ', array_column($cas, 'descr')));
		} else {
			sqad_msg('info', 'nenhuma CA existe ainda; "ssl-aplicar" vai pedir um nome para criar uma.');
		}
		sqad_msg('passo', 'O que "ssl-aplicar" muda em Services > Squid Proxy Server (General e ACLs)');
		$dif = sqad_diferencas($squid_antes, sqad_ssl_campos_squid('<CA escolhida>'));
		fwrite(STDOUT, ($dif ? implode("\n", $dif) : '  (nada: ja esta igual)') . "\n");
		sqad_msg('info', 'modo: splice por padrao, bump so quem NAO esta na Whitelist');
		sqad_msg('info', 'Remote Cert Checks: nenhuma marcada (nunca aceita certificado com erro)');
		sqad_msg('info', 'Certificate Adapt: imita validade e CN do certificado original');
		sqad_msg('info', 'simulacao: nada foi alterado.');
		return 0;
	}

	sqad_msg('passo', 'Inspecao SSL: escolha da CA');
	$ca = sqad_ssl_escolher_ca($opt);

	sqad_msg('passo', 'O que muda em Services > Squid Proxy Server (General e ACLs)');
	$novo_squid = sqad_ssl_campos_squid($ca['refid']);
	$dif = sqad_diferencas($squid_antes, $novo_squid);
	fwrite(STDOUT, ($dif ? implode("\n", $dif) : '  (nada: ja esta igual)') . "\n");
	sqad_msg('info', 'modo: splice por padrao, bump so quem NAO esta na Whitelist');
	sqad_msg('info', 'Remote Cert Checks: nenhuma marcada (nunca aceita certificado com erro)');
	sqad_msg('info', 'Certificate Adapt: imita validade e CN do certificado original');

	if (!sqad_pergunta('Aplicar a inspecao SSL agora?', false, $opt)) { return 1; }

	sqad_confirmar_ssl($opt);

	$backup = sqad_ssl_backup($nac_antes, $squid_antes);
	sqad_msg('ok', "backup: {$backup}");

	sqad_ssl_ca_exportar($ca, SQAD_SSL_CA_EXPORT);
	sqad_msg('ok', 'certificado publico exportado em ' . SQAD_SSL_CA_EXPORT . ' (para a GPO, fase seguinte)');

	config_set_path('installedpackages/squidnac/config/0', array_merge($nac_antes, [
		'whitelist' => base64_encode(sqad_ssl_whitelist_texto($padrao, $nac_antes['whitelist_extra'] ?? [])),
	]));
	config_set_path('installedpackages/squid/config/0', array_merge($squid_antes_full, sqad_ssl_campos_squid($ca['refid'])));
	write_config('pfSense-Squid-AD: inspecao SSL aplicada (splice por padrao)');

	require_once(SQAD_SQUIDINC);
	squid_resync();
	sqad_msg('ok', 'Squid reiniciado com o SSL bump.');

	file_put_contents(SQAD_SSL_ESTADO, json_encode([
		'AplicadoEm' => date('c'),
		'Backup'     => $backup,
		'CaRefid'    => $ca['refid'],
	]));

	sqad_msg('passo', 'Proximo passo: "php squid-ad.php ssl-testar" com um usuario real, ANTES de ligar qualquer GPO.');
	return 0;
}

function sqad_cmd_ssl_testar(array $opt): int {
	sqad_carregar_pfsense();
	$squid = config_get_path('installedpackages/squid/config/0', []) ?: [];
	if (($squid['ssl_proxy'] ?? '') !== 'on') {
		throw new RuntimeException('a inspecao SSL nao esta ligada (rode "ssl-aplicar" primeiro)');
	}
	$porta = (int)($squid['proxy_port'] ?? 3128);
	$usuario = $opt['pos'][1] ?? sqad_ler_texto('Usuario do AD para o teste (precisa valer para o proxy)');
	$senha   = sqad_ler_texto('Senha', true);

	sqad_msg('passo', 'Testando sites criticos pelo proxy (porta ' . $porta . '), sem -k: tem que fechar com certificado valido de verdade');
	$sites = sqad_ssl_sites_teste();
	$res = sqad_ssl_testar_sites($usuario, $senha, $porta, $sites);
	$falhas = 0;
	foreach ($res as $site => [$ok, $detalhe]) {
		sqad_msg($ok ? 'ok' : 'aviso', "{$site}: {$detalhe}");
		if (!$ok) { $falhas++; }
	}
	if ($falhas > 0) {
		sqad_msg('aviso', "{$falhas} site(s) com problema. NAO ligue a GPO em nenhum setor ate corrigir (confira a Whitelist e o DNS do pfSense).");
		return 1;
	}
	sqad_msg('ok', 'todos os sites criticos passaram em splice, com certificado real validado.');
	return 0;
}

function sqad_cmd_ssl_status(): int {
	sqad_carregar_pfsense();
	$squid = config_get_path('installedpackages/squid/config/0', []) ?: [];
	$nac = config_get_path('installedpackages/squidnac/config/0', []) ?: [];
	$estado = json_decode((string)@file_get_contents(SQAD_SSL_ESTADO), true);
	sqad_msg('passo', 'Status: inspecao SSL');
	sqad_msg('info', 'ligada:       ' . (($squid['ssl_proxy'] ?? '') === 'on' ? 'SIM' : 'nao'));
	sqad_msg('info', 'modo:         ' . ($squid['sslproxy_mitm_mode'] ?? '(default)'));
	$ca_nome = '(nenhuma)';
	if (!empty($squid['dca'])) {
		foreach (sqad_ssl_listar_cas() as $ca) {
			if (($ca['refid'] ?? '') === $squid['dca']) { $ca_nome = $ca['descr'] ?? $squid['dca']; break; }
		}
	}
	sqad_msg('info', 'CA em uso:    ' . $ca_nome);
	$wl = trim((string)base64_decode($nac['whitelist'] ?? ''));
	sqad_msg('info', 'whitelist:    ' . ($wl === '' ? '(vazia)' : count(explode("\n", $wl)) . ' dominio(s)'));
	if ($estado) {
		sqad_msg('info', "aplicado em:  {$estado['AplicadoEm']} (backup: {$estado['Backup']})");
	} else {
		sqad_msg('info', 'ainda nao foi aplicado por aqui (sem registro de estado).');
	}
	return 0;
}

function sqad_cmd_ssl_desfazer(array $opt): int {
	sqad_carregar_pfsense();
	$estado = json_decode((string)@file_get_contents(SQAD_SSL_ESTADO), true);
	if (!$estado || !is_readable($estado['Backup'] ?? '')) { throw new RuntimeException('nao achei o backup da inspecao SSL (' . SQAD_SSL_ESTADO . ')'); }
	$b = json_decode(file_get_contents($estado['Backup']), true);
	sqad_msg('passo', "Desfazer inspecao SSL: voltar como estava ANTES de {$estado['AplicadoEm']}");
	sqad_msg('info', 'a CA continua em System > Cert. Manager (inofensiva); remova a mao se nao for mais usar.');
	if (!sqad_pergunta('Desfazer agora?', true, $opt)) { return 1; }

	sqad_confirmar_ssl($opt);

	config_set_path('installedpackages/squidnac/config/0', $b['squidnac'] ?: []);
	$squid_atual = config_get_path('installedpackages/squid/config/0', []) ?: [];
	config_set_path('installedpackages/squid/config/0', array_merge($squid_atual, $b['squid_ssl'] ?: ['ssl_proxy' => '']));
	write_config('pfSense-Squid-AD: inspecao SSL desfeita');

	require_once(SQAD_SQUIDINC);
	squid_resync();
	@unlink(SQAD_SSL_ESTADO);
	sqad_msg('ok', 'inspecao SSL desligada e Squid reiniciado.');
	return 0;
}

/* Conteudo do wrapper que a chave SSH restrita executa: $SSH_ORIGINAL_COMMAND e o comando que o
 * cliente SSH pediu (o OpenSSH sempre preenche essa variavel quando "command=" esta em uso). So
 * passa se for exatamente um dos 5 subcomandos ssl-*, com ou sem os argumentos deles - qualquer
 * outra coisa (outro comando, shell, scp, port-forward) e recusada aqui, mesmo que a chave vaze. */
function sqad_ssl_wrapper_conteudo(): string {
	$php = '/usr/local/bin/php';
	$script = SQAD_SCRIPT_FIXO;
	return "#!/bin/sh\n"
		. "# Gerado por 'squid-ad.php ssl-chave-remota' - nao edite a mao, rode o comando de novo para atualizar.\n"
		. "case \"\$SSH_ORIGINAL_COMMAND\" in\n"
		. "  \"ssl-simular\"|\"ssl-aplicar\"|\"ssl-aplicar --sim --confirmo=" . SQAD_SSL_FRASE . "\"|\"ssl-testar \"*|\"ssl-status\"|\"ssl-desfazer\"|\"ssl-desfazer --sim --confirmo=" . SQAD_SSL_FRASE . "\")\n"
		. "    exec {$php} {$script} \$SSH_ORIGINAL_COMMAND\n"
		. "    ;;\n"
		. "  *)\n"
		. "    echo 'bloqueado: essa chave so roda os comandos ssl-* deste projeto.' >&2\n"
		. "    exit 1\n"
		. "    ;;\n"
		. "esac\n";
}

function sqad_ssl_cmd_chave_remota(array $opt): int {
	sqad_carregar_pfsense();
	$usuario = $opt['pos'][1] ?? '';
	$arquivo = $opt['pos'][2] ?? '';
	if ($usuario === '' || $arquivo === '') {
		throw new RuntimeException('uso: ssl-chave-remota <usuario-do-pfsense> <arquivo-com-a-chave-publica.pub>');
	}
	if (!is_readable($arquivo)) { throw new RuntimeException("nao consegui ler {$arquivo}"); }
	$chave = trim((string)file_get_contents($arquivo));
	if (!preg_match('/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+\S+/', $chave)) {
		throw new RuntimeException('isso nao parece uma chave PUBLICA ssh (comeca com ssh-ed25519/ssh-rsa/ecdsa-...). Confira se nao mandou a chave PRIVADA por engano.');
	}

	$usuarios = config_get_path('system/user', []) ?: [];
	$idx = null;
	foreach ($usuarios as $i => $u) { if (($u['name'] ?? '') === $usuario) { $idx = $i; break; } }
	if ($idx === null) { throw new RuntimeException("usuario \"{$usuario}\" nao existe no pfSense (System > User Manager)."); }

	sqad_msg('passo', "Instalar chave SSH restrita para o usuario \"{$usuario}\" (so roda ssl-simular/ssl-aplicar/ssl-testar/ssl-status/ssl-desfazer)");
	sqad_msg('info', 'nenhum outro comando passa por essa chave, mesmo que o shell do pfSense seja root.');
	if (!sqad_pergunta('Instalar agora?', true, $opt)) { return 1; }

	@mkdir(SQAD_BACKUPS, 0700, true);
	copy(SQAD_CONFIGXML, SQAD_BACKUPS . '/config-ssl-chave-' . date('Ymd-His') . '.xml');

	file_put_contents(SQAD_SSL_WRAPPER, sqad_ssl_wrapper_conteudo());
	chmod(SQAD_SSL_WRAPPER, 0700);

	$linha = 'command="' . SQAD_SSL_WRAPPER . '",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ' . $chave;
	$existentes = array_filter(explode("\n", base64_decode($usuarios[$idx]['authorizedkeys'] ?? '')));
	$chave_ja_tinha = false;
	foreach ($existentes as $l) { if (str_contains($l, $chave)) { $chave_ja_tinha = true; break; } }
	if (!$chave_ja_tinha) { $existentes[] = $linha; }
	config_set_path("system/user/{$idx}/authorizedkeys", base64_encode(implode("\n", $existentes) . "\n"));
	write_config('pfSense-Squid-AD: chave SSH restrita para inspecao SSL remota (Servidor AD)');

	sqad_msg('ok', $chave_ja_tinha ? 'chave ja estava instalada; wrapper atualizado.' : 'chave instalada.');
	sqad_msg('info', 'proximo passo (uma vez so): restrinja o acesso SSH desse usuario a rede interna '
		. '(System > Advanced > Admin Access > "SSH" / regra de firewall), nunca deixe aberto na WAN.');
	sqad_msg('info', 'do Servidor AD, teste com: ssh -i <chave-privada> ' . $usuario . '@<ip-do-pfsense> ssl-status');
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
		elseif (preg_match('/^--(dias|usuario|csv|confirmo)$/', $a, $m)) { $o[$m[1]] = $argv[++$i] ?? ''; }
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
			case 'ssl-simular': return sqad_cmd_ssl_aplicar($o, true);
			case 'ssl-aplicar': return sqad_cmd_ssl_aplicar($o, false);
			case 'ssl-testar':  return sqad_cmd_ssl_testar($o);
			case 'ssl-status':  return sqad_cmd_ssl_status();
			case 'ssl-desfazer': return sqad_cmd_ssl_desfazer($o);
			case 'ssl-chave-remota': return sqad_ssl_cmd_chave_remota($o);
			default:
				fwrite(STDOUT, "\n  Uso: php squid-ad.php simular|aplicar <arquivo.json> [--sim]\n"
					. "       php squid-ad.php testar <usuario> | relatorio [--dias N] [--usuario X] [--csv arq] | status | desfazer\n"
					. "       php squid-ad.php sincronizar [--forcar]   (o cron roda a cada 15 min)\n"
					. "       php squid-ad.php ssl-simular | ssl-aplicar [--sim] | ssl-testar <usuario> | ssl-status | ssl-desfazer\n"
					. "       php squid-ad.php ssl-chave-remota <usuario-pfsense> <chave-publica.pub>   (acesso remoto do Servidor AD)\n");
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
