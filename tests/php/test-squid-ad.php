<?php
/*
 * Testes do pfsense/squid-ad.php sem um pfSense de verdade:
 *  - funcoes puras (pacote, campos, ldap.conf, log, relatorio)
 *  - fluxo completo: simular -> aplicar -> reaplicar -> senha errada ->
 *    relatorio -> status -> desfazer, com o config.xml simulado em memoria,
 *    caminhos numa pasta temporaria e o basic_ldap_auth falso.
 * Uso: php test-squid-ad.php <pacote.json gerado pelo Test-AD.ps1> <pasta temporaria>
 */
$pacote = $argv[1] ?? '';
$W = rtrim($argv[2] ?? sys_get_temp_dir() . '/sqad-teste', '/');
@mkdir($W, 0700, true);

define('SQAD_TESTE', true);
define('SQAD_DIR',         "$W/etc-squid-ad");
define('SQAD_BACKUPS',     "$W/backups");
define('SQAD_LDAPCONF',    "$W/openldap/ldap.conf");
define('SQAD_HELPER',      __DIR__ . '/fake_basic_ldap_auth.sh');
define('SQAD_SQUIDCONF',   "$W/squid.conf");
define('SQAD_SQUIDINC',    "$W/squid.inc");
define('SQAD_ACCESSLOG',   "$W/access.log");
define('SQAD_CONFIGXML',   "$W/config.xml");
define('SQAD_VERSIONFILE', "$W/version");

/* ---------------- pfSense simulado ---------------- */
$GLOBALS['cfg'] = [];
$GLOBALS['resyncs'] = 0;
$GLOBALS['writes'] = [];
function config_get_path(string $path, $default = null) {
	$a = $GLOBALS['cfg'];
	foreach (explode('/', $path) as $k) { if (!is_array($a) || !array_key_exists($k, $a)) { return $default; } $a = $a[$k]; }
	return $a;
}
function config_set_path(string $path, $value, $default = null) {
	$a = &$GLOBALS['cfg'];
	foreach (explode('/', $path) as $k) { if (!isset($a[$k]) || !is_array($a[$k])) { $a[$k] = []; } $a = &$a[$k]; }
	$a = $value;
	return $value;
}
function config_path_enabled(string $path, $enable_key = 'enable') { return config_get_path("$path/$enable_key") !== null; }
function write_config($desc = '') { $GLOBALS['writes'][] = $desc; }
function is_process_running($p) { return true; }
function services_unbound_configure() { $GLOBALS['unbound'] = ($GLOBALS['unbound'] ?? 0) + 1; }
file_put_contents(SQAD_SQUIDINC, '<?php function squid_resync() { $GLOBALS["resyncs"]++; $a = config_get_path("installedpackages/squidauth/config/0", []);'
	. ' file_put_contents(SQAD_SQUIDCONF, ($a["auth_method"] ?? "") === "ldap" ? "auth_param basic program /x/basic_ldap_auth -H ldaps://{$a["auth_server"]}\n" : "# sem auth\n"); }');
file_put_contents(SQAD_VERSIONFILE, "2.7.0-RELEASE\n");
file_put_contents(SQAD_CONFIGXML, "<pfsense><version>23.3</version></pfsense>\n");
@mkdir(dirname(SQAD_LDAPCONF), 0755, true);
file_put_contents(SQAD_LDAPCONF, "# ldap.conf de antes\nBASE dc=antigo\n");
// o "squid.inc" real e testado por existencia no verificar ambiente:
$GLOBALS['cfg']['installedpackages']['squid']['config'][0] = ['enable_squid' => 'on', 'proxy_port' => '3128'];
$AUTH_ANTES = ['auth_method' => 'none', 'no_auth_hosts' => base64_encode("172.16.10.5/32"), 'max_user_ip' => '2'];
$GLOBALS['cfg']['installedpackages']['squidauth']['config'][0] = $AUTH_ANTES;
$GLOBALS['cfg']['unbound']['enable'] = '';

require __DIR__ . '/../../pfsense/squid-ad.php';

/* ---------------- mini framework ---------------- */
$falhas = 0;
function cenario(string $nome, callable $f) {
	global $falhas;
	ob_start();
	try { $r = $f(); ob_end_clean(); fwrite(STDERR, "  [PASSOU] {$nome}" . ($r ? " {$r}" : '') . "\n"); }
	catch (Throwable $e) { ob_end_clean(); $falhas++; fwrite(STDERR, "  [FALHOU] {$nome} -> " . $e->getMessage() . "\n"); }
}
function confere($cond, string $msg) { if (!$cond) { throw new Exception($msg); } }

$PAC = json_decode(file_get_contents($pacote), true);
$SVC_SENHA = $PAC['Conta']['Senha'];
putenv('SQAD_FAKE_SVC_SENHA=' . $SVC_SENHA);
putenv('SQAD_FAKE_CONTAS=' . json_encode([$PAC['Conta']['Usuario'] => $SVC_SENHA, 'joao.silva' => 'Senh@ "dificil" \\ c$o:`']));

fwrite(STDERR, "1) Pacote vindo do AD (contrato com o Install-SquidAD.ps1)\n");
cenario('o JSON do PowerShell e aceito', function () use ($pacote) {
	$p = sqad_ler_pacote($pacote);
	confere(count($p['Setores']) === 2, 'setores');
	confere($p['Servidor']['Transporte'] === 'ssl', 'transporte');
	return '(' . implode(', ', array_column($p['Setores'], 'Nome')) . ')';
});
cenario('BOM do Windows no inicio do arquivo e ignorado', function () use ($pacote, $W) {
	file_put_contents("$W/bom.json", "\xEF\xBB\xBF" . file_get_contents($pacote));
	sqad_ler_pacote("$W/bom.json");
});
cenario('arquivo de outro projeto e recusado', function () use ($W) {
	file_put_contents("$W/outro.json", json_encode(['Projeto' => 'x']));
	try { sqad_ler_pacote("$W/outro.json"); } catch (RuntimeException $e) { return; }
	throw new Exception('deveria recusar');
});
cenario('LDAPS sem a CA e recusado', function () use ($pacote, $W) {
	$p = json_decode(file_get_contents($pacote), true); $p['CaPem'] = '';
	file_put_contents("$W/semca.json", json_encode($p));
	try { sqad_ler_pacote("$W/semca.json"); } catch (RuntimeException $e) { return; }
	throw new Exception('deveria recusar');
});

fwrite(STDERR, "2) Campos do Squid e ldap.conf\n");
cenario('campos LDAP preenchidos e o resto preservado', function () use ($PAC, $AUTH_ANTES) {
	$n = sqad_campos_auth($PAC, $AUTH_ANTES, 'x');
	confere($n['auth_method'] === 'ldap' && $n['ldap_urltype'] === 'ssl' && $n['auth_server_port'] === '636', 'ldap');
	confere($n['ldap_version'] === '3' && $n['ldap_userattribute'] === 'sAMAccountName', 'versao/atributo');
	confere($n['no_auth_hosts'] === $AUTH_ANTES['no_auth_hosts'] && $n['max_user_ip'] === '2', 'preservou o resto');
	confere($n['auth_prompt'] === SQAD_PROMPT, 'prompt');
});
cenario('bloco do ldap.conf: entra, troca sem duplicar, sai sem estragar o resto', function () {
	$orig = "# meu\nBASE dc=x\n";
	$a = sqad_bloco_ldapconf($orig, '/ca1.pem');
	$b = sqad_bloco_ldapconf($a, '/ca2.pem');
	confere(substr_count($b, SQAD_MARCA_INI) === 1 && strpos($b, '/ca2.pem') !== false && strpos($b, '/ca1.pem') === false, 'troca');
	confere(strpos($b, "BASE dc=x") !== false, 'preserva');
	confere(sqad_bloco_ldapconf($b, null) === $orig, 'remove e volta igual: ' . json_encode(sqad_bloco_ldapconf($b, null)));
});
cenario('argumentos do helper iguais aos do pacote Squid, senha por arquivo', function () use ($PAC) {
	$a = sqad_args_helper($PAC, '/tmp/s');
	confere(in_array('-W', $a, true) && !in_array('-w', $a, true), 'senha por -W');
	confere($a[array_search('-H', $a) + 1] === 'ldaps://localhost:636', 'URL');
});

fwrite(STDERR, "3) Log do Squid e relatorio\n");
$LOG = [
	'1793100000.100   45 172.16.30.10 TCP_TUNNEL/200 3920 CONNECT www.bb.com.br:443 joao.silva HIER_DIRECT/1.2.3.4 -',
	'1793100001.100   45 172.16.30.10 TCP_TUNNEL/200 1000 CONNECT cdn.bb.com.br:443 joao.silva HIER_DIRECT/1.2.3.4 -',
	'1793100002.100   12 172.16.30.11 TCP_MISS/200 500 GET http://g1.globo.com/x maria.souza HIER_DIRECT/1.2.3.5 text/html',
	'1793100003.100    1 172.16.30.12 TCP_DENIED/407 3800 CONNECT www.google.com:443 - HIER_NONE/- text/html',
	'1793100004.100    5 172.16.30.13 TCP_MISS/200 900 GET http://windowsupdate.microsoft.com/a - HIER_DIRECT/1.2.3.6 -',
	'lixo que nao e linha de log',
];
cenario('linhas de log viram usuario + site', function () use ($LOG) {
	$r = sqad_parse_linha($LOG[0]);
	confere($r['usuario'] === 'joao.silva' && $r['site'] === 'bb.com.br', json_encode($r));
	confere(sqad_parse_linha($LOG[5]) === null, 'lixo');
	confere(sqad_site_base('a.b.receita.fazenda.gov.br') === 'fazenda.gov.br', 'gov.br');
	confere(sqad_site_base('mail.google.com') === 'google.com', 'com');
});
cenario('agregacao ignora pedidos de senha (407) e separa quem nao logou', function () use ($LOG) {
	$a = sqad_agregar($LOG);
	confere($a['joao.silva']['acessos'] === 2 && $a['joao.silva']['sites'] === ['bb.com.br' => 2], 'joao');
	confere(isset($a['(sem login) 172.16.30.13']) && !isset($a['(sem login) 172.16.30.12']), 'sem login / 407');
});
cenario('relatorio destaca quem esta SEM SETOR acessando tudo', function () use ($LOG) {
	$t = sqad_texto_relatorio(sqad_agregar($LOG), ['joao.silva' => ['SETOR-FINANCEIRO']]);
	confere(strpos($t, 'SETOR-FINANCEIRO') !== false, 'setor do joao');
	confere(preg_match('/maria\.souza\s+SEM SETOR - acessando tudo/', $t) === 1, 'maria sem setor');
	confere(strpos($t, "1 usuario(s) SEM SETOR acessando tudo: maria.souza") !== false, 'resumo');
});

fwrite(STDERR, "4) Fluxo completo no pfSense simulado\n");
cenario('simular nao muda nada', function () use ($pacote, $AUTH_ANTES) {
	$rc = sqad_cmd_aplicar($pacote, ['sim' => true], true);
	confere($rc === 0, "retorno $rc");
	confere(config_get_path('installedpackages/squidauth/config/0') === $AUTH_ANTES, 'mudou a config');
	confere(!is_dir(SQAD_BACKUPS) && $GLOBALS['resyncs'] === 0, 'criou backup ou reiniciou');
});
cenario('aplicar --sim: backup, CA, teste do helper, config e Squid reiniciado', function () use ($pacote, $PAC, $AUTH_ANTES) {
	$rc = sqad_cmd_aplicar($pacote, ['sim' => true], false);
	confere($rc === 0, "retorno $rc");
	$a = config_get_path('installedpackages/squidauth/config/0');
	confere($a['auth_method'] === 'ldap' && $a['ldap_pass'] === $PAC['Conta']['Senha'], 'config');
	confere($a['no_auth_hosts'] === $AUTH_ANTES['no_auth_hosts'], 'preservou no_auth_hosts');
	confere(file_get_contents(SQAD_CA) === $PAC['CaPem'], 'CA');
	$l = file_get_contents(SQAD_LDAPCONF);
	confere(strpos($l, 'TLS_CACERT ' . SQAD_CA) !== false && strpos($l, 'BASE dc=antigo') !== false, 'ldap.conf');
	confere(count(glob(SQAD_BACKUPS . '/config-*.xml')) === 1 && count(glob(SQAD_BACKUPS . '/squidauth-*.json')) === 1, 'backups');
	confere($GLOBALS['resyncs'] === 1 && strpos(file_get_contents(SQAD_SQUIDCONF), 'basic_ldap_auth') !== false, 'resync');
	confere(is_readable(SQAD_ESTADO), 'estado');
});
cenario('aplicar de novo nao duplica o bloco do ldap.conf', function () use ($pacote) {
	sleep(1);   // backup com outro nome
	sqad_cmd_aplicar($pacote, ['sim' => true], false);
	confere(substr_count(file_get_contents(SQAD_LDAPCONF), SQAD_MARCA_INI) === 1, 'duplicou');
});
cenario('senha errada da conta: o AD recusa e o Squid NAO e alterado', function () use ($pacote, $W) {
	$p = json_decode(file_get_contents($pacote), true); $p['Conta']['Senha'] = 'errada';
	file_put_contents("$W/errada.json", json_encode($p));
	$antes = config_get_path('installedpackages/squidauth/config/0');
	$r0 = $GLOBALS['resyncs'];
	$rc = sqad_main(['squid-ad.php', 'aplicar', "$W/errada.json", '--sim']);
	confere($rc === 1, "retorno $rc");
	confere(config_get_path('installedpackages/squidauth/config/0') === $antes && $GLOBALS['resyncs'] === $r0, 'alterou mesmo com erro');
});
cenario('relatorio roda em cima do access.log', function () use ($LOG) {
	file_put_contents(SQAD_ACCESSLOG, implode("\n", $LOG) . "\n");
	confere(sqad_cmd_relatorio(['dias' => 100000, 'csv' => SQAD_DIR . '/r.csv']) === 0, 'retorno');
	confere(preg_match('/maria\.souza;"?SEM SETOR/', file_get_contents(SQAD_DIR . '/r.csv')) === 1, 'csv');
});
cenario('status roda', function () { confere(sqad_cmd_status() === 0, 'retorno'); });
cenario('desfazer --sim volta tudo como era', function () use ($AUTH_ANTES) {
	$rc = sqad_cmd_desfazer(['sim' => true]);
	confere($rc === 0, "retorno $rc");
	confere(config_get_path('installedpackages/squidauth/config/0') === $AUTH_ANTES, 'squidauth: ' . json_encode(config_get_path('installedpackages/squidauth/config/0')));
	confere(file_get_contents(SQAD_LDAPCONF) === "# ldap.conf de antes\nBASE dc=antigo\n", 'ldap.conf: ' . json_encode(file_get_contents(SQAD_LDAPCONF)));
	confere(!file_exists(SQAD_ESTADO), 'estado');
});
cenario('Host Override no formato da tela do pfSense', function () use ($PAC) {
	$GLOBALS['cfg']['unbound'] = ['enable' => ''];
	$onde = sqad_host_override(['Servidor' => ['Host' => 'srv-ad.teste.local', 'Ip' => '172.16.10.5']]);
	$h = config_get_path('unbound/hosts')[0];
	confere($onde === 'DNS Resolver (unbound)' && $h['host'] === 'srv-ad' && $h['domain'] === 'teste.local' && $h['ip'] === '172.16.10.5', json_encode($h));
	confere($h['aliases'] === ['item' => []] && $GLOBALS['unbound'] === 1, 'aliases/reload');
});
cenario('sem terminal e sem --sim: para em vez de assumir resposta', function () use ($pacote) {
	$rc = sqad_main(['squid-ad.php', 'aplicar', $pacote]);
	confere($rc === 1, "retorno $rc");
});

if ($falhas) { fwrite(STDERR, "RESULTADO PHP: {$falhas} cenario(s) FALHARAM\n"); exit(1); }
fwrite(STDERR, "RESULTADO PHP: todos os cenarios passaram\n");
