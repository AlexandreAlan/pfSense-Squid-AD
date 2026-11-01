<?php
/*
 * basic_ldap_auth FALSO para os testes. Faz o que o original faz com a entrada
 * e confere os argumentos que o squid-ad.php monta:
 *   - le "usuario senha" por linha, decodificados como URL (rfc1738_unescape)
 *   - exige -W <arquivo> com a senha da conta de servico (nunca -w na linha)
 *   - exige -H ldaps://... e -f com %s
 * Responde OK / ERR como o helper real.
 * Contas validas: variavel SQAD_FAKE_CONTAS = JSON {"usuario": "senha"}.
 */
$args = $argv; array_shift($args);
$opt = [];
for ($i = 0; $i < count($args); $i++) {
	if ($args[$i][0] === '-' && strlen($args[$i]) === 2) {
		$tem_valor = !in_array($args[$i], ['-R', '-P', '-Z'], true);
		$opt[$args[$i]] = $tem_valor ? ($args[++$i] ?? '') : true;
	}
}
$problema = '';
if (isset($opt['-w'])) { $problema = 'senha na linha de comando (-w)'; }
if (empty($opt['-W']) || !is_readable($opt['-W'])) { $problema = 'sem -W <arquivo de senha>'; }
if (strpos($opt['-f'] ?? '', '%s') === false) { $problema = 'filtro sem %s'; }
if (!preg_match('#^ldaps?://[^/]+:\d+$#', $opt['-H'] ?? '')) { $problema = 'URL -H invalida: ' . ($opt['-H'] ?? ''); }
if (($opt['-v'] ?? '') !== '3') { $problema = 'precisa -v 3'; }

$contas = json_decode(getenv('SQAD_FAKE_CONTAS') ?: '{}', true);
$senha_conta = isset($opt['-W']) && is_readable($opt['-W']) ? trim(file_get_contents($opt['-W'])) : '';
$svc = getenv('SQAD_FAKE_SVC_SENHA') ?: '';
while (($l = fgets(STDIN)) !== false) {
	[$u, $p] = array_pad(explode(' ', rtrim($l, "\r\n"), 2), 2, '');
	$u = rawurldecode($u); $p = rawurldecode($p);
	if ($problema !== '')             { echo "ERR {$problema}\n"; continue; }
	if ($svc !== '' && $senha_conta !== $svc) { echo "ERR bind da conta de servico recusado\n"; continue; }
	echo (isset($contas[$u]) && $contas[$u] === $p) ? "OK\n" : "ERR Success\n";
}
