# Desenvolvimento e testes

[← README](../README.md)

## Estrutura

```
Install-SquidAD.ps1          servidor AD: dominio, DC, LDAPS, setores, conta, GPO, arquivo .json
pfsense/squid-ad.php         pfSense 2.7: simular/aplicar/testar/relatorio/status/desfazer
docs/                        documentacao
tests/run-testes.sh          roda tudo
tests/Test-Sintaxe.ps1       parser do PowerShell (5.1 no CI), ASCII, PSScriptAnalyzer
tests/Test-AD.ps1            funcoes do script do AD contra um servidor TLS local
tests/php/test-squid-ad.php  fluxo do script do pfSense com o pfSense simulado
tests/php/fake_basic_ldap_auth.*  helper LDAP falso que confere os argumentos
```

## Como o script do pfSense aplica a configuração

O pacote Squid do pfSense 2.7 guarda a autenticação em `installedpackages/squidauth/config/0` e monta a linha do `basic_ldap_auth` em `squid_resync_auth()` ([código do pacote](https://github.com/pfsense/FreeBSD-ports/blob/RELENG_2_7_0/www/pfSense-pkg-squid/files/usr/local/pkg/squid.inc)). O `squid-ad.php`:

- escreve **os mesmos campos** que a tela grava (`auth_method`, `auth_server`, `ldap_urltype`, `ldap_filter`...);
- chama `write_config()` e `squid_resync()`, como o botão *Save*;
- testa com o **mesmo helper e os mesmos argumentos** antes de aplicar. A senha vai por arquivo (`-W`), não na linha de comando.

## Convenções

- **ASCII puro** no `.ps1` e no `.php` (o PS 5.1 lê `.ps1` sem BOM como ANSI).
- **PowerShell 5.1** no AD; **PHP 8.2** do pfSense 2.7 (os testes rodam em 8.1+).
- **Nunca `"$variavel:"`** em string do PowerShell: use `"${variavel}:"`.
- Toda mudança pergunta antes; o padrão aparece entre colchetes.
- Caminhos do pfSense ficam no topo do `squid-ad.php` e podem ser redefinidos pelos testes.

## Testes

```bash
bash tests/run-testes.sh      # precisa de pwsh, php (com ldap) e openssl
```

| O que | Cenários |
|---|---|
| Script do AD | leitura do certificado LDAPS (nome, curinga, nome errado, porta fechada, GUID do objeto no SAN), PEM validado pelo `openssl`, senha gerada, escape de filtro LDAP, perguntas S/N, IPs do controlador, nome do setor sem acento, GUID no formato do LDAP, espelhamento de membros e o `Sync-SetoresAD` inteiro contra um **AD simulado** (criar, mover usuário, exceção manual, OU nova), arquivo `.json` |
| Contrato | o `.json` gerado pelo PowerShell é lido pelo PHP |
| Script do pfSense | simular não muda nada; aplicar faz backup, CA, teste, config, SquidGuard e cron; reaplicar não duplica; senha errada não altera o Squid; nome da regra (16 caracteres); lista de usuários no formato que o pfSense valida; sincronização (criar, membros mudaram, vazio desativa/reativa, desativada pelo admin fica, apagar, recriar, preservar restrições); conferência com o squidGuard (squidGuard falso que acusa erro); AD fora do ar não muda nada; zero grupos para; relatório e CSV; desfazer volta tudo e mantém as regras manuais |

Além dos testes automáticos, as decisões sobre o squidGuard foram **provadas no squidGuard 1.4 real** do pfSense 2.7.0, com cópias da configuração em `/tmp`: caracteres aceitos na senha, falta de LDAPS, formato `user` aceito, membro bloqueado e não membro liberado, maiúsculas indiferentes.

**Não cobertos** (dependem de um AD e de um pfSense reais): o LDAPS do Windows de verdade, o `basic_ldap_auth` real e o `squid_resync()` real. Por isso o `aplicar` sempre testa com o helper real antes de mudar o Squid.

Os testes também passam por **prova de mutação**: cada comportamento crítico é estragado de propósito numa cópia e o teste correspondente tem que reprovar.

## Próximos passos (roadmap)

- Relatório agendado (diário, por e-mail).
- Assistente para montar as restrições por setor (sugestão de *Target categories* a partir do relatório).
