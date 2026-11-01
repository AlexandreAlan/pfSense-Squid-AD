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
| Script do AD | leitura do certificado LDAPS (nome, curinga, nome errado, porta fechada), PEM validado pelo `openssl`, senha gerada, escape de filtro LDAP, perguntas S/N, arquivo `.json` |
| Contrato | o `.json` gerado pelo PowerShell é lido pelo PHP |
| Script do pfSense | simular não muda nada; aplicar faz backup, CA, teste e config; reaplicar não duplica; senha errada não altera o Squid; relatório e CSV; status; desfazer volta tudo; Host Override; sem terminal não assume resposta |

**Não cobertos** (dependem de um AD e de um pfSense reais): o LDAPS do Windows de verdade, o `basic_ldap_auth` real e o `squid_resync()` real. Por isso o `aplicar` sempre testa com o helper real antes de mudar o Squid.

## Próximos passos (roadmap)

- **v2 — restrição por setor (SquidGuard):** gerar as linhas `ldapusersearch` de cada setor para o *Groups ACL* e preencher o LDAP das *General Settings* do SquidGuard.
- Relatório agendado (diário, por e-mail).
