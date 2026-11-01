# Problemas comuns

[← README](../README.md) · [Conceitos](conceitos.md) · [AD](ad.md) · [pfSense](pfsense.md) · [Relatório](relatorio.md)

## No AD (`Install-SquidAD.ps1`)

| Mensagem | Causa provável | O que fazer |
|---|---|---|
| `Modulo ActiveDirectory nao encontrado` | Rodando fora do DC, sem RSAT | Rodar no controlador de domínio |
| `LDAPS nao respondeu` | O DC não tem certificado de servidor | [Habilitar o LDAPS](ad.md#ldaps-se-o-controlador-não-tiver-certificado) |
| `o certificado NAO tem o nome ...` | Certificado emitido para outro nome | Reemitir o certificado do DC com o nome completo (FQDN) |
| `o teste de LDAP falhou` | Senha da conta, porta ou certificado | Rodar de novo e gerar senha nova para a conta |
| `o usuario ... nao foi encontrado` | Usuário desativado ou nome errado | Usar o `sAMAccountName` (ex.: `joao.silva`) |

## No pfSense (`squid-ad.php`)

| Mensagem | Causa provável | O que fazer |
|---|---|---|
| `o pacote Squid nao esta instalado/configurado` | Squid não instalado, ou nunca salvo | Instalar e salvar *Services › Squid Proxy Server* uma vez |
| `o pfSense NAO resolve <nome do DC>` | O DNS do pfSense não conhece o domínio do AD | Responder **S** para criar o Host Override, ou criar um *Domain Override* do domínio apontando para o DC |
| `o AD recusou a conta de servico` | Senha, DNS, firewall ou CA | Ver a mensagem entre parênteses. O Squid **não** foi alterado |
| `sem terminal para responder` | Rodou na tela Command Prompt sem `--sim` | Usar `simular` e depois `aplicar ... --sim`, ou rodar por SSH |
| `o modo TRANSPARENTE esta ligado` | O proxy está transparente | O login só vale para PCs com o proxy configurado |
| `o Squid esta DESLIGADO` | *Enable Squid Proxy* desmarcado | Ligar em *Services › Squid Proxy Server* |

## Sincronização

| Mensagem | Causa provável | O que fazer |
|---|---|---|
| `sincronizacao falhou (nada foi alterado)` | O pfSense não alcançou o AD (rede, DC desligado, senha da conta trocada) | Nada se perdeu. Ver a mensagem; `php /root/squid-ad.php sincronizar` para testar |
| `o AD devolveu 0 grupos NET_*` | Prefixo trocado, OU da empresa renomeada ou grupos apagados | Conferir no AD. Se for intencional: `sincronizar --forcar` |
| Evento **2001** no AD | A tarefa agendada falhou | Ver `C:\ProgramData\pfSense-Squid-AD\sincronizacao.log` |
| Pessoa saiu do grupo sem querer | O espelhamento tirou quem não está na OU | Mover a pessoa para a OU certa, ou usar `[proxy-manual]` na descrição dela |
| Regra do setor não aparece no SquidGuard | Sincronização ainda não rodou | Esperar 15 min ou rodar `sincronizar` |
| `o squidGuard RECUSOU a configuracao` | Erro de sintaxe no `squidGuard.conf`: o squidGuard entra em **modo de emergência e libera tudo** | Ver a linha indicada em *Services › SquidGuard*; avisar o projeto se veio de uma regra gerada |
| Regra de setor desativada com "(grupo sem membros)" | O grupo do AD está vazio | Normal: volta sozinha quando o grupo tiver alguém |

## No dia a dia

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| A janela de senha não aparece | O PC não está usando o proxy | Conferir a GPO / proxy do PC |
| A senha certa é recusada | Conta desativada, senha expirada, ou digitou `DOMINIO\usuario` | Usar só o usuário: `joao.silva`. Testar: `php squid-ad.php testar joao.silva` |
| Usuário mudou de setor e o relatório não mudou | Cache do login (5 min) | Esperar 5 minutos |
| Windows Update / antivírus pararam | Não conseguem digitar senha | Liberar em *Squid › Authentication › Subnets That Don't Need Authentication*, ou por domínio na ACL do Squid |
| Tudo parou depois de aplicar | — | `php squid-ad.php desfazer` volta como era |

## Ver o que o Squid está fazendo

```sh
tail -f /var/squid/logs/cache.log
```

```sh
grep basic_ldap_auth /usr/local/etc/squid/squid.conf
```
