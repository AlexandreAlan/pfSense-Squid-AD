# Passo 2: no pfSense

[← README](../README.md) · [Conceitos](conceitos.md) · [AD](ad.md) · [Relatório](relatorio.md) · [Problemas](problemas.md)

**Requisitos:** pfSense CE **2.7**, pacote **Squid** instalado e configurado em modo **não transparente** (*Services › Squid Proxy Server*).

## 1. Enviar os arquivos

Em *Diagnostics › Command Prompt › Upload File*, envie os dois arquivos. Eles vão para `/tmp`:

- `pfsense/squid-ad.php` (deste repositório)
- `squid-ad-<DOMINIO>.json` (gerado no AD)

## 2. Rodar

### Opção A: por SSH (recomendado, com perguntas S/N)

Ligue o SSH em *System › Advanced › Admin Access › Secure Shell*, conecte (PuTTY, ou `ssh admin@IP -p porta`), escolha a opção **8 (Shell)** e rode:

```sh
php /tmp/squid-ad.php aplicar /tmp/squid-ad-AGFMEDICAL.json
```

### Opção B: pela tela Command Prompt (sem perguntas)

A tela não tem como responder S/N. Por isso, **primeiro simule** e confira, depois aplique com `--sim` (responde S para tudo):

```sh
php /tmp/squid-ad.php simular /tmp/squid-ad-AGFMEDICAL.json
```

```sh
php /tmp/squid-ad.php aplicar /tmp/squid-ad-AGFMEDICAL.json --sim
```

## O que o `aplicar` faz

1. **Confere o ambiente:** versão 2.7, Squid instalado e ligado. Avisa se o modo transparente estiver ligado.
2. **Lê o arquivo do AD** e mostra domínio, controlador, conexão e setores.
3. **DNS:** o pfSense precisa resolver o nome do controlador (o certificado tem o nome, não o IP). Se não resolver, **oferece criar um Host Override** no DNS Resolver.
4. **Mostra exatamente o que muda** em *Squid › Authentication* e pede confirmação.
5. **Backup:** o `config.xml` inteiro em `/root/squid-ad-backups/`.
6. **CA do AD** em `/usr/local/etc/squid-ad/ca-ad.pem`, com um bloco marcado no `/usr/local/etc/openldap/ldap.conf`. É de lá que o helper LDAP do Squid lê a CA.
7. **Testa o login** com o **mesmo helper do Squid** (`basic_ldap_auth`), com a conta de serviço e, por SSH, também com um usuário real. **Se o teste falhar, o Squid não é alterado.**
8. **Aplica** os campos de autenticação, grava o `config.xml` e reinicia o Squid, igual ao botão *Save* da tela.
9. **SquidGuard** (se instalado): cria **uma regra por setor** no *Groups ACL*, com a lista de usuários do grupo e liberando tudo, faz o *Apply* e **confere a configuração com o squidGuard real**. As regras que você já tinha ficam como estão.
10. **Cron:** instala a sincronização a cada 15 minutos (`php /root/squid-ad.php sincronizar --cron`) e copia o script para `/root`. Veja [Setores e sincronização](setores.md).

Os campos que o script preenche (os mesmos da tela *Services › Squid Proxy Server › Authentication*):

| Campo na tela | Valor |
|---|---|
| Authentication Method | LDAP |
| Authentication Server / Port | nome do controlador / 636 |
| LDAP version / Transport | 3 / SSL - Encrypted |
| LDAP Server User DN / Password | conta de serviço |
| LDAP Base Domain | `DC=...` do domínio |
| LDAP Username DN Attribute | `sAMAccountName` |
| LDAP Search Filter | usuários **ativos** do domínio |
| Authentication Prompt | "Proxy da empresa: use seu usuario e senha do Windows" |

O resto da tela (redes sem autenticação, limites, TTL) **é preservado**.

## Outros comandos

| Comando | O que faz |
|---|---|
| `php /tmp/squid-ad.php testar joao.silva` | Testa o login de um usuário e mostra o setor dele |
| `php /tmp/squid-ad.php relatorio` | Quem acessa o quê ([detalhes](relatorio.md)) |
| `php /root/squid-ad.php sincronizar` | Traz agora os grupos de setor do AD para o SquidGuard (o cron faz isso a cada 15 min) |
| `php /tmp/squid-ad.php status` | Mostra o estado atual, a última sincronização e o cron |
| `php /tmp/squid-ad.php desfazer` | Volta tudo como estava **antes do projeto**: autenticação, LDAP do SquidGuard, remove as regras criadas pelo projeto e o cron (`--sim` na tela Command Prompt) |

> O `/tmp` do pfSense é apagado no reboot. Para usar os comandos depois, copie o script para um lugar fixo: `cp /tmp/squid-ad.php /root/`.

## Inspeção SSL (fase 2)

Liga a inspeção SSL (SSL bump) do Squid: **splice por padrão** (passa direto, sem inspecionar) e bump só em quem não está na lista "nunca inspecionar" (bancos, gov.br/e-CAC/SEFAZ/eSocial, Windows Update, Microsoft 365, antivírus — ver [roadmap.md](roadmap.md)). Nunca marca "aceitar certificado com erro" nem "não verificar certificado remoto" — isso esconderia um ataque man-in-the-middle real.

| Comando | O que faz |
|---|---|
| `php /tmp/squid-ad.php ssl-simular` | Mostra o que a inspeção SSL vai mudar (CAs existentes, campos do Squid). **Não muda nada.** |
| `php /tmp/squid-ad.php ssl-aplicar [--sim]` | Deixa escolher uma CA existente ou criar uma nova (nome, tamanho, validade), liga o SSL bump e exporta o certificado público da CA para `/root/squid-ad/ssl-ca.crt` (para distribuir por GPO, fase seguinte) |
| `php /tmp/squid-ad.php ssl-testar <usuario>` | Testa os sites críticos (banco, gov.br, Microsoft...) pelo proxy com um usuário/senha do AD; **avisa para não ligar a GPO do setor se algum teste falhar** |
| `php /tmp/squid-ad.php ssl-status` | Mostra se está ligado, a CA em uso, quantos domínios estão na whitelist e quando foi aplicado |
| `php /tmp/squid-ad.php ssl-desfazer [--sim]` | Desliga a inspeção SSL e volta os campos do Squid como estavam antes do `ssl-aplicar`. A CA **não é removida** do Cert Manager (é inofensiva ficar lá; remova à mão se não for mais usar) |

**A CA nunca é fixa no código.** Cada cliente, ao rodar `ssl-aplicar` de verdade (fora de `--sim`), vê a lista de CAs já existentes naquele pfSense e escolhe uma, ou cria uma nova com nome/tamanho/validade próprios — importante porque este projeto é reutilizado em instalações diferentes, cada uma com seu próprio Cert Manager.

**Confirmação extra:** como `ssl-aplicar`/`ssl-desfazer` passam a interceptar tráfego criptografado da rede inteira, além da pergunta normal (S/N) eles pedem a frase digitada por extenso `CONFIRMO INSPECAO SSL` antes de mexer em qualquer coisa — isso evita um Enter sem querer ou um script de automação errado disparar isso por engano. Pela tela *Command Prompt* (sem terminal interativo) ou em `--sim`, passe a frase direto: `--confirmo="CONFIRMO INSPECAO SSL"`.

```sh
php /tmp/squid-ad.php ssl-aplicar --sim --confirmo="CONFIRMO INSPECAO SSL"
```

> **Antes de ligar a GPO de qualquer setor:** rode `ssl-testar` com um usuário real contra o Squid de produção (não só o `ssl-simular`) e confira à mão o login com certificado digital A1/A3 (gov.br, e-CAC), que quebra sob MITM.

### Rodar os comandos `ssl-*` a partir do Servidor AD

Os comandos `ssl-*` usam funções internas do pfSense (`config_get_path`, `write_config`, `ca_create`...) que só existem **dentro** do pfSense — por isso, mesmo disparando do Servidor AD, o PHP continua executando no pfSense; o AD só manda o comando por SSH.

Acesso de admin ao pfSense já dá controle total do firewall, então **não existe usuário "limitado"** no pfSense — qualquer credencial aqui equivale à chave do firewall inteiro. Em vez de senha (que ficaria guardada em algum lugar legível no Servidor AD — já tivemos esse problema antes com a senha da conta de serviço), use uma **chave SSH com comando forçado**: ela só executa os 5 subcomandos `ssl-*` deste projeto, nada mais, mesmo que o shell do pfSense seja root.

### Automático: pelo `Install-SquidAD.ps1`

O passo opcional *"Acesso remoto ao pfSense para a inspeção SSL"* do `Install-SquidAD.ps1` faz tudo isso sozinho:

1. Gera a chave SSH no Servidor AD (`%ProgramData%\pfSense-Squid-AD\ssl-remoto`), restrita a Administradores/SYSTEM.
2. Pede a **senha admin do pfSense só naquele momento** (nunca é salva em disco) e, com ela, envia a chave pública e manda o pfSense instalar o acesso restrito — chamando exatamente o `ssl-chave-remota` descrito abaixo.
3. No final, mostra o comando de teste já pronto (`ssh -i <chave> <usuario>@<pfsense> ssl-status`).

Requer o módulo PowerShell **Posh-SSH** (`Install-Module Posh-SSH -Scope CurrentUser`) no Servidor AD, porque autenticar por senha via SSH não é algo que o `ssh.exe` nativo do Windows faça sem digitar na hora. Se o módulo não estiver instalado, o passo avisa e cai para o caminho manual abaixo.

### Manual (sem Posh-SSH, ou se preferir fazer você mesmo)

1. No Servidor AD, gere um par de chaves dedicado a isso (não reaproveite outra):
   ```powershell
   ssh-keygen -t ed25519 -f C:\squid-ad\chave-ssl-remota -N '""' -C "squid-ad-ssl@ad"
   ```
2. Copie `chave-ssl-remota.pub` para o pfSense (upload no Command Prompt, ou `scp`) e, **por SSH normal de admin**, rode uma vez:
   ```sh
   php /root/squid-ad.php ssl-chave-remota admin /tmp/chave-ssl-remota.pub
   ```
   Isso instala um wrapper restrito (`/root/squid-ad-ssl-remoto.sh`) e adiciona a chave pública no usuário escolhido, só liberando `ssl-simular`, `ssl-aplicar`, `ssl-testar`, `ssl-status` e `ssl-desfazer`.
3. **Restrinja o SSH desse usuário à rede interna** (System › Advanced › Admin Access, ou uma regra de firewall): nunca deixe a porta SSH do pfSense aberta na WAN. Esse passo é manual mesmo pelo caminho automático — nenhum dos dois faz isso por você.
4. Do Servidor AD, teste com a chave privada:
   ```powershell
   ssh -i C:\squid-ad\chave-ssl-remota admin@<ip-do-pfsense> ssl-status
   ```
   Para automação (`--sim`), sempre inclua `--confirmo="CONFIRMO INSPECAO SSL"` em `ssl-aplicar`/`ssl-desfazer`, como descrito acima.

## Rodar de novo

Pode rodar o `aplicar` quantas vezes quiser: por exemplo, depois de escolher novos setores no AD. O bloco do `ldap.conf` é trocado, sem duplicar, e o `desfazer` continua voltando para **antes da primeira vez**.

## Testar num PC

1. Configure o proxy no PC (GPO ou *Configurações › Rede › Proxy*): IP do pfSense, porta 3128.
2. Abra um site: o navegador pede usuário e senha. Use o usuário do Windows (`joao.silva`, sem o domínio).
3. Rode o `relatorio` no pfSense: o usuário aparece com o setor.
