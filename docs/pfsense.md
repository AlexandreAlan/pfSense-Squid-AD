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
| `php /tmp/squid-ad.php status` | Mostra o estado atual |
| `php /tmp/squid-ad.php desfazer` | Volta a autenticação como estava **antes do projeto** (`--sim` na tela Command Prompt) |

> O `/tmp` do pfSense é apagado no reboot. Para usar os comandos depois, copie o script para um lugar fixo: `cp /tmp/squid-ad.php /root/`.

## Rodar de novo

Pode rodar o `aplicar` quantas vezes quiser: por exemplo, depois de escolher novos setores no AD. O bloco do `ldap.conf` é trocado, sem duplicar, e o `desfazer` continua voltando para **antes da primeira vez**.

## Testar num PC

1. Configure o proxy no PC (GPO ou *Configurações › Rede › Proxy*): IP do pfSense, porta 3128.
2. Abra um site: o navegador pede usuário e senha. Use o usuário do Windows (`joao.silva`, sem o domínio).
3. Rode o `relatorio` no pfSense: o usuário aparece com o setor.
