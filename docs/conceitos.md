# Como funciona

[← README](../README.md) · [AD](ad.md) · [pfSense](pfsense.md) · [Relatório](relatorio.md) · [Problemas](problemas.md)

## O login

```
PC do usuário ──(proxy explícito)──▶ Squid no pfSense ──(LDAPS 636)──▶ Active Directory
  janela pede usuário e senha          1. procura o usuário com a conta de serviço
  do Windows                           2. confere a senha do usuário (bind)
                                       3. libera a navegação
```

- O pfSense **não copia nem sincroniza** usuários. A cada login ele **pergunta ao AD na hora**.
- **Funcionário novo:** basta criar no AD. **Desligado:** desative a conta no AD e ele perde a internet no próximo login.
- **Troca de senha do Windows:** a nova senha passa a valer no proxy também.
- O pfSense guarda o login por **5 minutos** (`auth_ttl`), para não consultar o AD a cada clique.
- O log do Squid passa a registrar **o usuário** de cada acesso, e não só o IP.

## Setores

Cada setor é um **grupo do AD** (ex.: `SETOR-FINANCEIRO`). Nesta versão:

| Quem | O que acontece |
|---|---|
| Usuário de um setor | Acessa tudo; no [relatório](relatorio.md) aparece com o setor |
| Usuário **sem setor** | Também acessa tudo, mas aparece **destacado como "SEM SETOR - acessando tudo"** |
| Conta desativada, senha errada | Não navega (a janela pede a senha de novo) |

A ideia é **monitorar primeiro**: ver quem acessa o quê, por setor, organizar os grupos no AD e só depois restringir. A restrição por setor (SquidGuard) é o próximo passo do projeto.

## Limitações que você precisa conhecer

| Limitação | Por quê | O que fazer |
|---|---|---|
| **Não funciona em modo transparente** | Um proxy transparente não consegue pedir senha: o navegador nem sabe que ele existe | Configurar o proxy nos PCs: GPO (o script do AD cria, opcional), WPAD ou na mão |
| **Login com janela, não automático** | O pacote Squid do pfSense só faz autenticação *Basic*. Login automático com a sessão do Windows (Kerberos/SSO) não existe nele | O usuário digita usuário e senha do Windows uma vez; o navegador lembra durante a sessão |
| **Filtra por site, não por página** | Sem inspeção SSL, o Squid vê só o nome do site HTTPS (`bb.com.br`) | Suficiente para controle por setor |
| **Squid "deprecated" pela Netgate** | Netgate recomenda desinstalar por falhas de segurança não corrigidas no Squid, e avisa que ele vai parar de funcionar numa versão futura | Funciona no pfSense CE 2.7. Planeje a alternativa a médio prazo ([fonte](https://docs.netgate.com/pfsense/en/latest/packages/list.html)) |

## Segurança

- **LDAPS (636):** as senhas dos usuários vão criptografadas do pfSense até o AD. O certificado do AD é **verificado** (`TLS_REQCERT demand`): o pfSense recebe a CA do AD e não aceita outro servidor.
- **Conta de serviço só leitura:** o pfSense usa uma conta própria, sem permissão especial, só para procurar o usuário. A senha dela é aleatória (32 caracteres) e fica no `config.xml` do pfSense — como qualquer configuração LDAP do pfSense.
- **Proxy com autenticação *Basic*:** entre o PC e o proxy, a senha do usuário vai em Base64 (não criptografada) dentro da LAN. É o funcionamento do pacote Squid do pfSense.
- **Backup e desfazer:** antes de qualquer mudança, o script do pfSense salva o `config.xml` inteiro em `/root/squid-ad-backups/`, e o comando `desfazer` volta a autenticação como estava antes do projeto.
