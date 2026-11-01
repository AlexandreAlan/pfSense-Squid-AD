# pfSense-Squid-AD

[![Testes](https://github.com/AlexandreAlan/pfSense-Squid-AD/actions/workflows/testes.yml/badge.svg)](https://github.com/AlexandreAlan/pfSense-Squid-AD/actions/workflows/testes.yml)
![pfSense CE 2.7](https://img.shields.io/badge/pfSense_CE-2.7-212121)
![Windows Server 2016+](https://img.shields.io/badge/Windows_Server-2016%2B-0078D6?logo=windows)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
[![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-green)](LICENSE)

Login do **proxy Squid do pfSense** com o **usuário e a senha do Active Directory**, configurado de forma **automática, guiada e reversível**. Dois scripts fazem o trabalho que costuma levar horas de tentativa e erro: um no servidor AD, outro no pfSense.

## Recursos

- **Descobre sozinho** o domínio, o controlador e os grupos que parecem **setores**. Você só responde **S/N**.
- **LDAPS de verdade:** o pfSense recebe a CA do AD e **verifica o certificado** do controlador.
- **Conta de serviço só leitura**, com senha aleatória, criada e testada pelo script.
- **Testa antes de aplicar**, com o mesmo helper que o Squid usa. Se o teste falhar, o Squid não é alterado.
- **Backup e `desfazer`:** volta a autenticação como estava antes do projeto.
- **Relatório por usuário e setor:** quem acessa o quê, com destaque para quem está **sem setor**.
- **GPO opcional** que configura o proxy nos PCs, setor por setor.

## Como funciona

```
 PC do usuário ──proxy──▶ Squid no pfSense ──LDAPS 636──▶ Active Directory
 (pede usuário e senha     1. acha o usuário (conta de serviço)
  do Windows)              2. confere a senha  3. libera
```

O pfSense **não copia** usuários: a cada login ele pergunta ao AD. Funcionário novo, conta desativada ou senha trocada valem na hora. Nesta versão **todos os usuários autenticados acessam tudo**. Os setores servem para monitorar primeiro e restringir depois. Detalhes e limitações em [Como funciona](docs/conceitos.md).

## Requisitos

| | |
|---|---|
| **pfSense** | CE 2.7, com o pacote **Squid** em modo **não transparente** |
| **AD** | Windows Server 2016+, com **LDAPS** no controlador ([como habilitar](docs/ad.md#ldaps-se-o-controlador-não-tiver-certificado)) |
| **Rede** | O pfSense precisa alcançar o controlador na porta 636 |

> ⚠️ A Netgate marcou o pacote Squid como *deprecated* ([aviso oficial](https://docs.netgate.com/pfsense/en/latest/packages/list.html)). Ele funciona no pfSense CE 2.7, mas não é o futuro da plataforma.

## Uso rápido

**1. No servidor AD**, no PowerShell como Administrador:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-SquidAD.ps1
```

Responda as perguntas (ENTER aceita o padrão). No fim ele gera `squid-ad-<DOMINIO>.json`.

**2. No pfSense**, envie o `pfsense/squid-ad.php` e o `.json` em *Diagnostics › Command Prompt › Upload File* e rode por SSH:

```sh
php /tmp/squid-ad.php aplicar /tmp/squid-ad-EMPRESA.json
```

Ou, na própria tela Command Prompt, use primeiro `simular` e depois `aplicar ... --sim`.

**3. Acompanhe** quem acessa o quê:

```sh
php /tmp/squid-ad.php relatorio --dias 7
```

## Documentação

| | |
|---|---|
| [Como funciona](docs/conceitos.md) | O login, os setores, limitações e segurança |
| [Passo 1: AD](docs/ad.md) | O que o script pergunta, LDAPS, setores, GPO |
| [Passo 2: pfSense](docs/pfsense.md) | Enviar, simular, aplicar, testar, desfazer |
| [Relatório](docs/relatorio.md) | Monitorar acessos por usuário e setor, exportar CSV |
| [Problemas comuns](docs/problemas.md) | Cada mensagem de erro e o que fazer |
| [Desenvolvimento](docs/desenvolvimento.md) | Estrutura, testes e próximos passos |

## Próximos passos

Restrição de acesso **por setor** com o SquidGuard: o projeto vai gerar as regras de cada grupo do AD prontas.

## Licença

[MIT](LICENSE)
