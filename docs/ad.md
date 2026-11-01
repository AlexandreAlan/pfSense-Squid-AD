# Passo 1: no servidor AD

[← README](../README.md) · [Conceitos](conceitos.md) · [pfSense](pfsense.md) · [Relatório](relatorio.md) · [Problemas](problemas.md)

## Rodar

No **controlador de domínio**, abra o **Windows PowerShell como Administrador**, entre na pasta do projeto e rode:

```powershell
Get-ChildItem .\*.ps1 | Unblock-File
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-SquidAD.ps1
```

O script **descobre sozinho** o domínio, os controladores e os grupos. Cada pergunta mostra o padrão entre colchetes: **ENTER aceita**, ou responda **S** / **N**. Nada é criado no AD sem um **S**.

## O que ele pergunta, passo a passo

| Passo | O que mostra | O que você responde |
|---|---|---|
| **1. Domínio** | `agfmedical.local (NetBIOS AGFMEDICAL)` | ENTER |
| **2. Controlador** | Lista dos DCs com nome e IP, marcando "este servidor" | o número (ENTER = este) |
| **3. LDAPS** | Certificado do DC: nome, validade, quem emitiu | — (só confere) |
| **4. Setores** | A OU da empresa (ex.: `AGF`) e as OUs de departamento dentro dela | ENTER na OU, **S** para "cada OU é um departamento", o prefixo (`NET_`), e **S/N** para criar cada grupo e colocar nele os usuários da OU |
| **5. Conta de serviço** | `svc-squid-ldap` (cria ou reaproveita) | ENTER / S |
| **6. Teste** | Login LDAPS com a conta; quantos usuários ativos e quantos em cada setor | S para testar também com **um usuário real** (mostra o setor dele) |
| **7. GPO (opcional)** | GPO de proxy para os PCs | N, ou S e os dados do proxy |
| **8. Arquivo** | `squid-ad-AGFMEDICAL.json` para o pfSense | S para incluir a senha da conta de serviço |
| **9. Sincronização** | Tarefa agendada a cada 15 min | S |
| **Fim** | **A senha da conta de serviço**, em destaque | Guarde no cofre de senhas: ela não fica em nenhum log |

## LDAPS: se o controlador não tiver certificado

O LDAPS exige um certificado de servidor no controlador de domínio. Se o passo 3 disser que o LDAPS não respondeu:

1. **Confira se já existe uma CA no domínio.** Servidores Essentials costumam ter. Abra *Gerenciador do Servidor › Ferramentas › Autoridade de Certificação*.
2. **Se não existir**, o caminho mais comum é instalar o **AD CS** como **CA corporativa raiz**: os controladores recebem o certificado sozinhos.

   ```powershell
   Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
   ```

   ```powershell
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCa
   ```

3. Force o controlador a pedir o certificado e confira a porta 636:

   ```powershell
   certutil -pulse
   ```

   ```powershell
   Test-NetConnection $env:COMPUTERNAME -Port 636
   ```

4. Rode o `Install-SquidAD.ps1` de novo.

> Instalar uma CA é uma mudança de infraestrutura no domínio. Planeje com o responsável pelo AD. O script **não** instala nada disso sozinho: sem LDAPS, ele só oferece seguir com LDAP sem criptografia (porta 389), e o padrão dessa pergunta é **N**.

## Setores

- **Cada OU de departamento ganha um grupo só de internet**, com o prefixo escolhido: `OU=Financeiro` → `NET_FINANCEIRO`, criado **dentro** da OU. Nomes com acento viram sem acento (`Expedição Instrumental` → `NET_EXPEDICAO_INSTRUMENTAL`).
- Os grupos **espelham a OU**: o script coloca neles os usuários ativos que estão na OU. Para alguém de fora ficar num grupo, use `[proxy-manual]` na descrição do usuário. Detalhes em [Setores e sincronização](setores.md).
- **Usuários direto na OU da empresa**, fora dos departamentos, são listados: eles ficam "SEM SETOR".
- Se o domínio **não** tiver OUs de departamento, o script deixa escolher grupos que já existem.

## GPO do proxy (opcional)

O proxy com login **não funciona em modo transparente**: cada PC precisa apontar para o pfSense. Se você responder **S**, o script:

- cria a GPO **"Proxy Squid - pfSense"** com o proxy (`IP-do-pfSense:3128`) e as exceções (rede local e o domínio);
- **não vincula** a nenhuma OU, a menos que você escolha. Assim você liga **setor por setor**, no seu ritmo.

Para vincular depois: *Gerenciamento de Política de Grupo › OU do setor › Vincular um GPO existente*. Vale no próximo logon (ou `gpupdate /force`).

## O arquivo gerado

`squid-ad-<DOMINIO>.json`, ao lado do script, com permissão só para Administradores. Ele leva servidor, base, conta de serviço, setores e a CA do LDAPS.

> Se você incluiu a senha, **apague o arquivo** depois de usar no pfSense.

Próximo passo: [no pfSense](pfsense.md).
