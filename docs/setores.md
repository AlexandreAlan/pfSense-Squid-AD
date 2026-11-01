# Setores e sincronização

[← README](../README.md) · [Conceitos](conceitos.md) · [AD](ad.md) · [pfSense](pfsense.md) · [Relatório](relatorio.md) · [Problemas](problemas.md)

## A ideia

Cada **OU de departamento** do AD vira um **setor de internet**:

```
AD                                              pfSense (SquidGuard › Groups ACL)
OU=AGF                                          ──────────────────────────────────
├── OU=Financeiro  ── grupo NET_FINANCEIRO  ──▶ regra FINANCEIRO   (libera tudo)
├── OU=Comercial   ── grupo NET_COMERCIAL   ──▶ regra COMERCIAL    (libera tudo)
└── OU=Expedição Instrumental
         └─ grupo NET_EXPEDICAO_INSTRUMENTAL   ──▶ regra EXPEDICAO_INSTRU (libera tudo)
```

> O SquidGuard aceita nomes de regra com até 16 caracteres, por isso o nome da regra pode sair cortado. O vínculo com o grupo fica na descrição da regra.

- O grupo `NET_` é **só de internet**, separado dos grupos de pastas (ex.: `GR_`/`GRE_`). Ele fica **dentro da OU** do departamento.
- O grupo **espelha a OU**: quem está na OU está no grupo.
- Cada grupo vira uma regra no SquidGuard que **libera tudo**. Para restringir um setor, edite a regra na tela e escolha as *Target categories* (por exemplo, `!jogos`). **A sincronização nunca mexe nisso**: ela só cuida de *quem* é o setor.

## Sincronização automática (a cada 15 minutos)

Duas tarefas mantêm tudo em dia, sem ninguém rodar nada:

| Onde | O que faz |
|---|---|
| **AD** (tarefa agendada `pfSense-Squid-AD - Sincronizar setores`, como SYSTEM) | OU de departamento **nova** ganha o grupo `NET_`. Usuário **novo** entra no grupo do departamento. Usuário que **mudou de OU** sai do grupo antigo e entra no novo |
| **pfSense** (cron `squid-ad.php sincronizar`) | Grupo `NET_` **novo** vira regra. Grupo **renomeado ou movido** tem a origem da regra atualizada. Grupo **apagado** tem a regra **desativada**, e as restrições ficam guardadas nela. Grupo **recriado** com o mesmo nome **reativa** a mesma regra |

Nos dois lados, só aplica quando **algo mudou**.

### Proteções

- **AD fora do ar ou falha de rede:** o pfSense **não muda nada**, para não desativar todos os setores por causa de uma queda. O erro vai para o log do sistema.
- **O AD devolveu zero grupos de repente** (por exemplo, prefixo trocado ou OU errada): o pfSense **para** e não desativa nada. Se a mudança for intencional: `php squid-ad.php sincronizar --forcar`.
- **Regras que não são do projeto** (como uma `setor-davs` criada na mão) **nunca são tocadas**. As do projeto são reconhecidas pela descrição `pfSense-Squid-AD id=... grupo=...`.

## Exceção: alguém de fora do departamento

O espelhamento tira do grupo quem não está na OU. Para manter alguém de outro departamento num setor (por exemplo, um diretor no `NET_FINANCEIRO`):

1. Adicione o usuário ao grupo normalmente.
2. Na **Descrição** do usuário no AD, coloque **`[proxy-manual]`**.

Usuário com `[proxy-manual]` na descrição **nunca é removido** pela sincronização.

## Usuários fora dos departamentos

Quem está direto na OU da empresa (fora das OUs de departamento) **não entra em nenhum setor**. Essa pessoa acessa tudo e aparece como **"SEM SETOR - acessando tudo"** no [relatório](relatorio.md). O script do AD lista essas pessoas na instalação: mova cada uma para a OU do departamento certo.

## Acompanhar

| Onde | Como |
|---|---|
| AD | `C:\ProgramData\pfSense-Squid-AD\sincronizacao.log` e Log de Aplicativo, origem `pfSense-Squid-AD`: evento **2000** (o que mudou) e **2001** (erro) |
| pfSense | `php /root/squid-ad.php status` (última sincronização e cron) e *Status › System Logs › General* (linhas `pfSense-Squid-AD:`) |
| Forçar agora | AD: `schtasks /Run /TN "pfSense-Squid-AD - Sincronizar setores"` · pfSense: `php /root/squid-ad.php sincronizar` |
