# Relatório de acessos (monitoramento)

[← README](../README.md) · [Conceitos](conceitos.md) · [AD](ad.md) · [pfSense](pfsense.md) · [Problemas](problemas.md)

Antes de restringir, **monitore**: veja quem acessa o quê, por setor, sem bloquear nada. O relatório lê o log do Squid e pergunta ao AD o setor de cada usuário.

```sh
php /root/squid-ad.php relatorio
```

```
==> Acessos pelo proxy nos ultimos 1 dia(s) - 4 usuario(s)
USUARIO                  SETOR                                                SITES MAIS ACESSADOS
------------------------------------------------------------------------------------------------------------------------
joao.silva               SETOR-FINANCEIRO              1834 acessos     0 negados  bb.com.br (612), itau.com.br (240), ...
maria.souza              SEM SETOR - acessando tudo     977 acessos     0 negados  globo.com (310), youtube.com (205), ...
pedro.lima               SETOR-COMPRAS                  455 acessos     0 negados  mercadolivre.com.br (198), ...
(sem login) 172.16.10.30 -                               88 acessos     0 negados  microsoft.com (80), ...

!! 1 usuario(s) SEM SETOR acessando tudo: maria.souza
   Coloque-os no grupo do setor no AD (vale no proximo login).
```

## Opções

| Opção | Exemplo | O que faz |
|---|---|---|
| `--dias N` | `relatorio --dias 7` | Período (padrão: 1 dia) |
| `--usuario X` | `relatorio --usuario maria.souza` | Só um usuário (todos os sites dele) |
| `--csv arquivo` | `relatorio --dias 30 --csv /root/acessos.csv` | Exporta usuário, setor e cada site com a contagem. Abre no Excel (separador `;`) |

## Como ler

- **SEM SETOR - acessando tudo:** o usuário logou, mas não está em nenhum grupo de setor escolhido. Coloque-o no grupo certo no AD.
- **(sem login) IP:** acesso de um site liberado sem senha (*Subnets That Don't Need Authentication* no Squid) ou de um programa do sistema. É normal para Windows Update e antivírus.
- **Sites agrupados:** `www.bb.com.br` e `cdn.bb.com.br` contam como `bb.com.br`.
- O relatório **não muda nada**: só lê o log e consulta o AD.

## Requisito

O log precisa estar ligado em *Services › Squid Proxy Server › General › Logging Settings › Enable Access Logging*. O arquivo é `/var/squid/logs/access.log`. O pfSense faz a rotação diária pelo campo *Log Rotate*: para relatórios de vários dias, aumente esse valor.
