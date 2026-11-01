# Histórico de versões

## [1.3.0] — 2026-11-01

### Corrigido (provado no squidGuard real da AGF)
- **O squidGuard 1.4 do pfSense 2.7 não faz LDAPS** e **quebrava com `!` e `@` na senha** (erro de sintaxe → modo de emergência, liberando tudo, inclusive regras manuais). As regras dos setores agora levam a **lista de usuários do grupo** na origem (`'fulano' 'ciclano'`), escrita pela sincronização (LDAPS, a cada 15 min). O squidGuard não consulta mais o AD, e o LDAP que a 1.1/1.2 ligou nas *General settings* é desligado (a senha sai do `squidGuard.conf`).
- Grupo sem membros deixa a regra **desativada** (bloco vazio quebraria o squidGuard) e ela volta sozinha quando houver membros. Regra desativada pelo administrador continua desativada.
- Depois de cada *Apply*, a configuração é **conferida com o squidGuard real**; erro de sintaxe vira aviso na tela e no log.
- Senha gerada pelo script do AD só com letras, números e `- _ .`.
- O arquivo do AD leva os membros de cada setor (usados se o pfSense não conseguir consultar o AD na hora).

## [1.2.0] — 2026-11-01

### Alterado
- Saída dos scripts mais legível e didática: passos numerados ("PASSO 3 de 9"), cada passo explica **O QUE É / POR QUE / O QUE ACONTECE**, e há linhas em branco separando explicações, perguntas e resultados (inclusive entre departamentos). O script do pfSense ganhou o mesmo espaçamento nas etapas.
- O texto da conta de serviço explica como manter a senha atual (responder N e digitá-la), para o pfSense não ficar com a senha desatualizada.

## [1.1.1] — 2026-11-01

### Corrigido (vistos na AGF)
- OU recusada na instalação (ex.: `Computadores`) fica gravada em `Ignorar` e a tarefa agendada não cria o grupo dela depois.
- Exceções da GPO: o padrão (`<local>`, domínio, redes privadas) sempre entra; a pergunta agora pede só as exceções **extras**. Antes, digitar um IP substituía o padrão.

## [1.1.0] — 2026-11-01

### Adicionado
- **Setores por OU de departamento:** o script do AD cria um grupo só de internet por OU (`NET_<DEPARTAMENTO>`, dentro da OU) e coloca nele os usuários ativos da OU.
- **Regras no SquidGuard:** cada setor vira uma regra no *Groups ACL*, com origem `ldapusersearch` para o grupo do AD e destino "libera tudo". O LDAP das *General settings* do SquidGuard é ligado automaticamente.
- **Sincronização automática a cada 15 minutos:** tarefa agendada no AD (OU nova vira grupo, usuário que mudou de departamento troca de grupo) e cron no pfSense (grupo novo vira regra; movido atualiza a origem; apagado desativa a regra; recriado reativa). As restrições configuradas na tela nunca são sobrescritas.
- Exceção manual: usuário com `[proxy-manual]` na descrição nunca é removido de um grupo pela sincronização.
- Comando `sincronizar` no pfSense; `status` mostra a última sincronização e o cron; `desfazer` remove regras, LDAP do SquidGuard e cron criados pelo projeto.
- A senha da conta de serviço é mostrada no fim do script do AD, para guardar no cofre de senhas.

### Corrigido (vistos no primeiro uso real)
- IP 169.254 (APIPA) do controlador ignorado; preferência pelo IP da placa com gateway; aviso só quando o IP está de fato no DNS.
- A escolha do controlador aceita o número ou o nome; "S" numa pergunta de valor aceita o padrão.
- Nomes do certificado sem o GUID do objeto que o SAN de um DC traz.
- Senha de usuário recusada no teste explica as causas comuns.
- O gerador de senha não usa mais `#` (vira comentário no `squidGuard.conf`).

## [1.0.0] — 2026-11-01

- Login do Squid via LDAPS no AD: script do AD (domínio, DC, LDAPS, conta de serviço, teste, GPO opcional) e script do pfSense (simular, aplicar, testar, relatório, status, desfazer).
