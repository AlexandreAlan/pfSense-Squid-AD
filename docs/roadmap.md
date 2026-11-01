# Roteiro

[← README](../README.md)

## Próxima fase: inspeção SSL (HTTPS) bem feita

**Objetivo:** filtrar HTTPS com precisão sem quebrar banco, governo, certificado digital nem atualizações, de forma automatizada e reversível. Tem que aguentar uma indústria grande sem virar fila de chamados.

**Hoje (sem inspeção SSL)** o Squid já filtra HTTPS **por domínio**, pelo nome do site no `CONNECT`, e isso basta para liberar ou bloquear sites por setor. A inspeção SSL só é necessária para filtrar **por endereço completo/página**, forçar **SafeSearch** ou passar **antivírus** no tráfego HTTPS.

### O que a automação vai fazer

1. **Criar a CA do proxy** no pfSense (*System › Cert. Manager*), dedicada só a isso e com validade definida.
2. **Distribuir a CA por GPO**, sem vínculo, ligada **setor por setor**:
   - *Configuração do Computador › Políticas › Configurações do Windows › Configurações de Segurança › Políticas de Chave Pública › Autoridades de Certificação Raiz Confiáveis*;
   - **Firefox** usa o próprio repositório de certificados: política `security.enterprise_roots.enabled` (ADMX do Firefox) ou `policies.json`;
   - Java e aplicativos com repositório próprio: levantar e documentar caso a caso.
3. **Configurar o SSL no Squid** com modo **"bump só no necessário"**: o padrão é *splice* (passa sem abrir) e só abre o que precisa ser inspecionado.
4. **Lista de "nunca inspecionar" (splice) pronta e mantida:**
   - **bancos** (Banco do Brasil, Caixa, Itaú, Bradesco, Santander, Sicoob/Sicredi...) e meios de pagamento;
   - **governo e certificado digital ICP-Brasil**: e-CAC, gov.br, SEFAZ/NF-e, eSocial, Conectividade Social, tribunais. A autenticação por **certificado do cliente (A1/A3) não passa por um proxy que inspeciona**;
   - **Windows Update, Microsoft 365/Teams, antivírus**, e serviços com *certificate pinning*;
   - lista editável por cliente, com sincronização como a dos setores.
5. **Validação dos certificados remotos sempre ligada.** *Remote Cert Checks* **sem** "Accept remote server certificate with errors" e **sem** "Do not verify remote certificate": aceitar erro esconderia um ataque *man-in-the-middle* de verdade. *Certificate Adapt*: imitar o certificado original (validade e CN) para o navegador mostrar dados coerentes.
6. **Testes antes de ligar** cada setor: script que acessa a lista de sites críticos através do proxy e confere que não há erro de certificado.
7. **Desfazer** completo: desliga o SSL bump, remove a GPO da CA e volta ao filtro por domínio.

### Riscos que a fase precisa tratar

- **Squid "deprecated" pela Netgate:** a inspeção SSL aumenta a exposição a falhas do Squid. Para uma indústria grande, vale avaliar um proxy dedicado ou um NGFW. O projeto deve deixar essa escolha clara.
- **LGPD e transparência:** inspecionar HTTPS abre dados pessoais. É preciso política interna comunicada aos colaboradores e exclusão de categorias sensíveis (saúde, banco).
- **Desempenho:** inspeção SSL usa bem mais CPU. Precisa medir no hardware do cliente antes de ligar para todos.

## Ideias para depois

- Relatório agendado (diário, por e-mail).
- Assistente para montar as restrições por setor a partir do relatório (sugerir *Target categories*).
