#!/usr/bin/env bash
# Roda TODOS os testes: sintaxe (PowerShell + PHP), funcoes do script do AD
# contra um servidor TLS local, e o fluxo do script do pfSense com o JSON que
# o script do AD gerou (contrato entre os dois).
# Precisa de: pwsh, php (com ldap), openssl.   PWSH=/caminho/pwsh para outro pwsh.
set -euo pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"
PWSH="${PWSH:-pwsh}"
PORTA="${PORTA:-18636}"
WORK="$(mktemp -d)"
trap 'kill "${TLS:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== Sintaxe"
"$PWSH" -NoProfile -File "$AQUI/Test-Sintaxe.ps1"
for f in "$AQUI"/../pfsense/*.php "$AQUI"/php/*.php; do php -l "$f" >/dev/null && echo "PHP OK: $(basename "$f")"; done

echo "== Certificados de teste (CA + controlador dc.teste.local)"
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=CA Teste pfSense-Squid-AD" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=dc.teste.local" -keyout dc.key -out dc.csr 2>/dev/null
# Como um DC de verdade: alem dos nomes, o SAN traz o GUID do objeto no AD (OID 1.3.6.1.4.1.311.25.1)
printf 'subjectAltName=@alt\nextendedKeyUsage=serverAuth\n[alt]\notherName.1=1.3.6.1.4.1.311.25.1;FORMAT:HEX,OCT:fbb70dbc38a9d64f9304abaf26b74181\nDNS.1=dc.teste.local\nDNS.2=*.dcs.teste.local\n' > ext.cnf
openssl x509 -req -in dc.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out dc.pem 2>/dev/null
PIN="$(openssl x509 -in ca.pem -outform der | sha256sum | cut -d' ' -f1)"
openssl s_server -quiet -accept "$PORTA" -cert dc.pem -key dc.key -cert_chain ca.pem -www >/dev/null 2>&1 &
TLS=$!
for _ in $(seq 1 50); do (echo > /dev/tcp/127.0.0.1/"$PORTA") 2>/dev/null && break; sleep 0.1; done

echo "== Script do AD (Install-SquidAD.ps1)"
"$PWSH" -NoProfile -File "$AQUI/Test-AD.ps1" -PortaTls "$PORTA" -PinCaOpenssl "$PIN" -WorkDir "$WORK"

echo "== Script do pfSense (squid-ad.php), com o JSON gerado pelo script do AD"
php "$AQUI/php/test-squid-ad.php" "$WORK/pacote.json" "$WORK/php" </dev/null >"$WORK/php-stdout.txt"
