# PKI Certificate Types Lab

Hands-on practice generating and inspecting X.509 certificates, CSRs, trust chains, SANs, and wildcards.

## Quick Reference

| Concept | Role in PKI | Key Takeaway |
| :--- | :--- | :--- |
| **Root CA** | Top trust anchor | Self-signed; kept **offline** so its private key stays protected. |
| **Intermediate CA** | Day-to-day signer | Signed by the Root CA; issues end-entity server/user certificates. |
| **CSR** | Certificate Signing Request | Contains **public key + identity details** sent to a CA; the **private key never leaves** the requester. |
| **Self-Signed** | Lab / internal testing | Signed with its own private key (`Issuer === Subject`); browsers reject by default. |
| **SAN** | Subject Alternative Name | Extension listing every exact domain/IP covered (e.g., `example.com`, `://example.com`). |
| **Wildcard** | First-level subdomains | Uses `*.example.com` — covers `://example.com`, **not** `://example.com` or `example.com`. |

## How to Run
1. Install the zero-dependency PKI helper package: `npm install node-forge`
2. Run the Certificate Authority & Chain lab: `node 01-ca-chain-and-csr.js`
3. Run the SAN & Wildcard hostname tester: `node 02-san-and-wildcard.js`

## My Lab Output & Takeaways

### 1. Trust Chain & CSR Verification (`01-ca-chain-and-csr.js`)
* **Root CA:** `Subject === Issuer` (`My Offline Root CA`). Anchors the trust store and stays offline.
* **Intermediate CA:** Issued by `My Offline Root CA`; handles day-to-day signing so the Root key stays protected.
* **CSR:** Verified signature (`true`) using only the public key and subject identity—the server's private key never left the machine.
* **Chain Verification:** `Server Cert -> Intermediate CA -> Root CA` verified as **`true`**.
* **Self-Signed Cert:** Rejected by the Root CA store (`Certificate is not trusted`) because it wasn't signed by a trusted CA.

### 2. SAN & Wildcard Hostname Checks (`02-san-and-wildcard.js`)
Certificate SANs configured: `DNS:example.com`, `DNS:www.example.com`, `DNS:*.example.com`

| Test Hostname | Result | Why |
| :--- | :--- | :--- |
| `example.com` | **PASS** | Explicitly listed in the SAN extension (`*.example.com` alone would not cover the apex domain). |
| `www.example.com` | **PASS** | Covered by both the explicit SAN and `*.example.com`. |
| `mail.example.com` | **PASS** | First-level subdomain matched by `*.example.com`. |
| `a.b.example.com` | **FAIL** | Wildcards (`*`) only match **one** subdomain level, not nested subdomains. |
| `evil-example.com` | **FAIL** | Completely different domain; rejected immediately. |

