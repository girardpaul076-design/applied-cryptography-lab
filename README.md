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

### 3. Live Local HTTPS Server & Client (`03-setup-certs.js` – `05-https-client.js`)
* **Certificate Setup:** Generated persistent `localhost.key` and `localhost.crt` files inside the git-ignored `certs/` directory with SANs for `localhost` and `127.0.0.1`.
* **TLS Handshake & Encryption:** Connected `05-https-client.js` to `04-https-server.js` on port `8443` using `localhost.crt` as the client's trusted CA (`HTTP 200`).
* **Negotiated Protocol & Cipher:** `TLSv1.3` using **`TLS_AES_256_GCM_SHA384`**—demonstrating how asymmetric X.509 certificates authenticate the connection and then hand off bulk data encryption to symmetric **AES-256-GCM**.

### 4. Mutual TLS (mTLS) Zero-Trust Authentication (`06-mtls-server.js` – `07-mtls-client.js`)
Configured an mTLS server (`requestCert: true`, `rejectUnauthorized: true`) on port `8444` backed by a shared internal Root CA (`mTLS Internal Root CA`):

| Client Attempt | Result | TLS Behavior |
| :--- | :--- | :--- |
| **No Client Certificate** | **REJECTED** | `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED` — dropped during TLS 1.3 handshake. |
| **Rogue Self-Signed Cert** | **REJECTED** | `ECONNRESET` — rejected because the certificate was not signed by the trusted Root CA. |
| **CA-Signed Client Cert** | **HTTP 200** | Authenticated client `CN=authorized-client-01` issued by `mTLS Internal Root CA`. |

### 5. Asymmetric Signatures & ECDHE Key Exchange (`08-rsa-vs-ecdsa-signatures.js` – `09-ecdhe-key-exchange.js`)

| Algorithm | KeyGen Time | Public Key Size | Key Takeaway |
| :--- | :--- | :--- | :--- |
| **RSA-2048** | `22.71ms` | `451 chars` | Widely compatible legacy/standard asymmetric algorithm; slower key generation and larger payloads. |
| **ECDSA (P-256)** | `0.187ms` | `178 chars` | **~121x faster** key generation and **60% smaller** keys with equivalent security—ideal for mobile, IoT, and TLS 1.3. |

* **Digital Signatures (`08-rsa-vs-ecdsa-signatures.js`):** Verified an authentic document (`true`) and immediately caught a 1-character modification (`false`) using an ECDSA SHA-256 signature.
* **ECDHE + AES-256-GCM (`09-ecdhe-key-exchange.js`):** Simulated Alice and Bob deriving an identical shared secret over a public channel via Elliptic Curve Diffie-Hellman Ephemeral (ECDHE), stretching it with HKDF, and encrypting traffic with **AES-256-GCM**.

### 6. Certificate Revocation Simulation (`10-cert-revocation.js`)
Demonstrated why checking **CRL (Certificate Revocation List)** or **OCSP (Online Certificate Status Protocol)** status by **Serial Number** is critical:
* `://example.com` (**Serial #1001**): Passed cryptographic signature verification and active revocation check (`[TRUSTED]`).
* `://example.com` (**Serial #1002**): Cryptographic signature and expiration date were still valid, but connection was blocked (`[REVOKED]`) because Serial `#1002` was flagged for `keyCompromise`.

### 7. Cryptographic Hashing, HMAC & Password Storage (`11-hashing-and-avalanche.js` – `13-password-salting-and-pbkdf2.js`)
* **SHA-256 & Avalanche Effect (`11-hashing-and-avalanche.js`):** Verified that inputs ranging from 2 bytes to 1 MB always produce a fixed 64-character hex digest, and changing a single character (`$500.00` -> `$500.01`) completely scrambles ~95%+ of the output characters.
* **HMAC-SHA256 Authentication (`12-hmac-message-auth.js`):** Demonstrated why plain hashes cannot prove authenticity, using a shared secret key and constant-time comparison (`crypto.timingSafeEqual`) to verify legitimate API webhooks and reject forged payloads.
* **Salted Password Key Stretching (`13-password-salting-and-pbkdf2.js`):** Showed why unsalted SHA-256 exposes duplicate passwords, then implemented per-user random 16-byte salts combined with memory-hard `scrypt` key derivation (`WrongPass123` -> `false`, `Summer2026!` -> `true`).

### 8. Hybrid Cryptography: Envelope Encryption & PGP Sign-then-Encrypt (`14-envelope-encryption.js` – `15-pgp-sign-and-encrypt.js`)
* **Cloud KMS Envelope Encryption (`14-envelope-encryption.js`):** Encrypted payload data with a fast 256-bit symmetric **Data Encryption Key (DEK)** using **AES-256-GCM**, wrapped the DEK with an asymmetric **RSA-OAEP Key Encryption Key (KEK)**, and zeroed the plaintext DEK from memory.
* **PGP-Style Sign-then-Encrypt (`15-pgp-sign-and-encrypt.js`):** Combined **ECDSA** digital signatures (authenticity + non-repudiation) with **ECDHE + AES-256-GCM** encryption (confidentiality) to securely transmit and verify an authorized message.

