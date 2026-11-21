const forge = require('node-forge');

// 1. Setup a Root CA
const caKeys = forge.pki.rsa.generateKeyPair(2048);
const caCert = forge.pki.createCertificate();
caCert.publicKey = caKeys.publicKey;
caCert.serialNumber = '01';
caCert.validity.notBefore = new Date();
caCert.validity.notAfter = new Date();
caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 5);
const caAttrs = [{ name: 'commonName', value: 'Enterprise Root CA' }];
caCert.setSubject(caAttrs);
caCert.setIssuer(caAttrs);
caCert.setExtensions([{ name: 'basicConstraints', cA: true }]);
caCert.sign(caKeys.privateKey, forge.md.sha256.create());

const caStore = forge.pki.createCaStore([caCert]);

// Helper to issue a server certificate with a unique Serial Number
function issueServerCert(domain, serialNumber) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject([{ name: 'commonName', value: domain }]);
  cert.setIssuer(caAttrs);
  cert.sign(caKeys.privateKey, forge.md.sha256.create());
  return cert;
}

// 2. Issue two valid certificates
const healthyCert = issueServerCert('://example.com', '1001');
const compromisedCert = issueServerCert('://example.com', '1002');

// 3. Simulated CA Revocation Database (CRL / OCSP Responder)
// Serial #1002 was reported compromised and revoked by the CA!
const revokedSerials = new Map([
  ['1002', { reason: 'keyCompromise', revokedAt: new Date().toISOString() }]
]);

// Full validation function: Cryptographic Signature + Expiration + Revocation Check
function validateCertificate(cert) {
  const cn = cert.subject.getField('CN').value;
  const serial = cert.serialNumber;

  // Step A: Verify cryptographic signature & expiration against Root CA
  try {
    forge.pki.verifyCertificateChain(caStore, [cert]);
  } catch (err) {
    return `[REJECTED] ${cn} (Serial #${serial}) -> Invalid signature or expired (${err.message})`;
  }

  // Step B: Check CRL / OCSP status by Serial Number
  if (revokedSerials.has(serial)) {
    const info = revokedSerials.get(serial);
    return `[REVOKED]  ${cn} (Serial #${serial}) -> Signature is valid, BUT revoked due to: ${info.reason}`;
  }

  return `[TRUSTED]  ${cn} (Serial #${serial}) -> Signature valid & active in OCSP/CRL!`;
}

console.log('--- CERTIFICATE REVOCATION (CRL / OCSP) SIMULATION ---\n');
console.log(validateCertificate(healthyCert));
console.log(validateCertificate(compromisedCert));
