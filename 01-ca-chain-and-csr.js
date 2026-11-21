const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

// Create local output folder (ignored by git)
const outDir = path.join(__dirname, 'certs');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

function makeCert(subjectAttrs, issuerAttrs, publicKey, signingKey, isCa, serial) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(subjectAttrs);
  cert.setIssuer(issuerAttrs);
  cert.setExtensions([{ name: 'basicConstraints', cA: isCa }]);
  cert.sign(signingKey, forge.md.sha256.create());
  return cert;
}

console.log('--- 1. ROOT CA (Offline Trust Anchor) ---');
const rootKeys = forge.pki.rsa.generateKeyPair(2048);
const rootAttrs = [{ name: 'commonName', value: 'My Offline Root CA' }];
const rootCert = makeCert(rootAttrs, rootAttrs, rootKeys.publicKey, rootKeys.privateKey, true, '01');
console.log(`Subject: ${rootCert.subject.getField('CN').value}`);
console.log(`Issuer:  ${rootCert.issuer.getField('CN').value} (Matches Subject = Self-Signed Root!)\n`);

console.log('--- 2. INTERMEDIATE CA (Day-to-Day Signer) ---');
const intKeys = forge.pki.rsa.generateKeyPair(2048);
const intAttrs = [{ name: 'commonName', value: 'My Intermediate Issuing CA' }];
// Intermediate is signed by Root's private key
const intCert = makeCert(intAttrs, rootAttrs, intKeys.publicKey, rootKeys.privateKey, true, '02');
console.log(`Subject: ${intCert.subject.getField('CN').value}`);
console.log(`Issuer:  ${intCert.issuer.getField('CN').value}\n`);

console.log('--- 3. CSR (Certificate Signing Request) ---');
const serverKeys = forge.pki.rsa.generateKeyPair(2048);
const csr = forge.pki.createCertificationRequest();
csr.publicKey = serverKeys.publicKey;
csr.setSubject([{ name: 'commonName', value: '://example.com' }]);
csr.sign(serverKeys.privateKey); // Proves requester owns the private key without sending it!
console.log(`CSR Subject: ${csr.subject.getField('CN').value}`);
console.log(`CSR Signature Valid (Private key stayed local): ${csr.verify()}\n`);

console.log('--- 4. SERVER CERT & CHAIN VERIFICATION ---');
// Intermediate CA signs the server's CSR public key
const serverCert = makeCert(csr.subject.attributes, intAttrs, csr.publicKey, intKeys.privateKey, false, '03');
const caStore = forge.pki.createCaStore([rootCert]);
const chainValid = forge.pki.verifyCertificateChain(caStore, [serverCert, intCert]);
console.log(`Server Cert Issued By: ${serverCert.issuer.getField('CN').value}`);
console.log(`Full Chain Verified (Server -> Intermediate -> Root): ${chainValid}\n`);

console.log('--- 5. SELF-SIGNED CERT (Lab / Testing) ---');
const selfKeys = forge.pki.rsa.generateKeyPair(2048);
const selfAttrs = [{ name: 'commonName', value: 'localhost-dev' }];
const selfCert = makeCert(selfAttrs, selfAttrs, selfKeys.publicKey, selfKeys.privateKey, false, '04');
console.log(`Subject: ${selfCert.subject.getField('CN').value} | Issuer: ${selfCert.issuer.getField('CN').value}`);
console.log(`Trusted by Root CA Store? ${(() => { try { return forge.pki.verifyCertificateChain(caStore, [selfCert]); } catch (e) { return 'FALSE (' + e.message + ')'; } })()}`);
