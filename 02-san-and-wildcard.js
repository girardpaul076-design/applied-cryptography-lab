const forge = require('node-forge');
const tls = require('tls');

// Generate a certificate with SAN + Wildcard extensions
const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '05';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{ name: 'commonName', value: '*.example.com' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);

// Add Subject Alternative Name (SAN) extension
cert.setExtensions([
  {
    name: 'subjectAltName',
    altNames: [
      { type: 2, value: 'example.com' },       // Apex domain
      { type: 2, value: '://example.com' },   // Explicit SAN
      { type: 2, value: '*.example.com' }      // First-level wildcard
    ]
  }
]);
cert.sign(keys.privateKey, forge.md.sha256.create());

// Convert to PEM and load into Node's native X509Certificate inspector
const pem = forge.pki.certificateToPem(cert);
const x509 = new (require('crypto').X509Certificate)(pem);

console.log('--- INSPECTING SAN & WILDCARD CERTIFICATE ---');
console.log(`Subject Alternative Names: ${x509.subjectAltName}\n`);

const testDomains = [
  'example.com',         // Covered by explicit SAN
  '://example.com',     // Covered by explicit SAN & wildcard
  '://example.com',    // Covered by *.example.com (1st-level subdomain)
  '://example.com',     // NOT covered! Wildcards only match ONE level
  'evil-example.com'     // NOT covered!
];

console.log('--- HOSTNAME VERIFICATION RESULTS ---');
for (const domain of testDomains) {
  const matched = x509.checkHost(domain);
  console.log(`${matched ? '[PASS]' : '[FAIL]'} ${domain}`);
}
