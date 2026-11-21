const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir);

const keys = forge.pki.rsa.generateKeyPair(2048);
const cert = forge.pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '100';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

const attrs = [{ name: 'commonName', value: 'localhost' }];
cert.setSubject(attrs);
cert.setIssuer(attrs);
cert.setExtensions([
  {
    name: 'subjectAltName',
    altNames: [
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' }
    ]
  }
]);
cert.sign(keys.privateKey, forge.md.sha256.create());

fs.writeFileSync(path.join(certsDir, 'localhost.key'), forge.pki.privateKeyToPem(keys.privateKey));
fs.writeFileSync(path.join(certsDir, 'localhost.crt'), forge.pki.certificateToPem(cert));

console.log('Saved certs/localhost.key and certs/localhost.crt!');
