const forge = require('node-forge');
const https = require('https');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir);

// Helper to create and sign certificates
function issueCert(commonName, issuerAttrs, signingKey, isCa, serial, sanList = []) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const subjectAttrs = [{ name: 'commonName', value: commonName }];
  cert.setSubject(subjectAttrs);
  cert.setIssuer(issuerAttrs || subjectAttrs);

  const extensions = [{ name: 'basicConstraints', cA: isCa }];
  if (sanList.length > 0) {
    extensions.push({ name: 'subjectAltName', altNames: sanList });
  }
  cert.setExtensions(extensions);
  cert.sign(signingKey || keys.privateKey, forge.md.sha256.create());

  return {
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certPem: forge.pki.certificateToPem(cert),
    privateKey: keys.privateKey,
    subjectAttrs
  };
}

// 1. Create a Private Root CA for our mTLS network
const ca = issueCert('mTLS Internal Root CA', null, null, true, '200');
fs.writeFileSync(path.join(certsDir, 'mtls-ca.crt'), ca.certPem);

// 2. Issue Server Certificate signed by our CA
const serverCert = issueCert('localhost', ca.subjectAttrs, ca.privateKey, false, '201', [
  { type: 2, value: 'localhost' },
  { type: 7, ip: '127.0.0.1' }
]);

// 3. Issue a VALID Client Certificate signed by our CA
const validClient = issueCert('authorized-client-01', ca.subjectAttrs, ca.privateKey, false, '202');
fs.writeFileSync(path.join(certsDir, 'client.key'), validClient.keyPem);
fs.writeFileSync(path.join(certsDir, 'client.crt'), validClient.certPem);

// 4. Issue a ROGUE Client Certificate (Self-signed, NOT signed by our CA)
const rogueClient = issueCert('hacker-client', null, null, false, '666');
fs.writeFileSync(path.join(certsDir, 'rogue.key'), rogueClient.keyPem);
fs.writeFileSync(path.join(certsDir, 'rogue.crt'), rogueClient.certPem);

// 5. Start mTLS Server (Demands a valid client certificate!)
const serverOptions = {
  key: serverCert.keyPem,
  cert: serverCert.certPem,
  ca: ca.certPem,            // Trust certificates signed by our mTLS Root CA
  requestCert: true,         // Ask every connecting client for a certificate
  rejectUnauthorized: true   // Immediately drop connections without a valid CA-signed cert
};

const server = https.createServer(serverOptions, (req, res) => {
  const clientCert = req.socket.getPeerCertificate();
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'mTLS Mutual Authentication Succeeded!',
    authenticatedClientCN: clientCert.subject.CN,
    issuedBy: clientCert.issuer.CN
  }, null, 2));
});

server.listen(8444, () => {
  console.log('mTLS Server running on https://localhost:8444 (Client Cert REQUIRED)');
  console.log('Open a second terminal (+) and run: node 07-mtls-client.js');
});
