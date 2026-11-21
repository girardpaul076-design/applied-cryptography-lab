const https = require('https');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');
const caCert = fs.readFileSync(path.join(certsDir, 'mtls-ca.crt'));

function testConnection(label, clientKeyFile, clientCertFile) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'localhost',
      port: 8444,
      path: '/',
      method: 'GET',
      ca: caCert // Client trusts the server's CA
    };

    // Attach client certificate & key if provided
    if (clientKeyFile && clientCertFile) {
      options.key = fs.readFileSync(path.join(certsDir, clientKeyFile));
      options.cert = fs.readFileSync(path.join(certsDir, clientCertFile));
    }

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        console.log(`[${label}] HTTP ${res.statusCode}\n${body}\n`);
        resolve();
      });
    });

    req.on('error', (err) => {
      console.log(`[${label}] REJECTED at TLS Handshake -> ${err.code || err.message}\n`);
      resolve();
    });

    req.end();
  });
}

(async () => {
  console.log('--- TESTING MUTUAL TLS (mTLS) AUTHENTICATION ---\n');

  // Attempt 1: No client certificate presented
  await testConnection('Test 1: No Client Cert', null, null);

  // Attempt 2: Untrusted self-signed ("rogue") client certificate
  await testConnection('Test 2: Rogue Client Cert', 'rogue.key', 'rogue.crt');

  // Attempt 3: Valid client certificate signed by mTLS Internal Root CA
  await testConnection('Test 3: Valid CA-Signed Client Cert', 'client.key', 'client.crt');
})();
