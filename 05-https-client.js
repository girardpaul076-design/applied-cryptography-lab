const https = require('https');
const fs = require('fs');
const path = require('path');

const trustedCert = fs.readFileSync(path.join(__dirname, 'certs', 'localhost.crt'));

const options = {
  hostname: 'localhost',
  port: 8443,
  path: '/',
  method: 'GET',
  ca: trustedCert
};

const req = https.request(options, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    console.log(`Status: ${res.statusCode}`);
    console.log('Response from HTTPS Server:\n' + data);
  });
});

req.on('error', (err) => console.error('Connection failed:', err.message));
req.end();
