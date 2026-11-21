const https = require('https');
const fs = require('fs');
const path = require('path');

const options = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'localhost.key')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'localhost.crt'))
};

const server = https.createServer(options, (req, res) => {
  const cipher = req.socket.getCipher();
  const protocol = req.socket.getProtocol();

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    message: 'Encrypted HTTPS connection established!',
    tlsVersion: protocol,
    negotiatedCipher: cipher.name,
    timestamp: new Date().toISOString()
  }, null, 2));
});

server.listen(8443, () => {
  console.log('HTTPS Server live at https://localhost:8443');
  console.log('Open a second terminal (+) and run: node 05-https-client.js');
});
