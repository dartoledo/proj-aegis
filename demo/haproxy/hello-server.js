'use strict';

const http = require('node:http');

const port = Number(process.env.PORT || 8080);

const server = http.createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'hello-world-app' }));
    return;
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      service: 'hello-world-app',
      message: 'Hello World from Project Aegis HAProxy TLS Sandbox',
      timestamp: new Date().toISOString(),
    }),
  );
});

if (require.main === module) {
  server.listen(port, '0.0.0.0', () => {
    process.stdout.write(`hello-world-app listening on 0.0.0.0:${port}\n`);
  });
}

module.exports = { server };
