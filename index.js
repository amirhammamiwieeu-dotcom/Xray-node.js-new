require('http').createServer((q, r) => r.end('OK'))
  .listen(process.env.SERVER_PORT || process.env.PORT || 8080);
