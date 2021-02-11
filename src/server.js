const http = require('http');
const fs = require('fs');
const app = require('./app');

app.set('port', process.env.PORT || 8080);

const server = http.createServer(app);

server.listen(process.env.PORT || 8080);
console.log("Server run");