const spdy = require('spdy')
const fs = require('fs')

const app = require('./app');

const port = 3010

const options = {
    key: fs.readFileSync(__dirname + '/keys/auth_server.key'),
    cert: fs.readFileSync(__dirname + '/keys/auth_server.crt')
}

spdy
    .createServer(options, app)
    .listen(port, (error) => {
        if (error) {
            console.error(error)
            return process.exit(1)
        } else {
            console.log('Listening on port: ' + port + '.')
        }
    })