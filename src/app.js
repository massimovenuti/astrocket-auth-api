const express = require('express');
const bodyParser = require('body-parser');

const userRoutes = require('./routes/user');
const serverRoutes = require('./routes/server');

const app = express();

app.use(bodyParser.json());

app.use('/user', userRoutes);

app.use('/server', serverRoutes);

module.exports = app;