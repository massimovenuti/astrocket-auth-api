const dbConfig = require('../config/dbConfig');
const knex = require('knex')(dbConfig);
const crypto = require('crypto');

exports.add = (req, res, next) => {
    knex('tokens').innerJoin('users', 'tokens.idUser', 'users.idUser').where({ strToken: req.body['user_token'] }).select('role')
        .then((data) => {
            if (data[0].role === 'A') {
                let token = crypto.randomBytes(75).toString('hex');
                knex('servers').insert({
                    idServer: knex.raw('NEXTVAL(s_tokens)'),
                    serverName: req.body['name'],
                    serverToken: token
                }).then(() => {
                    res.status(200).send('OK');
                })
                    .catch((err) => {
                        res.status(400).send('Bad');
                    })
            } else {
                res.status(401).send("bad token");
            }
        })
        .catch((err) => {
            res.status(401).send("bad token");
        });
}

exports.remove = (req, res, next) => {
    knex('tokens').innerJoin('users', 'tokens.idUser', 'users.idUser').where({ strToken: req.body['user_token'] }).select('role')
        .then((data) => {
            if (data[0].role === 'A') {
                knex('servers').delete().where({ serverName: req.body['name'] })
                    .then(() => {
                        res.status(200).send('OK');
                    })
                    .catch((err) => {
                        res.status(400).send('Bad name');
                    })
            } else {
                res.status(401).send("bad token");
            }
        })
        .catch((err) => {
            res.status(401).send("bad token");
        });
}

exports.check = (req, res, next) => {
    knex('tokens').select('serverName').where({ serverToken: req.body['token'] })
        .then((data) => {
            res.status(200).json({
                name: data[0].serverName
            });
        })
        .catch((err) => {
            res.status(400).send("bad token");
        });
}