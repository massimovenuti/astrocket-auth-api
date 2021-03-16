const dbConfig = require('../config/dbConfig');
const knex = require('knex')(dbConfig);
const crypto = require('crypto');

exports.add = (req, res, next) => {
    if(!req.body.name || !req.body.user_token) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('tokens').innerJoin('users', 'tokens.idUser', 'users.idUser').where({ strToken: req.body['user_token'] }).select('role')
        .then((data) => {
            if (data[0].role === 'A') {
                let token = crypto.randomBytes(75).toString('hex');
                knex('servers').insert({
                    idServer: knex.raw('NEXTVAL(s_tokens)'),
                    serverName: req.body['name'],
                    serverToken: token
                })
                    .then(() => {
                        res.status(200).json({
                            token: token
                        });
                    })
                    .catch((err) => {
                        if (err.code === 'ER_DUP_ENTRY') {
                            res.status(403).send("Le serveur existe déjà");
                        } else {
                            console.error(err);
                            res.status(500).send('Internal Server Error');
                        }
                    })
            } else {
                res.status(402).send("Le token n'appartient pas à un administrateur");
            }
        })
        .catch((err) => {
            res.status(401).send("Token non valide");
        });
    }
}

exports.remove = (req, res, next) => {
    if(!req.body.name || !req.body.token) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('tokens').innerJoin('users', 'tokens.idUser', 'users.idUser').where({ strToken: req.body['token'] }).select('role')
            .then((data) => {
                if (data[0].role === 'A') {
                    knex('servers').select('idServer').where({ serverName: req.body['name'] })
                        .then((rows) => {
                            if(rows[0]){
                                knex('servers').delete().where({ serverName: req.body['name'] })
                                    .then(() => {
                                        res.status(200).send('Serveur retiré');
                                    })
                                    .catch((err) => {
                                        console.error(err);
                                        res.status(500).send('Internal Server Error');
                                    })
                            } else {
                                res.status(403).send('Nom du serveur non valide');
                            }
                        })
                        .catch((err) => {
                            console.error(err);
                            res.status(500).send('Internal Server Error');
                        });
                } else {
                    res.status(402).send('Le token n\'appartient pas à un administrateur');
                }
            })
            .catch((err) => {
                res.status(401).send('Token non valide');
            });
    }
}

exports.check = (req, res, next) => {
    if(!req.body.token) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('servers').select('serverName').where({ serverToken: req.body['token'] })
            .then((data) => {
                res.status(200).json({
                    name: data[0].serverName
                });
            })
            .catch((err) => {
                res.status(401).send("Token non valide");
            });
    }
}