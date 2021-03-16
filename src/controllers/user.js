// fonctionnel jusqu'à server add
const dbConfig = require('../config/dbConfig');
const knex = require('knex')(dbConfig);
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

exports.add = (req, res, next) => {
    const checkUsername = /^[a-zA-Z][a-zA-Z0-9]+$/;
    const checkEmail = /^[a-z0-9A-Z-_.]+@[a-z0-9A-Z-_.]+\.[a-z]{2,}/;
    if(!req.body.username || !req.body.password || !req.body.email) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else if(!checkUsername.test(req.body.username)){
        res.status(402).send('Nom d\'utilisateur non valide');
    } else if(!checkEmail.test(req.body.email)){
        res.status(403).send('Email non valide');
    } else {
        knex('users').insert({
            idUser: knex.raw('NEXTVAL(s_users)'),
            username: req.body['username'],
            pwd: bcrypt.hashSync(req.body['password'], saltRounds),
            email: req.body['email'],
        })
            .then(() => {
                knex('users').select('idUser').where({ username: req.body['username'] })
                    .then((data) => {
                        let token = crypto.randomBytes(40).toString('hex');
                            knex('tokens').insert({
                                idToken: knex.raw('NEXTVAL(s_tokens)'),
                                idUser: data[0].idUser,
                                strToken: token,
                                expirationDate: knex.raw('DATE_ADD(NOW(), INTERVAL 1 DAY)')
                            })
                                .then(() => {
                                    res.status(200).json({
                                        token: token
                                    });
                                })
                                .catch((err) => {
                                    console.error(err);
                                    res.status(500).send('Internal Server Error');
                                })
                    })
                    .catch((err) => {
                        console.error(err);
                        res.status(500).send('Internal Server Error');
                    });
            })
            .catch((err) => {
                if (err.code === 'ER_DUP_ENTRY') {
                    res.status(401).send("L'utilisateur ou l'email existe déjà");
                } else {
                    console.error(err);
                    res.status(500).send('Internal Server Error');
                }
            });
    }
}

exports.remove = (req, res, next) => {
    if(!req.body.token || !req.body.username) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({ strToken: req.body.token })
            .then((data) => {
                if (data[0].role == 'A') {
                    knex('users').select('idUser').where({ username: req.body['username'] })
                        .then((rows) =>{
                            if(rows[0]){
                                knex('users').where({ username: req.body.username }).del()
                                    .then(() => {
                                        res.status(200).send('Utilisateur retiré');
                                    })
                                    .catch((err) => {
                                        console.error(err);
                                        res.status(500).send('Internal Server Error');
                                    });
                            } else {
                                res.status(403).send('Nom d\'utilisateur non valide');
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

exports.login = (req, res, next) => {
    if(!req.body.username || !req.body.password) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').select('idUser', 'pwd').where({ username: req.body['username'] })
            .then((data) => {
                if(data[0]){
                    if (bcrypt.compareSync(req.body['password'], data[0].pwd)) {
                        knex('bans').select('idUser').where({ idUser: data[0].idUser })
                            .then((rows) => {
                                if(rows[0]) {
                                    res.status(401).send('Connexion refusée l\'utilisateur est banni');
                                } else {
                                    let token = crypto.randomBytes(40).toString('hex');
                                    knex('tokens').insert({
                                        idToken: knex.raw('NEXTVAL(s_tokens)'),
                                        idUser: data[0].idUser,
                                        strToken: token,
                                        expirationDate: knex.raw('DATE_ADD(NOW(), INTERVAL 1 DAY)')
                                    })
                                        .then(() => {
                                            res.status(200).json({
                                                token: token
                                            });
                                        })
                                        .catch((err) => {
                                            console.error(err);
                                            res.status(500).send('Internal Server Error');
                                        })
                                }        
                            })
                            .catch((err) => {
                                console.error(err);
                                res.status(500).send('Internal Server Error');
                            })
                    } else {
                        res.status(403).send('Mot de passe non valide');
                    }
                } else {
                    res.status(402).send('Nom d\'utilisateur / mot de passe non valide');
                }
            })
            .catch((err) => {
                console.log(err);
                res.status(500).send('Internal Server Error');
            });
    }
}

exports.check = (req, res, next) => {
    if(!req.body.token) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('username', 'role').where({ strToken: req.body.token })
            .then((data) => {
                if(data[0]){
                    res.status(200).json({
                        username: data[0].username,
                        role: data[0].role
                    });
                } else {
                    res.status(401).send('Token non valide');
                }
            })
            .catch((err) => {
                console.error(err);
                res.status(500).send('Internal Server Error');
            });
    }
}

exports.ban = (req, res, next) => {
    if(!req.body.token || !req.body.username) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({ strToken: req.body.token })
            .then((data) => {
                if (data[0].role == 'A') {
                    knex('users').select('idUser').where({ username: req.body.username })
                        .then((data2) => {
                            knex('bans').select('idUser').where({ idUser: data2[0].idUser })
                                .then((rows) => {
                                    if(rows[0]) {
                                        res.status(404).send('L\'utilisateur est déjà banni');
                                    } else {
                                        knex('bans').insert({
                                            idUser: data2[0].idUser,
                                            banEnd: knex.raw(`(DATE(NOW()) + INTERVAL 14 DAY)`),
                                        })
                                            .then(() => {
                                                res.status(200).send('Bannissement réussi');
                                            })
                                            .catch((err) => {
                                                res.status(500).send('Internal Server Error');
                                            });
                                    }
                                })
                                .catch((err) => {
                                    console.error(err);
                                    res.status(500).send('Internal Server Error');
                                });
                        })
                        .catch((err) => {
                            res.status(403).send('Nom d\'utilisateur non valide');
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

exports.unban = (req, res, next) => {
    if(!req.body.token || !req.body.username) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({ strToken: req.body.token })
            .then((data) => {
                if (data[0].role == 'A') {
                    knex('users').select('idUser').where({ username: req.body.username })
                        .then((data2) => {
                            knex('bans').select('idUser').where({ idUser: data2[0].idUser })
                                .then((rows) => {
                                    if(rows[0]) {
                                        knex('bans').where({ idUser: data2[0].idUser }).del()
                                            .then(() => {
                                                res.status(200).send('Suspension levé');
                                            })
                                            .catch((err) => {
                                                res.status(500).send('Internal Server Error');
                                            });
                                    } else {
                                        res.status(404).send('L\'utilisateur n\'est pas banni');
                                    }
                                })
                                .catch((err) => {
                                    res.status(401).send('Nom d\'utilisateur non valide');
                                });
                        })
                        .catch((err) => {
                            res.status(403).send('Nom d\'utilisateur non valide');
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

exports.admin = (req, res, next) => {
    if(!req.body.token || !req.body.username) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({ strToken: req.body.token })
            .then((data) => {
                if (data[0].role == 'A') {
                    knex('users').select('role').where({ username: req.body.username })
                        .then((rows) => {
                            if(rows[0].role == 'A'){
                                res.status(404).send('L\'utilisateur est déjà administrateur');
                            } else {
                                knex('users').where({ username: req.body['username'] }).update({ role: 'A' })
                                    .then(() => {
                                        res.status(200).send('Attribution des droits d\'administrateur réussie');
                                    })
                                    .catch((err) => {
                                        console.error(err);
                                        res.status(500).send('Internal Server Error');
                                    });
                            }
                        }).catch((err) => {
                            res.status(403).send('Nom d\'utilisateur non valide');
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

exports.unadmin = (req, res, next) => {
    if(!req.body.token || !req.body.username) {
        res.status(400).send("Requête invalide : attribut(s) manquant(s)");
    } else {
        knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({ strToken: req.body.token })
            .then((data) => {
                if (data[0].role == 'A') {
                    knex('users').select('role').where({ username: req.body.username })
                        .then((rows) => {
                            if(rows[0].role == 'U'){
                                res.status(404).send('Les privilèges d\'un utilisateur sont déjà limités')
                            } else {
                                knex('users').where({ username: req.body['username'] }).update({ role: 'U' })
                                    .then(() => {
                                        res.status(200).send('Retrait des privilèges réussi');
                                    })
                                    .catch((err) => {
                                        console.error(err);
                                        res.status(500).send('Internal Server Error');
                                    });
                            }
                        })
                        .catch((err) => {
                            res.status(403).send('Nom d\'utilisateur non valide');
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
