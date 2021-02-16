const dbConfig = require('../config/dbConfig');
const knex = require('knex')(dbConfig);
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

exports.add = (req, res, next) => {
    knex('users').insert({
        idUser: knex.raw('NEXTVAL(s_users)'),
        username: req.body['username'],
        pwd: bcrypt.hashSync(req.body['password'], saltRounds),
        email: req.body['email'],
    })
    .then( () => {
        res.status(200).send('OK');
    })
    .catch((err) => {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(401).send("L'utilisateur existe déjà");
        } else {
            res.status(400).send('Bad');
        }
    });
}

exports.remove = (req, res, next) => {
    knex('users').join('tokens', 'users.idUser', '=', 'tokens.idUser').select('role').where({strToken: req.body.token})
    .then( (data) => {
        if(data[0].role == 'A') {
            knex('users').where({username: req.body.username}).del()
            .then ( () => {
                res.status(200).send('Utilisateur retiré');
            })
            .catch((err) => {
                res.status(401).send('Nom d\'utilisateur non valide');
            });
        } else {
            res.status(400).send('Token non valide');
        }
    })
    .catch((err) => {
        res.status(400).send('Token non valide');
    });
    next();
}

exports.login = (req, res, next) => {
    knex('users').select('idUser', 'pwd').where({username: req.body['username']})
    .then((data) => {
        if (bcrypt.compareSync(req.body['password'] ,data[0].pwd)) {
            let token = crypto.randomBytes(40).toString('hex');
            knex('tokens').insert({
                idToken: knex.raw('NEXTVAL(s_users)'),
                idUser: data[0].idUser,
                strToken: token,
                expirationDate: knex.raw('SYSDATE()+1') // not work
            }).then(()=> {
                res.status(200).json({
                    token: token
                });
            })
            .catch((err)=> {
                console.log(err);
                res.status(400).send('Bad');
            })
        } else {
            res.status(400).send('Bad');
        }
    })
    .catch((err) => {
        console.log(err);
        res.status(400).send('Bad');
    });
}

exports.check = (req, res, next) => {
    knex('users')
        .join('tokens', 'users.idUser', '=', 'tokens.idUser')
        .select('username,role')
        .where({strToken: req.body.token})
    .then( (data) => {
        res.status(200).json({
            username: data[0].username,
            role: data[0].role
        });
    })
    .catch((err) => {
        res.status(400).send('Token non valide');
    });
    next();
}

exports.ban = (req, res, next) => {
    knex('users')
        .join('tokens', 'users.idUser', '=', 'tokens.idUser')
        .select('role')
        .where({strToken: req.body.token})
    .then( (data) => {
        if(data[0].role == 'A') {
            knex('users')
                .select('idUser')
                .where({username: req.body.username})
            .then( (data2) => {
                knex('bans').insert({
                    idUser: data2[0].idUser,
                    banEnd: knex.raw(`(DATE(NOW()) + INTERVAL 14 DAY)`),
                    //knex.raw('date_add(?, INTERVAL ? day)', [knex.fn.now(), 14])
                })
                .then( () => {
                    res.status(200).send('Bannissement réussi');
                })
                .catch( (err) => {
                    res.status(400).send('Bad');
                });
            })
            .catch( (err) => {
                res.status(400).send('Nom d\'utilisateur non valide');
            });
        } else {
            res.status(402).send('Token non valide');
        }
    })
    .catch((err) => {
        res.status(402).send('Token non valide');
    });
    next();
}

exports.unban = (req, res, next) => {
    knex('users')
        .join('tokens', 'users.idUser', '=', 'tokens.idUser')
        .select('role')
        .where({strToken: req.body.token})
    .then( (data) => {
        if(data[0].role == 'A') {
            knex('users')
                .select('idUser')
                .where({username: req.body.username})
            .then ( (data2) => {
                knex('bans').where({idUser: data2[0].idUser}).del()
                .then( () => {
                    res.status(200).send('Suspension levé');
                })
                .catch( (err) => {
                    res.status(402).send('L\'utilisateur n\'est pas banni');
                });
            })
            .catch((err) => {
                res.status(401).send('Nom d\'utilisateur non valide');
            });
        } else {
            res.status(400).send('Token non valide');
        }
    })
    .catch((err) => {
        res.status(400).send('Token non valide');
    });
    next();
}

exports.admin = (req, res, next) => {
    knex('users')
        .join('tokens', 'users.idUser', '=', 'tokens.idUser')
        .select('role')
        .where({strToken: req.body.token})
    .then( (data) => {
        if(data[0].role == 'A') {
            knex('users')
                .where({username: req.body['username']})
                .update({role: 'A'})
            .then ( () => {
                res.status(200).send('Attribution des droits d\'administrateur réussie');
            })
            .catch((err) => {
                res.status(401).send('Nom d\'utilisateur non valide');
            });
        } else {
            res.status(400).send('Token non valide');
        }
    })
    .catch((err) => {
        res.status(400).send('Token non valide');
    });
    next();
}

exports.unadmin = (req, res, next) => {
    knex('users')
        .join('tokens', 'users.idUser', '=', 'tokens.idUser')
        .select('role')
        .where({strToken: req.body.token})
    .then( (data) => {
        if(data[0].role == 'A') {
            knex('users')
                .where({username: req.body['username']})
                .update({role: 'U'})
            .then ( () => {
                res.status(200).send('Retrait des privilèges réussi');
            })
            .catch((err) => {
                res.status(401).send('Nom d\'utilisateur non valide');
            });
        } else {
            res.status(400).send('Token non valide');
        }
    })
    .catch((err) => {
        res.status(400).send('Token non valide');
    });
    next();
}