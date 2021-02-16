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
    
}

exports.ban = (req, res, next) => {
    
}

exports.unban = (req, res, next) => {
    
}

exports.admin = (req, res, next) => {
    
}

exports.unadmin = (req, res, next) => {
    
}