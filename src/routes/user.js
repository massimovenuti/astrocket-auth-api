const express = require('express');
const router = express.Router();

const userCtrl = require('../controllers/user')

router.post('/add', userCtrl.add);
router.post('/remove', userCtrl.remove);
router.post('/login', userCtrl.login);
router.post('/check', userCtrl.check);
router.post('/ban', userCtrl.ban);
router.post('/unban', userCtrl.unban);
router.post('/admin', userCtrl.admin);
router.post('/unadmin', userCtrl.unadmin);

module.exports = router;