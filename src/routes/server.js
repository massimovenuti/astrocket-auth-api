const express = require('express');
const router = express.Router();

const serverCtrl = require('../controllers/server')

router.post('/add', serverCtrl.add);
router.post('/remove', serverCtrl.remove);
router.post('/check', serverCtrl.check);

module.exports = router;