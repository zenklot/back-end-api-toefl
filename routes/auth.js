const express = require('express');
const verifyToken = require('../middleware/verifyToken');

const router = express.Router();
const AuthController = require('../controllers/AuthController');

router.get('/', verifyToken, AuthController.methodGet);
router.post('/auth/register', AuthController.register);
router.post('/auth/login', AuthController.login);

module.exports = router;
