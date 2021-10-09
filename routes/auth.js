const express = require('express');
const { authLogin, authEmailVerify } = require('../middleware/verifyToken');

const router = express.Router();
const AuthController = require('../controllers/AuthController');

router.get('/', authLogin, AuthController.methodGet);
router.post('/auth/register', AuthController.register);
router.post('/auth/login', AuthController.login);
router.post('/auth/refresh-token', AuthController.postRefreshToken);
router.get('/auth/logout', authLogin, AuthController.logout);
router.put('/auth/verify-email/:token', authEmailVerify, AuthController.emailVerifycation);
module.exports = router;
