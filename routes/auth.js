const express = require('express');
const {
  authLogin, authEmailVerify, refreshTokenVerify, forgetPwdToken,
} = require('../middleware/verifyToken');
const { authRole } = require('../middleware/rolePermission');

const router = express.Router();
const AuthController = require('../controllers/AuthController');
const { ROLE } = require('../permissions/userRole');

router.get('/', authLogin, authRole(ROLE.ADMIN), AuthController.methodGet);
router.post('/register', AuthController.postRegister);
router.post('/login', AuthController.postLogin);
router.post('/refresh-token', refreshTokenVerify, AuthController.postRefreshToken);
router.get('/logout', authLogin, AuthController.getLogout);
router.put('/verify-email/:token', authEmailVerify, AuthController.putEmailVerifycation);
router.get('/:id/verify-email', authLogin, AuthController.getEmailValidation);
router.post('/forget-password/', AuthController.postForgetPassword);
router.put('/forget-password/', forgetPwdToken, AuthController.putForgetPassword);

module.exports = router;
