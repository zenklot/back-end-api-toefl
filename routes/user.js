const express = require('express');
const { authLogin } = require('../middleware/verifyToken');

const router = express.Router();
const UserController = require('../controllers/UserController');

router.get('/', authLogin, UserController.getDetail);

module.exports = router;
