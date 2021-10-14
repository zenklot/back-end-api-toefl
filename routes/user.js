const express = require('express');
const { authLogin } = require('../middleware/verifyToken');

const router = express.Router();
const UserController = require('../controllers/UserController');

router.get('/details', authLogin, UserController.getDetail);
router.put('/updates', authLogin, UserController.putUpdate);

module.exports = router;
