const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validation } = require('../middleware/validation');
require('dotenv').config();
const User = require('../models/User');

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validasi ngambil dari middle ware
    const { error } = validation(req.body);
    if (error) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: error.details[0].message },
      });
      return;
    }

    // enkripsi
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = await bcrypt.hashSync(password, salt);
    const user = new User({
      name,
      email,
      password: hashedPassword,
    });

    // save ke db
    const savedUser = await user.save();
    res.json(savedUser);
  } catch (error) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: error.message },
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const data = await User.findOne({ email });

    if (!data) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User is not registered!' },
      });
      return;
    }

    // deskrip
    const resultLogin = bcrypt.compareSync(password, data.password);

    if (!resultLogin) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'Password wrong!' },
      });
      return;
    }
    /* eslint no-underscore-dangle: ["error", { "allow": ["_id"] }] */
    const token = jwt.sign({ id: data._id }, process.env.KUNCI_TOKEN,
      { expiresIn: process.env.KUNCI_TOKEN_EXP });
    const refreshToken = jwt.sign({ id: data._id }, process.env.REFRESH_TOKEN,
      { expiresIn: process.env.REFRESH_TOKEN_EXP });

    res.header({ 'auth-token': token, 'refresh-token': refreshToken });
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 5 * 60 * 60 * 1000,
    });
    res.cookie('ref-token', refreshToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.json('berhasil Login');
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'There was an error on the server and the request could not be completed',
      data: { message: error.message },
    });
  }
};

const postRefreshToken = (req, res) => {
  try {
    const { refreshToken } = req.body;
    const verifikasi = jwt.verify(refreshToken, process.env.REFRESH_TOKEN);
    const token = jwt.sign({ id: verifikasi._id }, process.env.KUNCI_TOKEN,
      { expiresIn: process.env.KUNCI_TOKEN_EXP });
    res.header({ 'auth-token': token, 'refresh-token': refreshToken });
    res.status(200).json({
      status: 200,
      message: 'Everything is OK',
      data: { message: 'Refresh Token Berhasil!' },
    });
  } catch (error) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: error.message },
    });
  }
};

// eslint-disable-next-line consistent-return
const logout = (req, res) => {
  try {
    const token = req.header('auth-token') || req.cookies.token;
    if (!token) {
      return res.status(401).json('Maaf Anda Harus Login Terlebih Dahulu!');
    }
    const verifikasi = jwt.verify(token, process.env.KUNCI_TOKEN);
    const hapusToken = jwt.sign({ id: verifikasi._id }, process.env.KUNCI_TOKEN,
      { expiresIn: '0s' });
    res.header({ 'auth-token': hapusToken, 'refresh-token': hapusToken });
    res.cookie('token', '', { maxAge: 0 });
    res.cookie('ref-token', '', { maxAge: 0 });
    // res.redirect('/api/');
    res.status(200).json({
      status: 200,
      message: 'Everything is OK',
      data: { message: 'Logout success!' },
    });
  } catch (error) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: error.message },
    });
  }
};

const methodGet = (req, res) => {
  res.json('contoh get');
};

module.exports = {
  register,
  login,
  postRefreshToken,
  logout,
  methodGet,
};
