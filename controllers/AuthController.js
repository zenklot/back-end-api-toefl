const { nanoid } = require('nanoid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const { validation } = require('../middleware/validation');
require('dotenv').config();
const User = require('../models/User');
const EmailValid = require('../models/EmailValid');

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

    // save token valid to db and send email verifikasi
    const kodeId = nanoid();

    const emailValidasi = new EmailValid({
      userId: savedUser._id,
      token: kodeId,
    });

    await emailValidasi.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_PASS,
      },
    });

    const mailOptions = {
      from: '"TOEFL" <noreplyl@toefl.com>',
      to: email,
      subject: 'Verifikasi Alamat Email',
      html: `<h3>Silahkan Klik Tombol Dibawah Untuk Verifikasi Email</h3>
      <a href="http://${req.headers.host}/api/user/verify-email?id=${kodeId}" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';box-sizing:border-box;border-radius:3px;color:#fff;display:inline-block;text-decoration:none;background-color:#3490dc;border-top:10px solid #3490dc;border-right:18px solid #3490dc;border-bottom:10px solid #3490dc;border-left:18px solid #3490dc" target="_blank">Verifikasi Alamat Email</a>
      `,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) throw err;
      console.log(`Email sent: ${info.response}`);
    });

    const { _id: ids, createdAt: crtd, updatedAt: uptd } = savedUser;
    const dataUser = {
      _id: ids,
      createdAt: crtd,
      updateAt: uptd,
    };
    res.status(201).json({
      status: 201,
      message: 'Created',
      data: dataUser,
    });
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

    res.json({
      status: 200,
      message: 'Everything is OK',
      data: { message: 'Login success!' },
    });
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
    const hapusToken = jwt.sign({ id: '' }, process.env.KUNCI_TOKEN,
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
