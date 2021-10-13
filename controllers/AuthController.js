const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { validUserReg, validForgetPwd } = require('../middleware/validation');
const { transporter } = require('../helpers/sendMail');
require('dotenv').config();
const User = require('../models/User');

const postRegister = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validasi ngambil dari middle ware
    const { error } = validUserReg(req.body);
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

    // Buat token Untuk Validasi Email
    const token = jwt.sign({ email }, process.env.KUNCI_VALID_EMAIL,
      { expiresIn: process.env.KUNCI_VALID_EMAIL_EXP });

    // Format Email
    const mailOptions = {
      from: '"TOEFL" <noreplyl@toefl.com>',
      to: email,
      subject: 'Verifikasi Alamat Email',
      html: `<h3>Silahkan Klik Tombol Dibawah Untuk Verifikasi Email</h3>
      <a href="${process.env.CLIENT_HOST}/auth/verify-email/${token}" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';box-sizing:border-box;border-radius:3px;color:#fff;display:inline-block;text-decoration:none;background-color:#3490dc;border-top:10px solid #3490dc;border-right:18px solid #3490dc;border-bottom:10px solid #3490dc;border-left:18px solid #3490dc" target="_blank">Verifikasi Alamat Email</a>
      `,
    };

    // Kirim Email ngambil dari helper
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

const postLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    // Tambah deteksi case insensitif
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

const postRefreshToken = async (req, res) => {
  const { id } = req.user;
  const searchUser = await User.findById(id);
  if (!searchUser) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: 'User Not Found!' },
    });
    return;
  }
  const token = jwt.sign({ id }, process.env.KUNCI_TOKEN,
    { expiresIn: process.env.KUNCI_TOKEN_EXP });
  const refreshToken = jwt.sign({ id }, process.env.REFRESH_TOKEN,
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
    data: { message: 'Refresh Token Success!' },
  });
};

// eslint-disable-next-line consistent-return
const getLogout = (req, res) => {
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

const putEmailVerifycation = async (req, res) => {
  const { email } = req.user;
  const newUserData = await User.findOneAndUpdate({ email },
    { verification: true },
    { returnOriginal: false });

  if (!newUserData) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: 'Error tidak ditemukan emailya' },
    });
    return;
  }

  res.json({
    status: 200,
    message: 'Everything is OK',
    data: { message: 'Validasi Email Berhasil!' },
  });
};

const getEmailValidation = async (req, res) => {
  try {
    const { id } = req.params;
    if (id !== req.user.id) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User Not Found!' },
      });
      return;
    }
    const result = await User.findById(id).exec();
    if (!result) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User Not Found!' },
      });
      return;
    }

    if (result.verification === true) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User is registered!' },
      });
      return;
    }

    const { email } = result;
    const token = jwt.sign({ email }, process.env.KUNCI_VALID_EMAIL,
      { expiresIn: process.env.KUNCI_VALID_EMAIL_EXP });

    const mailOptions = {
      from: '"TOEFL" <noreplyl@toefl.com>',
      to: email,
      subject: 'Verifikasi Alamat Email',
      html: `<h3>Silahkan Klik Tombol Dibawah Untuk Verifikasi Email</h3>
    <a href="${process.env.CLIENT_HOST}/auth/verify-email/${token}" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';box-sizing:border-box;border-radius:3px;color:#fff;display:inline-block;text-decoration:none;background-color:#3490dc;border-top:10px solid #3490dc;border-right:18px solid #3490dc;border-bottom:10px solid #3490dc;border-left:18px solid #3490dc" target="_blank">Verifikasi Alamat Email</a>
    `,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) throw err;
      console.log(`Email sent: ${info.response}`);
    });

    const { _id: ids, createdAt: crtd, updatedAt: uptd } = result;
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
      data: { message: 'User Not Found!' },
    });
  }
};

const postForgetPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await User.findOne({ email });
    if (!result) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User Not Found!' },
      });
      return;
    }
    const { name } = result;

    const token = jwt.sign({ email, name }, process.env.KUNCI_FORGET_PWD,
      { expiresIn: process.env.KUNCI_FORGET_PWD_EXP });

    const mailOptions = {
      from: '"TOEFL" <noreplyl@toefl.com>',
      to: email,
      subject: 'Forget Password!',
      html: `<h3>Silahkan Klik Tombol Dibawah Untuk Melakukan Reset Password</h3>
      <p>Halo ${name}, untuk melakukan reset password silahkan klik link dibawah ini!</p>
    <a href="${process.env.CLIENT_HOST}/auth/forget-password?token=${token}" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol';box-sizing:border-box;border-radius:3px;color:#fff;display:inline-block;text-decoration:none;background-color:#3490dc;border-top:10px solid #3490dc;border-right:18px solid #3490dc;border-bottom:10px solid #3490dc;border-left:18px solid #3490dc" target="_blank">Create New Password</a>
    `,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) throw err;
      console.log(`Email sent: ${info.response}`);
    });

    res.status(200).json({
      status: 200,
      message: 'Created',
      data: { message: 'Forget Password Was Sent to Email!' },
    });
  } catch (error) {
    res.status(400).json({
      status: 400,
      message: 'Bad Request',
      data: { message: error.message },
    });
  }
};

const putForgetPassword = async (req, res) => {
  try {
    const { email, token } = req.user;
    const { password } = req.body;
    if (!token || !email) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'Token Or Email Wrong!' },
      });
      return;
    }

    const result = await User.findOne({ email });
    if (!result) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: 'User Not Found!' },
      });
      return;
    }

    const { error } = validForgetPwd(req.body);
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
    // save ke db
    const updateUser = await User.findOneAndUpdate({ email }, { password: hashedPassword });
    if (!updateUser) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: error.message },
      });
      return;
    }
    const { _id: ids, createdAt: crtd, updatedAt: uptd } = updateUser;
    const dataUser = {
      _id: ids,
      createdAt: crtd,
      updateAt: uptd,
    };
    res.status(201).json({
      status: 201,
      message: 'Password Was Reset!',
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

const methodGet = (req, res) => {
  res.json('contoh get');
};

module.exports = {
  postRegister,
  postLogin,
  postRefreshToken,
  getLogout,
  putEmailVerifycation,
  getEmailValidation,
  postForgetPassword,
  putForgetPassword,
  methodGet,
};
