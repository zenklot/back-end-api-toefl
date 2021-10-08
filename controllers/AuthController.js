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
      res.status(400).json(error);
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
    res.status(400).json('Error!');
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const data = await User.findOne({
      where: { email },
    });

    if (!data) {
      res.status(400).json('Username Tidak Terdaftar');
      return;
    }

    // deskrip
    const resultLogin = bcrypt.compareSync(password, data.password);

    if (!resultLogin) {
      res.status(400).send('Username atau Password Salah !');
      return;
    }

    // eslint-disable-next-line no-underscore-dangle
    const token = jwt.sign({ id: data._id }, process.env.KUNCI_TOKEN, { expiresIn: '1h' });

    res.header('auth-token', token).json('berhasil Login');
  } catch (error) {
    res.status(500).json('error');
  }
};

const methodGet = (req, res) => {
  res.send('contoh get');
};

module.exports = {
  register, login, methodGet,
};
