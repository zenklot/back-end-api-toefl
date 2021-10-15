const CryptoJS = require('crypto-js');
require('dotenv').config();
const User = require('../models/User');
const { validUserUpdate } = require('../middleware/validation');

const getDetail = async (req, res) => {
  try {
    const jwtID = req.user.id;
    const userData = await User.findById(jwtID);

    if (!userData) {
      res.status(401).json({
        status: 401,
        message: 'user not found',
        data: {},
      });
      return;
    }
    // eslint-disable-next-line no-underscore-dangle
    const { password, saldo, ...dataUser } = userData._doc;
    const bytes = CryptoJS.AES.decrypt(saldo, process.env.CRYPTO_KEY);
    const decrypted = parseFloat(bytes.toString(CryptoJS.enc.Utf8));

    dataUser.saldo = decrypted;
    res.json({
      status: 200,
      message: 'Everything is OK',
      data: { dataUser },
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'There was an error on the server and the request could not be completed',
      data: { message: error.message },
    });
  }
};

const putUpdate = async (req, res) => {
  try {
    const jwtID = req.user.id;
    const { name } = req.body;
    const { error } = validUserUpdate(req.body);
    if (error) {
      res.status(400).json({
        status: 400,
        message: 'Bad Request',
        data: { message: error.details[0].message },
      });
      return;
    }
    const update = {
      name,
    };
    const userData = await User.findByIdAndUpdate(jwtID, update, { new: true });

    if (!userData) {
      res.status(401).json({
        status: 401,
        message: 'user not found',
        data: {},
      });
      return;
    }

    // eslint-disable-next-line no-underscore-dangle
    const { password, ...dataUser } = userData._doc;
    res.json({
      status: 200,
      message: 'Everything is OK',
      data: { dataUser },
    });
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: 'There was an error on the server and the request could not be completed',
      data: { message: error.message },
    });
  }
};

module.exports = {
  getDetail,
  putUpdate,
};
