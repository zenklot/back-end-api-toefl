const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  const token = req.header('auth-token');
  if (!token) {
    return res.status(401).json('tidak ada akses');
  }

  try {
    const verifikasi = jwt.verify(token, process.env.KUNCI_TOKEN);
    req.user = verifikasi;
    return next();
  } catch (error) {
    return res.status(400).send('token salah!');
  }
}

module.exports = auth;
