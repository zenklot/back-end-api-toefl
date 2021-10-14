const User = require('../models/User');

function authRole(...roles) {
  return async (req, res, next) => {
    const userData = await User.findById(req.user.id);
    if (roles.includes(userData.role)) {
      next();
      return;
    }
    res.status(401).json({
      status: 401,
      message: 'Unauthorized',
      data: {},
    });
  };
}

module.exports = {
  authRole,
};
