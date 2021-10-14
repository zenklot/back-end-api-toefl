const User = require('../models/User');

function authRole(...roles) {
  return async (req, res, next) => {
    try {
      const userData = await User.findById(req.user.id);
      if (!userData) {
        res.status(401).json({
          status: 401,
          message: 'user not found',
          data: {},
        });
        return;
      }
      if (roles.includes(userData.role)) {
        next();
        return;
      }
      res.status(401).json({
        status: 401,
        message: 'Unauthorized',
        data: {},
      });
    } catch (error) {
      res.status(401).json({
        status: 401,
        message: 'Unauthorized',
        data: { error: error.message },
      });
    }
  };
}

module.exports = {
  authRole,
};
