const Joi = require('@hapi/joi');

const validUserReg = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(4).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
  });
  return schema.validate(data);
};

const validForgetPwd = (data) => {
  const schema = Joi.object({
    password: Joi.string().min(6).required(),
  });
  return schema.validate(data);
};

const validUserUpdate = (data) => {
  const schema = Joi.object({
    name: Joi.string().min(4).required(),
  });
  return schema.validate(data);
};

module.exports = {
  validUserReg,
  validForgetPwd,
  validUserUpdate,
};
