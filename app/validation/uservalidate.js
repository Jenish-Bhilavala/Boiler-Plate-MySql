const Joi = require("joi");

const registerValidation = Joi.object({
  firstName: Joi.string().required().messages({
    "string.base": "First name must be a string.",
    "string.empty": "First name cannot be empty.",
    "any.required": "First name is a required field.",
  }),
  lastName: Joi.string().required().messages({
    "string.base": "Last name must be a string.",
    "string.empty": "Last name cannot be empty.",
    "any.required": "Last name is a required field.",
  }),
  hobby: Joi.string().required().messages({
    "string.base": "hobby must be a string.",
    "string.empty": "hobby cannot be empty.",
    "any.required": "hobby is a required field.",
  }),
  gender: Joi.string().valid("male", "female", "other").required().messages({
    "string.base": "Gender must be a string.",
    "string.empty": "Gender cannot be empty.",
    "any.required": "Gender is a required field.",
    "any.only": "Gender must be male, female, or other.",
  }),
  email: Joi.string().email().required().messages({
    "string.base": "Email must be a string.",
    "string.empty": "Email cannot be empty.",
    "any.required": "Email is a required field.",
    "string.email": "Email must be a valid email address.",
  }),
  password: Joi.string().required().messages({
    "string.base": "Password must be a string.",
    "string.empty": "Password cannot be empty.",
    "any.required": "Password is a required field.",
  }),
  phone: Joi.string().required().messages({
    "string.base": "Phone must be a string.",
    "string.empty": "Phone cannot be empty.",
    "any.required": "Phone is a required field.",
  }),
  image: Joi.string().optional(),
});

const loginUser = Joi.object({
  email: Joi.string().empty().email().required().messages({
    "string.base": "Email should be a type of 'text'.",
    "string.empty": "Email cannot be an empty field.",
    "string.email": "Email format is not valid.",
    "any.required": "Email is a required field.",
  }),
  password: Joi.string().empty().min(6).max(16).required().messages({
    "string.base": "Password should be a type of text.",
    "string.empty": "Password cannot be an empty field.",
    "string.min": "Password should be of minimum 6 characters.",
    "string.max": "Password can be of maximum 16 characters.",
    "any.required": "Password is a required field.",
  }),
});

module.exports = { registerValidation, loginUser };
