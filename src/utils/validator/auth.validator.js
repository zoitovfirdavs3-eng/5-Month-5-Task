const Joi = require("joi");

const registerValidator = Joi.object({
    full_name: Joi.string().required().trim().messages({
        "string.base": "Full name must be a string",
        "string.empty": "Full name must not be empty",
        "any.required": "Full name is required"
    }),
    age: Joi.number().required(),
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const loginValidator = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const profileVerifiedValidator = Joi.object({
    email: Joi.string().email().required(),
    otp: Joi.string().max(6).required()
});

const resendOtpOrForgotPasswordValidator = Joi.object({
    email: Joi.string().email().required()
});

const changePasswordValidator = Joi.object({
    email: Joi.string().email().required(),
    new_password: Joi.string().required()
});

module.exports = { registerValidator, loginValidator, profileVerifiedValidator, resendOtpOrForgotPasswordValidator, changePasswordValidator }