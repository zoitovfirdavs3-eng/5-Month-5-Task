const { globalError, ClientError } = require("shokhijakhon-error-handler");
const {
  registerValidator,
  profileVerifiedValidator,
  resendOtpOrForgotPasswordValidator,
  changePasswordValidator,
  loginValidator,
} = require("../utils/validator/auth.validator");
const UserModel = require("../models/User.model");
const { hash, compare } = require("bcrypt");
const otpGenerator = require("../utils/generators/otp.generator");
const emailService = require("../lib/mail.service");
const jwtService = require("../lib/jwt.service");

module.exports = {
  async REGISTER(req, res) {
    try {
      let newUser = req.body;
      await registerValidator.validateAsync(newUser);
      let findUser = await UserModel.findOne({ email: newUser.email });
      if (findUser) throw new ClientError("User already exists !");
      newUser.password = await hash(newUser.password, 10);
      let { otp, otpTime } = otpGenerator();
      await emailService(newUser.email, otp);
      await UserModel.create({
        ...newUser,
        otp,
        otpTime,
      });
      return res
        .status(201)
        .json({ message: "User successfully registered !", status: 201 });
    } catch (err) {
      return globalError(err, res);
    }
  },
  async VERIFY(req, res) {
    try {
      let profileData = req.body;
      await profileVerifiedValidator.validateAsync(profileData);

      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser) throw new ClientError("User not found !", 404);

      let currentDate = Date.now();
      if (currentDate > findUser.otpTime)
        throw new ClientError("OTP expired !", 400);

      if (profileData.otp != findUser.otp)
        throw new ClientError("OTP invalid !", 400);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { is_verified: true },
      );

      return res.json({
        message: "Profile successfullt verified",
        status: 200,
      });
    } catch (err) {
      return globalError(err, res);
    }
  },
  async RESEND_OTP(req, res) {
    try {
      let profileData = req.body;
      await resendOtpOrForgotPasswordValidator.validateAsync(profileData);
      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser || findUser.is_verified)
        throw new ClientError("User not found or user already activated", 404);
      let { otp, otpTime } = otpGenerator();
      await emailService(profileData.email, otp);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { otp, otpTime },
      );
      return res.json({ message: "OTP successfully resended" });
    } catch (err) {
      return globalError(err, res);
    }
  },
  async FORGOT_PASSWORD(req, res) {
    try {
      let profileData = req.body;
      await resendOtpOrForgotPasswordValidator.validateAsync(profileData);
      let findUser = await UserModel.findOne({ email: profileData.email });
      if (!findUser || findUser.is_verified)
        throw new ClientError("User not found or user already activated", 404);
      let { otp, otpTime } = otpGenerator();
      await emailService(profileData.email, otp);
      await UserModel.findOneAndUpdate(
        { email: profileData.email },
        { otp, otpTime },
      );
      return res.json({ message: "OTP successfully resended" });
    } catch (err) {
      return globalError(err, res);
    }
  },
  async CHANGE_PASSWORD(req, res) {
    let profileData = req.body;
    await changePasswordValidator.validateAsync(profileData);
    let findUser = await UserModel.findOne({ email: profileData.email });
    if (!findUser || findUser.is_verified)
      throw new ClientError("User not found or user already activated", 404);
    let hash_password = await hash(profileData.new_password, 10);
    await UserModel.findOneAndUpdate(
      { email: profileData.email },
      { password: hash_password },
    );
    return res.json({ message: "Password successfullt changed", status: 200 });
  },
  async LOGIN(req, res) {
    try {
      let data = req.body;
      await loginValidator.validateAsync(data);
      let findUser = await UserModel.findOne({ email: data.email });
      if (!findUser || !findUser.is_verified)
        throw new ClientError("User not found or user already activated", 404);
      let checkPassword = await compare(data.password, findUser.password);
      if (!checkPassword)
        throw new ClientError("Password or email invalid", 400);
      let accessToken = jwtService.createAccessToken({ sub: findUser.id });
      return res.json({
        message: "User successfully logged in",
        status: 200,
        accessToken,
      });
    } catch (err) {
      return globalError(err, res);
    }
  },
};
