const { Router } = require("express");
const authController = require("../controller/auth.controller");

const authRouter = Router();

authRouter.post("/register", authController.REGISTER);
authRouter.post("/verify", authController.VERIFY);
authRouter.post("/resend/otp", authController.RESEND_OTP);

module.exports = authRouter;