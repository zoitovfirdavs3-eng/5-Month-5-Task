const { Router } = require("express");
const authController = require("../controller/auth.controller");

const authRouter = Router();

authRouter.post("/register", authController.REGISTER);
authRouter.post("/verify", authController.VERIFY);
authRouter.post("/resend/otp", authController.RESEND_OTP);
authRouter.post("/forgot/password", authController.FORGOT_PASSWORD);
authRouter.post("/change/password", authController.CHANGE_PASSWORD)
authRouter.post("/login", authController.LOGIN)

module.exports = authRouter;