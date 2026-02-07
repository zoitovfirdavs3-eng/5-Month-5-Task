const { Router } = require("express");
const authRouter = require("./auth.routes");

const mainRouter = Router();

mainRouter.use("/auth", authRouter);

module.exports = mainRouter;