const { sign, verify } = require("jsonwebtoken");

module.exports = {
    createAccessToken: (payload) => sign(payload, process.env.ACCESS_TOKEN_KEY, {expiresIn: "5m"}),
    parseAccessToken: (token) => verify(token, process.env.ACCESS_TOKEN_KEY)
}