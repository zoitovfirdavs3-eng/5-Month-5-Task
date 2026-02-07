const { Schema, model } = require("mongoose");

const userSchema = new Schema({
    full_name: {
        type: String,
        required: true
    },
    age: {
        type: Number,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    otp: {
        type: String
    },
    otpTime: {
        type: Date
    },
    is_verified: {
        type: Boolean,
        default: false
    }
}, {
    versionKey: false,
    timestamps: true
});

module.exports = model('users', userSchema)