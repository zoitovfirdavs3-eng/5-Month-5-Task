module.exports = () => {
    let randomNumbers = Array.from({length: 6}, () => Math.floor(Math.random() * 9)).join("");
    let otpTime = Date.now() + 120000
    return {otp: Number(randomNumbers), otpTime};
};