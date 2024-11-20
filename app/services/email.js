const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.USER_MAIL,
    pass: process.env.USER_PASS,
  },
});

const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

const sendOTP = (obj) => {
  const { email, otp } = obj;
  let mailOptions;

  if (email && otp) {
    mailOptions = {
      to: email,
      subject: "OTP Verification",
      html: `Your OTP is <strong>${otp}</strong><br>Please do not share it with anyone.<br>OTP will expire in 5 minutes.`,
    };
  }

  return transporter.sendMail(mailOptions);
};

module.exports = { sendOTP, generateOTP };
