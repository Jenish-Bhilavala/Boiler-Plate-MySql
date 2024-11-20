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

const sendOTP = async (email, otp) => {
  const mailOptions = {
    to: email,
    subject: "OTP Verification",
    html: `
      <p>Your OTP is <strong>${otp}</strong></p>
      <p>Please do not share it with anyone.</p>
      <p>OTP will expire in 5 minutes.</p>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    throw new Error(`Failed to send OTP to ${email}: ${error.message}`);
  }
};

module.exports = { sendOTP, generateOTP };
