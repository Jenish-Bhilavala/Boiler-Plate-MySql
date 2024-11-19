const nodemailer = require("nodemailer");
const crypto = require("crypto");

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "jenishbhilavala@gmail.com",
    pass: "uqis ecsx wkdq yvzs",
  },
});

const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

const sendOTP = (email, otp, db) => {
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  db.query(
    `INSERT INTO otp (email, otp, expires_at) VALUES (?, ?, ?)`,
    [email, otp, expiresAt],
    (err, result) => {
      if (err) {
        console.error("Error inserting OTP into database: ", err);
        return;
      }
      console.log("OTP stored successfully in the database.");
    }
  );

  const mailOptions = {
    to: email,
    subject: "OTP Verification",
    html: `Your OTP is <strong>${otp}</strong><br>Please do not share it with anyone.<br>OTP will expire in 5 minutes.`,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Error sending OTP email:", error);
    } else {
      console.log("OTP sent.");
    }
  });
};

module.exports = { sendOTP, generateOTP };
