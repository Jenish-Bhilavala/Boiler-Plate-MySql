const db = require("../middleware/db");
const { sendOTP, generateOTP } = require("../services/email");
const logger = require("../services/logger");
const { registerValidation, loginUser } = require("../validation/userValidate");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const otp = Math.floor(100000 + Math.random() * 900000);

module.exports = {
  // Register
  registerUser: async (req, res) => {
    try {
      const { error } = registerValidation.validate(req.body);
      if (error) {
        return res.status(400).json({ message: error.details[0].message });
      }

      const { firstName, lastName, hobby, gender, email, password, phone } =
        req.body;

      db.query(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, results) => {
          if (err) {
            logger.error(`Error checking email: ${err.message}`);
            return res
              .status(500)
              .json({ message: "Database error", error: err.message });
          }

          if (results.length > 0) {
            return res.status(400).json({ message: "Email already in use" });
          }

          const image = req.file ? req.file.filename : null;
          const saltRounds = 10;
          const hashedPassword = await bcrypt.hash(password, saltRounds);

          const query = `INSERT INTO users (firstName, lastName, hobby, gender, email, password, phone, image) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

          db.query(
            query,
            [
              firstName,
              lastName,
              hobby,
              gender,
              email,
              hashedPassword,
              phone,
              image,
            ],
            (err, result) => {
              if (err) {
                logger.error(`Error inserting user: ${err.message}`);
                return res.status(500).json({
                  message: "Error registering user",
                  error: err.message,
                });
              }

              return res.status(201).json({
                message: "User registered successfully",
                userId: result.insertId,
              });
            }
          );
        }
      );
    } catch (error) {
      logger.error(`Error in registerUser: ${error.message}`);
      return res.status(500).json({
        message: "An unexpected error occurred",
        error: error.message,
      });
    }
  },
  // Get all user
  getUser: (req, res) => {
    db.query(`SELECT * FROM users`, (err, results) => {
      if (err) {
        logger.error(`Error fetching users: ${err.message}`);
        return res.status(500).json({
          message: "Error fetching users",
          error: err.message,
        });
      }
      return res.status(200).json({
        message: "Users retrieved successfully",
        data: results,
      });
    });
  },

  // Login
  loginUser: async (req, res) => {
    try {
      const { email, password } = req.body;

      const { error } = loginUser.validate(req.body);
      if (error) {
        return res.status(400).json({ message: error.details[0].message });
      }

      db.query(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, results) => {
          if (err) {
            logger.error(`Error finding user: ${err.message}`);
            return res
              .status(500)
              .json({ message: "Database error", error: err.message });
          }

          if (results.length === 0) {
            return res.status(404).json({ message: "User not found" });
          }

          const user = results[0];

          const isPasswordMatch = await bcrypt.compare(password, user.password);
          console.log(password);
          console.log(user.password);
          console.log(isPasswordMatch);

          if (isPasswordMatch) {
            const token = jwt.sign(
              { id: user.id, email: user.email },
              process.env.JWT_SECRET,
              { expiresIn: "24h" }
            );

            return res.status(200).json({
              message: "Login successful",
              token,
            });
          } else {
            logger.error(`Invalid password for user: ${email}`);
            return res
              .status(401)
              .json({ message: "Invalid email or password" });
          }
        }
      );
    } catch (error) {
      logger.error(`Error in loginUser: ${error.message}`);
      return res.status(500).json({
        message: "An unexpected error occurred",
        error: error.message,
      });
    }
  },
  // email verify
  verifyEmail: (req, res) => {
    const email = req.body.email;

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (error, result) => {
        if (error) {
          console.error("Database error:", error);
          return res.status(500).send("Server error");
        }

        if (result.length > 0) {
          const otp = generateOTP();

          sendOTP(email, otp, db);

          return res.send("OTP sent successfully.");
        } else {
          return res.send("User not found.");
        }
      }
    );
  },
};
