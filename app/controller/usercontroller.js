const db = require("../middleware/db");
const logger = require("../services/logger");
const { registerValidation } = require("../validation/userValidate");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = {
  // Register
  registerUser: async (req, res) => {
    try {
      const { error } = registerValidation.validate(req.body);
      if (error) {
        return res.status(400).json({ message: error.details[0].message });
      }

      console.log("File Upload Result:", req.file);

      const { firstName, lastName, hobby, gender, email, password, phone } =
        req.body;

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
            return res
              .status(500)
              .json({ message: "Error registering user", error: err.message });
          }

          return res.status(201).json({
            message: "User registered successfully",
            userId: result.insertId,
          });
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
    const query = "SELECT * FROM users";

    db.query(query, (err, results) => {
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
  userLogin: async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ message: "Email and password are required" });
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

          const user = results[0];

          const isPasswordMatch = await bcrypt.compare(password, user.password);

          if (!isPasswordMatch) {
            const token = jwt.sign(
              { id: user.id, email: user.email },
              process.env.JWT_SECRET,
              { expiresIn: "1h" }
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
      logger.error(`Error in userLogin: ${error.message}`);
      return res.status(500).json({
        message: "An unexpected error occurred",
        error: error.message,
      });
    }
  },
};
