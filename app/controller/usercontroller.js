const db = require("../middleware/db");
const logger = require("../services/logger");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sendOTP, generateOTP } = require("../services/email");
const { registerValidation, loginUser } = require("../validation/userValidate");
const { GeneralResponse } = require("../utils/response");
const { StatusCodes } = require("http-status-codes");
const { BadRequest } = require("../utils/error");
require("dotenv").config();

module.exports = {
  // Register
  registerUser: async (req, res, next) => {
    try {
      const { error } = registerValidation.validate(req.body);
      if (error) {
        return next(
          new BadRequest(
            `${error.details[0].message}`,
            { updated: false },
            StatusCodes.BAD_REQUEST
          )
        );
      }

      const { firstName, lastName, hobby, gender, email, password, phone } =
        req.body;

      db.query(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, results) => {
          if (err) {
            logger.error(`Error checking email: ${err.message}`);
            return next(
              new BadRequest(
                "Database error",
                { message: err.message },
                StatusCodes.BAD_REQUEST
              )
            );
          }

          if (results.length > 0) {
            return next(
              new BadRequest(
                "Email allredy in use.",
                { updated: false },
                StatusCodes.BAD_REQUEST
              )
            );
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
                return next(
                  new BadRequest(
                    "Error registering user",
                    { error: err.message },
                    StatusCodes.BAD_REQUEST
                  )
                );
              }

              return next(
                new GeneralResponse(
                  StatusCodes.CREATED,
                  StatusCodes.CREATED,
                  "User registerd successfully",
                  { userId: results.insertId }
                )
              );
            }
          );
        }
      );
    } catch (error) {
      logger.error(`Error in registerUser: ${error.message}`);
      return next(
        new BadRequest(
          "Internal server error",
          { error: error.message },
          StatusCodes.INTERNAL_SERVER_ERROR
        )
      );
    }
  },
  // Get all user
  getUser: (req, res, next) => {
    db.query(`SELECT * FROM users`, (err, results) => {
      if (err) {
        logger.error(`Error fetching users: ${err.message}`);
        return next(
          new BadRequest(
            "Error fatching user",
            { error: err.message },
            StatusCodes.INTERNAL_SERVER_ERROR
          )
        );
      }
      return next(
        new GeneralResponse(
          StatusCodes.OK,
          StatusCodes.OK,
          "User retrived successfully",
          results
        )
      );
    });
  },

  // Login
  loginUser: async (req, res, next) => {
    try {
      const { email, password } = req.body;

      const { error } = loginUser.validate(req.body);
      if (error) {
        return next(
          new BadRequest(
            `${error.details[0].message}`,
            { updated: false },
            StatusCodes.BAD_REQUEST
          )
        );
      }

      db.query(
        `SELECT * FROM users WHERE email = ?`,
        [email],
        async (err, results) => {
          if (err) {
            logger.error(`Error finding user: ${err.message}`);
            return next(
              new BadRequest(
                "Internal server error",
                { updated: false },
                StatusCodes.INTERNAL_SERVER_ERROR
              )
            );
          }

          if (results.length === 0) {
            return next(
              new BadRequest(
                "User not found",
                { updated: false },
                StatusCodes.NOT_FOUND
              )
            );
          }

          const user = results[0];

          const isPasswordMatch = await bcrypt.compare(password, user.password);

          if (isPasswordMatch) {
            const token = jwt.sign(
              { id: user.id, email: user.email },
              process.env.JWT_SECRET,
              { expiresIn: "24h" }
            );

            return next(
              new GeneralResponse(
                StatusCodes.OK,
                StatusCodes.OK,
                "Login successfull",
                { token }
              )
            );
          } else {
            logger.error(`Invalid password for user: ${email}`);
            return next(
              new BadRequest(
                "Invalid password",
                { updated: false },
                StatusCodes.UNAUTHORIZED
              )
            );
          }
        }
      );
    } catch (error) {
      logger.error(`Error in loginUser: ${error.message}`);
      return next(
        new BadRequest(
          `${error.message}`,
          { updated: false },
          StatusCodes.INTERNAL_SERVER_ERROR
        )
      );
    }
  },
  // Forgot Password
  verifyEmail: (req, res, next) => {
    const email = req.body.email;

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (error, result) => {
        if (error) {
          return next(
            new BadRequest(
              "Internal server error",
              { error: error.message },
              StatusCodes.INTERNAL_SERVER_ERROR
            )
          );
        }

        if (result.length > 0) {
          const otp = generateOTP();

          sendOTP(email, otp, db);

          return next(
            new GeneralResponse(
              StatusCodes.OK,
              StatusCodes.OK,
              "OTP sent successfully",
              { OTP: otp }
            )
          );
        } else {
          return next(
            new BadRequest("User not found", undefined, StatusCodes.NOT_FOUND)
          );
        }
      }
    );
  },
  // Reset Pass
  resetPassword: (req, res, next) => {
    const { email, newPassword, confirmPassword, otp } = req.body;

    db.query(
      "SELECT * FROM otp WHERE email = ? ORDER BY created_at DESC LIMIT 1",
      [email],
      (err, result) => {
        if (err) {
          console.error("Database error:", err);
          return next(
            new BadRequest(
              "Internal server error.",
              undefined,
              StatusCodes.INTERNAL_SERVER_ERROR
            )
          );
        }

        if (result.length === 0) {
          return next(
            new BadRequest("OTP not found", undefined, StatusCodes.NOT_FOUND)
          );
        }

        const storedOtp = result[0].otp;
        const expiresAt = result[0].expires_at;

        if (storedOtp !== otp) {
          return next(
            new BadRequest("Invalid OTP", undefined, StatusCodes.BAD_REQUEST)
          );
        }

        const now = new Date();

        if (now >= expiresAt) {
          return next(
            new BadRequest("OTP expired", undefined, StatusCodes.BAD_REQUEST)
          );
        }

        if (newPassword !== confirmPassword) {
          return next(
            new BadRequest(
              "Confirm password must be same.",
              { updated: false },
              StatusCodes.BAD_REQUEST
            )
          );
        }

        bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
          if (err) {
            console.error("Error hashing password:", err);
            return next(
              new BadRequest(
                "Internal server error.",
                { updated: false },
                StatusCodes.INTERNAL_SERVER_ERROR
              )
            );
          }

          db.query(
            "UPDATE users SET password = ? WHERE email = ?",
            [hashedPassword, email],
            (err, result) => {
              if (err) {
                console.error("Error updating password:", err);
                return next(
                  new BadRequest(
                    "Internal server error.",
                    undefined,
                    StatusCodes.INTERNAL_SERVER_ERROR
                  )
                );
              }

              return next(
                new GeneralResponse(
                  StatusCodes.OK,
                  StatusCodes.OK,
                  "Password updated successfully",
                  undefined
                )
              );
            }
          );
        });
      }
    );
  },
};
