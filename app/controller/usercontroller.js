const db = require("../middleware/db");
const { sendOTP, generateOTP } = require("../services/email");
const logger = require("../services/logger");
const { registerValidation, loginUser } = require("../validation/userValidate");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { StatusCodes } = require("http-status-codes");
const { BadRequest } = require("../utils/error");
const { GeneralResponse } = require("../utils/response");
require("dotenv").config();

const otp = Math.floor(100000 + Math.random() * 900000);

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
  // email verify
  verifyEmail: (req, res, next) => {
    const email = req.body.email;

    db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (error, result) => {
        if (error) {
          console.error("Database error:", error);
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
};
