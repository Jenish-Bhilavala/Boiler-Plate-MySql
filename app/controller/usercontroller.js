const db = require("../middleware/db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const message = require("../utils/message");
const responseStatus = require("../utils/enum");
const { registerValidation, loginUser } = require("../validation/userValidate");
const { sendOTP, generateOTP } = require("../services/email");
const { StatusCodes } = require("http-status-codes");
const { GeneralError, NotFound, UnAuthorized } = require("../utils/error");
const { GeneralResponse } = require("../utils/response");
require("dotenv").config();

module.exports = {
  // Register
  registerUser: async (req, res, next) => {
    try {
      const { error } = registerValidation.validate(req.body);
      if (error) {
        return next(
          new GeneralError(
            responseStatus.RESPONSE_ERROR,
            StatusCodes.BAD_REQUEST,
            `${error.details[0].message}`,
            undefined
          )
        );
      }

      const { firstName, lastName, hobby, gender, email, password, phone } =
        req.body;

      const findUser = "SELECT * FROM users WHERE email = ?";
      db.query(findUser, [email], async (err, results) => {
        if (err) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.INTERNAL_SERVER_ERROR,
              message.DATABASE_ERROR,
              err.message
            )
          );
        }

        if (results.length > 0) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.INTERNAL_SERVER_ERROR,
              message.INTERNAL_SERVER_ERROR,
              undefined
            )
          );
        }

        const image = req.file ? req.file.filename : null;
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const createUser = `INSERT INTO users (firstName, lastName, hobby, gender, email, password, phone, image) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

        db.query(
          createUser,
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
              return next(
                new GeneralError(
                  responseStatus.RESPONSE_ERROR,
                  StatusCodes.INTERNAL_SERVER_ERROR,
                  message.ERROR_REGISTERING_USER,
                  undefined
                )
              );
            }

            return next(
              new GeneralResponse(
                responseStatus.RESPONSE_SUCCESS,
                StatusCodes.CREATED,
                message.REGISTERING_USER,
                { userId: result.insertId }
              )
            );
          }
        );
      });
    } catch (error) {
      return next(
        new GeneralError(
          responseStatus.RESPONSE_ERROR,
          StatusCodes.INTERNAL_SERVER_ERROR,
          message.INTERNAL_SERVER_ERROR,
          error.message
        )
      );
    }
  },

  // Get all users
  getUser: (req, res, next) => {
    const displayUsers = "SELECT * FROM users";

    db.query(displayUsers, (err, results) => {
      if (err) {
        return next(
          new GeneralError(
            responseStatus.RESPONSE_ERROR,
            StatusCodes.INTERNAL_SERVER_ERROR,
            message.ERROR_FETCHING_USER,
            err.message
          )
        );
      }
      return next(
        new GeneralResponse(
          responseStatus.RESPONSE_SUCCESS,
          StatusCodes.OK,
          message.RETRIEVED_USER,
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
          new GeneralError(
            responseStatus.RESPONSE_ERROR,
            StatusCodes.BAD_REQUEST,
            `${error.details[0].message}`,
            undefined
          )
        );
      }

      const findUser = "SELECT * FROM users WHERE email = ?";
      db.query(findUser, [email], async (err, results) => {
        if (err) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.INTERNAL_SERVER_ERROR,
              message.INTERNAL_SERVER_ERROR,
              undefined
            )
          );
        }

        if (results.length === 0) {
          return res.status(404).json({ message: "User not found" });
        }

        const user = results[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);

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
          return res.status(401).json({ message: "Invalid email or password" });
        }
      });
    } catch (error) {
      return next(
        new GeneralError(
          responseStatus.RESPONSE_ERROR,
          StatusCodes.INTERNAL_SERVER_ERROR,
          message.INTERNAL_SERVER_ERROR,
          error.message
        )
      );
    }
  },

  // Email verification
  verifyEmail: async (req, res, next) => {
    const email = req.body.email;

    try {
      const findUserQuery = "SELECT * FROM users WHERE email = ?";
      db.query(findUserQuery, [email], async (error, result) => {
        if (error) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.INTERNAL_SERVER_ERROR,
              message.DATABASE_ERROR,
              error.message
            )
          );
        }

        if (result.length > 0) {
          // User found, generate OTP
          const otp = generateOTP();
          const expiresAt = new Date();

          expiresAt.setMinutes(expiresAt.getMinutes() + 5);

          const insertOtpQuery =
            "INSERT INTO otp (email, otp, expires_at) VALUES (?, ?, ?)";
          db.query(
            insertOtpQuery,
            [email, otp, expiresAt],
            async (insertError, insertResult) => {
              if (insertError) {
                return next(
                  new GeneralError(
                    responseStatus.RESPONSE_ERROR,
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    message.DATABASE_ERROR,
                    insertError.message
                  )
                );
              }

              try {
                await sendOTP(email, otp);
                return res.status(200).send("OTP sent successfully.");
              } catch (sendError) {
                return next(
                  new GeneralError(
                    responseStatus.RESPONSE_ERROR,
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    message.FAILED_SENDING_OTP,
                    sendError.message
                  )
                );
              }
            }
          );
        } else {
          return next(
            NotFound(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.NOT_FOUND,
              `User ${message.NOT_FOUND}`,
              undefined
            )
          );
        }
      });
    } catch (error) {
      return next(
        new GeneralError(
          responseStatus.RESPONSE_ERROR,
          StatusCodes.INTERNAL_SERVER_ERROR,
          message.INTERNAL_SERVER_ERROR,
          error.message
        )
      );
    }
  },

  // Reset Password
  resetPassword: (req, res, next) => {
    const { email, newPassword, confirmPassword, otp } = req.body;

    db.query(
      "SELECT * FROM otp WHERE email = ? ORDER BY created_at DESC LIMIT 1",
      [email],
      (err, result) => {
        if (err) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.INTERNAL_SERVER_ERROR,
              message.INTERNAL_SERVER_ERROR,
              err.message
            )
          );
        }

        if (result.length === 0) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.NOT_FOUND,
              message.INVALID_OTP,
              undefined
            )
          );
        }

        const storedOtp = result[0].otp;
        const expiresAt = result[0].expires_at;

        if (storedOtp !== otp) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.BAD_REQUEST,
              message.INVALID_OTP,
              undefined
            )
          );
        }

        const now = new Date();
        if (now >= expiresAt) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.BAD_REQUEST,
              message.OTP_EXPIRED,
              undefined
            )
          );
        }

        if (newPassword !== confirmPassword) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.BAD_REQUEST,
              message.CONFIRM_PASSWORD_ERROR,
              undefined
            )
          );
        }

        bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
          if (err) {
            return next(
              new GeneralError(
                responseStatus.RESPONSE_ERROR,
                StatusCodes.INTERNAL_SERVER_ERROR,
                message.INTERNAL_SERVER_ERROR,
                err.message
              )
            );
          }

          db.query(
            "UPDATE users SET password = ? WHERE email = ?",
            [hashedPassword, email],
            (err, result) => {
              if (err) {
                return next(
                  new GeneralError(
                    responseStatus.RESPONSE_ERROR,
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    message.UPDATE_PASSWORD_ERROR,
                    err.message
                  )
                );
              }

              return next(
                new GeneralResponse(
                  responseStatus.RESPONSE_SUCCESS,
                  StatusCodes.OK,
                  message.UPDATE_PASSWORD,
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
