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

      const findUser = `SELECT * FROM users WHERE email = ?`;
      db.query(findUser, [email], async (err, results) => {
        if (err) {
          return next(
            new GeneralError(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.BAD_REQUEST,
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
      });

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

  // Get all user
  getUser: (req, res, next) => {
    const displayUsers = `SELECT * FROM users`;

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

      const findUser = `SELECT * FROM users WHERE email = ?`;
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
          return next(
            new NotFound(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.NOT_FOUND,
              `User ${message.NOT_FOUND}`,
              undefined
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
              responseStatus.RESPONSE_SUCCESS,
              StatusCodes.OK,
              message.LOGIN_SUCCESS,
              { token }
            )
          );
        } else {
          return next(
            new UnAuthorized(
              responseStatus.RESPONSE_ERROR,
              StatusCodes.UNAUTHORIZED,
              message.INVALID_CREDENTIAL,
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
          undefined
        )
      );
    }
  },
  // email verify
  verifyEmail: (req, res, next) => {
    const email = req.body.email;
    const findUser = `SELECT * FROM users WHERE email = ?`;

    db.query(findUser, [email], async (error, result) => {
      if (error) {
        next(
          new GeneralError(
            responseStatus.RESPONSE_ERROR,
            StatusCodes.INTERNAL_SERVER_ERROR,
            message.INTERNAL_SERVER_ERROR,
            undefined
          )
        );
      }

      if (result.length > 0) {
        const otp = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        const insertOtpQuery = `INSERT INTO otp (email, otp, expires_at) VALUES (?, ?, ?)`;
        db.query(insertOtpQuery, [email, otp, expiresAt], (err, result) => {
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

          sendOTP(email, otp)
            .then(() => {
              console.log(message.OTP_SENT);
              return next(
                new GeneralResponse(
                  responseStatus.RESPONSE_SUCCESS,
                  StatusCodes.OK,
                  message.OTP_SENT,
                  { OTP: otp }
                )
              );
            })
            .catch((error) => {
              return next(
                new GeneralError(
                  responseStatus.RESPONSE_ERROR,
                  StatusCodes.INTERNAL_SERVER_ERROR,
                  message.OTP_NOT_SENT,
                  undefined
                )
              );
            });
        });
      } else {
        return next(
          new NotFound(
            responseStatus.RESPONSE_ERROR,
            StatusCodes.NOT_FOUND,
            `User ${message.NOT_FOUND}`,
            undefined
          )
        );
      }
    });
  },
};
