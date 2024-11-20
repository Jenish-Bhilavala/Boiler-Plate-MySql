const db = require("../middleware/db");
const { sendOTP, generateOTP } = require("../services/email");
const logger = require("../services/logger");
const { registerValidation, loginUser } = require("../validation/userValidate");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const message = require("../utils/message");
const { StatusCodes } = require("http-status-codes");
const {
  BadRequest,
  GeneralError,
  NotFound,
  UnAuthorized,
} = require("../utils/error");
const { GeneralResponse } = require("../utils/response");
require("dotenv").config();
const responseStatus = require("../utils/enum");

module.exports = {
  // Register
  registerUser: async (req, res, next) => {
    try {
      const { error } = registerValidation.validate(req.body);
      if (error) {
        return next(
          new BadRequest(
            `${error.details[0].message}`,
            undefined,
            StatusCodes.BAD_REQUEST
          )
        );
      }

      const { firstName, lastName, hobby, gender, email, password, phone } =
        req.body;

      const findUser = `SELECT * FROM users WHERE email = ?`;
      db.query(findUser, [email], async (err, results) => {
        if (err) {
          logger.error(`Error checking email: ${err.message}`);
          return next(
            new BadRequest(
              message.DATABASE_ERROR,
              { message: err.message },
              StatusCodes.BAD_REQUEST
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
            logger.error(`Error inserting user: ${err.message}`);
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
      logger.error(`${message.ERROR_REGISTERING_USER}: ${error.message}`);
      return next(
        new BadRequest(
          message.INTERNAL_SERVER_ERROR,
          { error: error.message },
          StatusCodes.INTERNAL_SERVER_ERROR
        )
      );
    }
  },

  // Get all user
  getUser: (req, res, next) => {
    const displayUsers = `SELECT * FROM users`;

    db.query(displayUsers, (err, results) => {
      if (err) {
        logger.error(`${message.ERROR_FETCHING_USER}: ${err.message}`);
        return next(
          new BadRequest(
            message.ERROR_FETCHING_USER,
            { error: err.message },
            StatusCodes.INTERNAL_SERVER_ERROR
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
          new BadRequest(
            `${error.details[0].message}`,
            { updated: false },
            StatusCodes.BAD_REQUEST
          )
        );
      }

      const findUser = `SELECT * FROM users WHERE email = ?`;
      db.query(findUser, [email], async (err, results) => {
        if (err) {
          logger.error(`${message.ERROR_FINDING_USER}: ${err.message}`);
          return next(
            new BadRequest(
              message.INTERNAL_SERVER_ERROR,
              { updated: false },
              StatusCodes.INTERNAL_SERVER_ERROR
            )
          );
        }

        if (results.length === 0) {
          return next(new NotFound(message.USER_NOT_FOUND));
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
          logger.error(`${message.INVALID_CERIDIAN}: ${email}`);
          return next(new UnAuthorized(message.INVALID_CERIDIAN));
        }
      });
    } catch (error) {
      logger.error(`Error in loginUser: ${error.message}`);
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
        console.error(`${message.DATABASE_ERROR}`, error);
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
            console.error("Error inserting OTP into database: ", err);
            return next(
              new GeneralError(
                responseStatus.RESPONSE_ERROR,
                StatusCodes.INTERNAL_SERVER_ERROR,
                message.INTERNAL_SERVER_ERROR,
                undefined
              )
            );
          }
          console.log("OTP stored successfully in the database.");

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
              console.error("Error sending OTP email:", error);
              return next(new GeneralError(message.OTP_NOT_SENT, error));
            });
        });
      } else {
        return next(new NotFound(message.USER_NOT_FOUND));
      }
    });
  },
};
