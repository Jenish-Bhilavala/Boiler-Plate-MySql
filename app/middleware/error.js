const { GeneralError, BadRequest } = require("../utils/error");
const { StatusCodes } = require("http-status-codes");
const message = require("../utils/message");
const status = require("../utils/enum");

module.exports = {
  handleErrors(err, req, res, next) {
    if (err instanceof GeneralError) {
      return res
        .status(err.statusCode !== "" ? err.statusCode : err.getCode())
        .json({
          status: status.SUCCESS,
          code: err.statusCode !== "" ? err.statusCode : err.getCode(),
          message: err.message,
          result: err.result !== "" ? err.result : undefined,
        });
    }

    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      status: status.ERROR,
      code: err.statusCode !== "" ? err.statusCode : config.HTTP_SERVER_ERROR,
      message: err.message,
    });
  },

  handleJoiErrors(err, req, res, next) {
    if (err && err.error && err.error.isJoi) {
      console.log(err.error);
      const customErrorResponse = {};
      if (err.error.details.length !== 0) {
        err.error.details.forEach((item) => {
          customErrorResponse[`${item.context.key}`] = {
            message: item.message,
            context: item.context.label,
            type: item.type,
          };
        });
      }
      next(new BadRequest(message.VALIDATION_ERROR, customErrorResponse));
    } else {
      next(err);
    }
  },
};
