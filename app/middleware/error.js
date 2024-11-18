const { BadRequest, GeneralError } = require("../utils/error");
const { StatusCodes } = require("http-status-codes");

const handleErrors = (err, req, res, next) => {
  if (err instanceof GeneralError) {
    return res.status(err.statusCode || err.getCode()).json({
      status: false,
      code: err.statusCode || err.getCode(),
      message: err.message,
      result: err.result || undefined,
    });
  }

  return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
    status: false,
    code: StatusCodes.INTERNAL_SERVER_ERROR,
    message: err.message,
  });
};

const handleJoiErrors = (err, req, res, next) => {
  if (err && err.error && err.error.isJoi) {
    const customErrorResponse = {};
    if (err.error.details.length > 0) {
      err.error.details.forEach((item) => {
        customErrorResponse[`${item.context.key}`] = {
          message: item.message,
          context: item.context.label,
          type: item.type,
        };
      });
    }
    next(new BadRequest("Validation Error", customErrorResponse));
  } else {
    next(err);
  }
};

module.exports = { handleErrors, handleJoiErrors };
