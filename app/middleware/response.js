const { GeneralResponse } = require("../utils/response");
const { StatusCodes } = require("http-status-codes");

const handleResponse = (response, req, res, next) => {
  if (response instanceof GeneralResponse) {
    return res.status(StatusCodes.OK).json({
      status: "success" || StatusCodes.OK,
      statusCode: StatusCodes.OK,
      message: response.message,
      result: response.result,
    });
  }
  next(response);
};

module.exports = handleResponse;
