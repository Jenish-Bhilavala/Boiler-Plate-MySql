const { StatusCodes } = require("http-status-codes");

class GeneralResponse {
  constructor(status = StatusCodes.OK, statusCode = "", message, result) {
    this.status = status;
    this.statusCode = statusCode || StatusCodes.OK;
    this.message = message;
    this.result = result;
  }
}

module.exports = {
  GeneralResponse,
};
