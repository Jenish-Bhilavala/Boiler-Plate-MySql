const { StatusCodes } = require("http-status-codes");

class GeneralResponse {
  constructor(message, result, statusCode = "") {
    this.message = message;
    this.statusCode = statusCode == "" ? StatusCodes.OK : statusCode;
    this.result = result;
  }
}

module.exports = {
  GeneralResponse,
};
