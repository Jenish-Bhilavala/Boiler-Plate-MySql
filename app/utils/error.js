const { StatusCodes } = require("http-status-codes");

class GeneralError extends Error {
  constructor(status, statusCode = "", message, result = "") {
    super();
    this.status = status;
    this.statusCode = statusCode;
    this.message = message;
    this.result = result === "" ? undefined : result;
  }
  getCode() {
    if (this instanceof BadRequest) {
      return StatusCodes.BAD_REQUEST;
    } else if (this instanceof NotFound) {
      return StatusCodes.NOT_FOUND;
    } else if (this instanceof UnAuthorized) {
      return StatusCodes.UNAUTHORIZED;
    } else if (this instanceof ServiceNotAvailable) {
      return StatusCodes.SERVICE_UNAVAILABLE;
    }
    return StatusCodes.INTERNAL_SERVER_ERROR;
  }
}
class BadRequest extends GeneralError {}
class NotFound extends GeneralError {}
class UnAuthorized extends GeneralError {}
class ServiceNotAvailable extends GeneralError {}

module.exports = {
  GeneralError,
  BadRequest,
  NotFound,
  UnAuthorized,
  ServiceNotAvailable,
};
