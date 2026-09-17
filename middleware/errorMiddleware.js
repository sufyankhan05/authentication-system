const logger = require("../utils/logger");

const errorMiddleware = (err, req, res, next) => {

  logger.error(
    "Unhandled application error",
    {
      name: err.name,
      message: err.message,
      stack: err.stack,
    },
  );

  const statusCode = err.statusCode || 500;

  res.status(statusCode).json({
    success: false,
    message: err.isOperational
      ? err.message
      : "Internal server error",
  });
};

module.exports = errorMiddleware;