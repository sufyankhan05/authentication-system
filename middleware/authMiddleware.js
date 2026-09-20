const jwt = require("jsonwebtoken");
const User = require("../models/user");
const env = require("../config/env");
const logger = require("../utils/logger");
const protect = async (req, res, next) => {
  try {
    // ==================================================
    // GET AUTHORIZATION HEADER
    // ==================================================

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    // ==================================================
    // CHECK BEARER FORMAT
    // ==================================================

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Invalid authorization format",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Access token missing",
      });
    }

    // ==================================================
    // VERIFY JWT
    // ==================================================

    const decoded = jwt.verify(token, env.JWT_SECRET, {
      algorithms: ["HS256"],
    });

    // ==================================================
    // FIND USER
    // ==================================================

    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User no longer exists",
      });
    }

    // ==================================================
    // CHECK TOKEN VERSION
    // ==================================================

    if (
      decoded.tokenVersion === undefined ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    // ==================================================
    // ATTACH USER
    // ==================================================

    req.user = user;

    next();
  } catch (error) {
    logger.error("Authentication Error", {
      name: error.name,
      message: error.message,
    });

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        message: "Access token expired",
      });
    }

    return res.status(401).json({
      success: false,
      message: "Invalid access token",
    });
  }
};

module.exports = protect;
