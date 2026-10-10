const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    // Check Authentication
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    // Check Role
    if (!allowedRoles.includes(req.user.role)) { //allowedroles = admin , if req.user.role = admin. admin = admin so true
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }

    // Continue
    next();
  };
};

module.exports = authorize;
