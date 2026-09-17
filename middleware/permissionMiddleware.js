const authorizePermission = (...requiredPermissions) => {
  return (req, res, next) => {
    // Authentication Check
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required",
      });
    }

    // Check Permissions
    const hasPermission = requiredPermissions.every((permission) =>
      req.user.permissions.includes(permission),
    );

    if (!hasPermission) {
      return res.status(403).json({
        success: false,
        message: "Permission denied",
      });
    }

    next();
  };
};

module.exports = authorizePermission;
