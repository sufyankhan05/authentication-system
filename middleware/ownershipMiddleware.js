// ONLY OWNER

const checkOwnership = (req, res, next) => {
  const requestedUserId = req.params.id; //requested url id

  const loggedInUserId = req.user._id.toString(); //at the time of jwt token created.

  if (requestedUserId !== loggedInUserId) {
    return res.status(403).json({
      success: false,
      message: "You can only access your own resource",
    });
  }

  next();
};

// OWNER OR ADMIN
const checkOwnershipOrAdmin = (req, res, next) => {
  const requestedUserId = req.params.id;

  const loggedInUserId = req.user._id.toString();

  // Admin can access anyone
  if (req.user.role === "admin") {
    return next();
  }

  // Owner can access own resource
  if (requestedUserId === loggedInUserId) {
    return next();
  }

  // Everyone else
  return res.status(403).json({
    success: false,
    message: "Access denied",
  });
};

module.exports = {
  checkOwnership,
  checkOwnershipOrAdmin,
};
