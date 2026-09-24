const express = require("express");

const User = require("../models/user");

const protect = require("../middleware/authMiddleware");

const authorize = require("../middleware/roleMiddleware");

const authorizePermission = require("../middleware/permissionMiddleware");
const validateObjectId = require("../utils/validateObjectId");
const {
  checkOwnership,
  checkOwnershipOrAdmin,
} = require("../middleware/ownershipMiddleware");

const AppError = require("../utils/AppError");
const asyncHandler = require("../utils/asyncHandler");
const validateString = require("../utils/validateString");
const validateEmail = require("../utils/validateEmail");
const router = express.Router();

// ==================================================
// GET ALL USERS
// ADMIN ONLY
// ==================================================

router.get(
  "/",
  protect,
  authorize("admin"),
  asyncHandler(async (req, res) => {
    const users = await User.find().select(
      "-password " + "-refreshTokenHash " + "-refreshTokenExpiresAt",
    );

    res.json({
      success: true,

      users,
    });
  }),
);

// ==================================================
// GET USER BY ID
// OWNER OR ADMIN
// ==================================================

router.get(
  "/:id",
  protect,
  (req, res, next) => {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID",
      });
    }

    next();
  },
  checkOwnershipOrAdmin,
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions,
      },
    });
  }),
);

// ==================================================
// UPDATE OWN USER
// OWNER OR ADMIN
// ==================================================

router.put(
  "/:id",
  protect,
  // ObjectId validation
  (req, res, next) => {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID",
      });
    }

    next();
  },
  checkOwnershipOrAdmin,
  asyncHandler(async (req, res, next) => {
    const { name, email } = req.body;

    //Validate name only if provided
    if (name !== undefined) {
      const nameValidation = validateString(name, "Name", 2, 50);
      if (!nameValidation.valid) {
        return res.status(400).json({
          success: false,
          message: nameValidation.message,
        });
      }
    }
    // Validate email only if provided
    if (email !== undefined) {
      const emailValidation = validateEmail(email);
      if (!emailValidation.valid) {
        return res.status(400).json({
          success: false,
          message: emailValidation.message,
        });
      }
    }
    // validateString();
    // validateEmail();
    const user = await User.findById(req.params.id);

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    if (name !== undefined) {
      user.name = name.trim();
    }

    if (email !== undefined) {
      const cleanEmail = email.trim().toLowerCase();
      const existingUser = await User.findOne({
        email: cleanEmail,
        _id: { $ne: user._id },
      });
      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: "Unable to use this email",
        });
      }
      user.pendingEmail = cleanEmail;
      user.email = cleanEmail;
    }

    await user.save();

    res.json({
      success: true,
      message: "User updated successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  }),
);

// ==================================================
// DELETE USER
// ADMIN OR OWNER ONLY
// ==================================================

router.delete(
  "/:id",
  protect,
  (req, res, next) => {
    if (!validateObjectId(req.params.id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID",
      });
    }

    next();
  },
  authorize("admin", "user"),
  asyncHandler(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    res.json({
      success: true,
      message: "User deleted successfully",
    });
  }),
);

// ==================================================
// EXAMPLE: PERMISSION PROTECTED ROUTE
// ==================================================

router.post(
  "/:id/test-permission",
  protect,
  authorizePermission("create_student"),
  async (req, res) => {
    res.json({
      success: true,

      message: "You have create_student permission",
    });
  },
);

// ==================================================
// EXAMPLE: OWNER ONLY
// ==================================================

router.get("/:id/owner-test", protect, checkOwnership, async (req, res) => {
  res.json({
    success: true,

    message: "You are the owner of this resource",
  });
});

module.exports = router;
