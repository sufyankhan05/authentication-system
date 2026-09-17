const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
      select: false,
    },

    role: {
      type: String,
      enum: ["user", "teacher", "admin"],
      default: "user",
    },

    permissions: {
      type: [String],
      default: [],
    },

    // ==================================================
    // EMAIL VERIFICATION
    // ==================================================

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    emailVerificationOtpHash: {
      type: String,
      default: null,
      select: false,
    },

    emailVerificationOtpExpiresAt: {
      type: Date,
      default: null,
      select: false,
    },

    emailVerificationOtpLastSentAt: {
      type: Date,
      default: null,
      select: false,
    },

    // ==================================================
    // PASSWORD RESET OTP
    // ==================================================

    passwordResetOtpHash: {
      type: String,
      default: null,
      select: false,
    },

    passwordResetOtpExpiresAt: {
      type: Date,
      default: null,
      select: false,
    },

    passwordResetOtpLastSentAt: {
      type: Date,
      default: null,
      select: false,
    },

    // ==================================================
    // PASSWORD RESET ONE-TIME TOKEN
    // ==================================================

    passwordResetTokenHash: {
      type: String,
      default: null,
      select: false,
    },

    passwordResetTokenExpiresAt: {
      type: Date,
      default: null,
      select: false,
    },

    // ==================================================
    // REFRESH TOKEN
    // ==================================================

    // refreshTokenHash: {
    //   type: String,
    //   default: null,
    //   select: false,
    // },

    // refreshTokenExpiresAt: {
    //   type: Date,
    //   default: null,
    //   select: false,
    // },

    // ==================================================
    // TOKEN VERSION
    // ==================================================

    tokenVersion: {
      type: Number,
      default: 0,
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },

    loginLockUntil: {
      type: Date,
      default: null,
    },

    emailVerificationOtpAttempts: {
      type: Number,
      default: 0,
    },

    emailVerificationOtpLockUntil: {
      type: Date,
      default: null,
    },

    passwordResetOtpAttempts: {
      type: Number,
      default: 0,
    },

    passwordResetOtpLockUntil: {
      type: Date,
      default: null,
    },
  },

  {
    timestamps: true,
  },
);

module.exports = mongoose.model("User", userSchema);
