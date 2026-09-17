const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const User = require("../models/user");
const Session = require("../models/session");
const env = require("../config/env");
const logger = require("../utils/logger");
const authMiddleware = require("../middleware/authMiddleware");

const sendEmail = require("../utils/sendEmail");
const validatePassword = require("../utils/validatePassword");
const validateEmail = require("../utils/validateEmail");
const validateString = require("../utils/validateString");
const validateObjectId = require("../utils/validateObjectId");
const asyncHandler = require("../utils/asyncHandler");
const router = express.Router();

// ============================================================
// CONSTANTS
// ============================================================

const OTP_EXPIRES_MINUTES = 10;

const OTP_RESEND_COOLDOWN_SECONDS = 60;

const RESET_TOKEN_EXPIRES_MINUTES = 10;

// Login brute-force protection
const MAX_LOGIN_ATTEMPTS = 5;

const LOGIN_LOCK_TIME = 15 * 60 * 1000;

// OTP brute-force protection
const MAX_OTP_ATTEMPTS = 5;

const OTP_LOCK_TIME = 15 * 60 * 1000;

// ============================================================
// RATE LIMITERS
// ============================================================

// Protect login endpoint by IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  max: 10,

  message: {
    success: false,
    message: "Too many login attempts. Please try again later.",
  },
});

// Protect OTP endpoints by IP
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  max: 5,

  message: {
    success: false,
    message: "Too many OTP requests. Please try again later.",
  },
});

// ============================================================
// HELPER FUNCTIONS
// ============================================================

// SHA-256 hash
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

// Generate 6-digit OTP
const generateOtp = () => {
  return crypto.randomInt(100000, 1000000).toString();
};

// Generate access token
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user._id.toString(),
      role: user.role,
      tokenVersion: user.tokenVersion,
    },

    env.JWT_SECRET,

    {
      expiresIn: env.ACCESS_TOKEN_EXPIRES,
      algorithm: "HS256",
    },
  );
};

// Generate refresh token
const generateRefreshToken = (user, sessionId) => {
  return jwt.sign(
    {
      userId: user._id.toString(),
      sessionId: sessionId,
      tokenVersion: user.tokenVersion,
    },

    env.REFRESH_TOKEN_SECRET,

    {
      expiresIn: env.REFRESH_TOKEN_EXPIRES,
      algorithm: "HS256",
    },
  );
};

// ============================================================
// REGISTER
// POST /api/auth/register
// ============================================================

router.post(
  "/register",
  asyncHandler(async (req, res, next) => {
    const { name, email, password } = req.body;

    // ------------------------------------------------------
    // NAME VALIDATION
    // ------------------------------------------------------

    const nameValidation = validateString(name, "Name", 2, 50);

    if (!nameValidation.valid) {
      return res.status(400).json({
        success: false,
        message: nameValidation.message,
      });
    }

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // ------------------------------------------------------
    // PASSWORD VALIDATION
    // ------------------------------------------------------

    const passwordValidation = validatePassword(password);

    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // ------------------------------------------------------
    // CLEAN INPUT
    // ------------------------------------------------------

    const cleanName = name.trim();

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // CHECK EXISTING USER
    // ------------------------------------------------------

    const existingUser = await User.findOne({
      email: cleanEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Email already registered",
      });
    }

    // ------------------------------------------------------
    // HASH PASSWORD
    // ------------------------------------------------------

    const hashedPassword = await bcrypt.hash(password, 12);

    // ------------------------------------------------------
    // GENERATE EMAIL OTP
    // ------------------------------------------------------

    const otp = generateOtp();

    const otpHash = hashToken(otp);

    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000);

    // ------------------------------------------------------
    // CREATE USER
    // ------------------------------------------------------

    const user = await User.create({
      name: cleanName,

      email: cleanEmail,

      password: hashedPassword,

      // Never trust role from req.body
      role: "user",

      isEmailVerified: false,

      emailVerificationOtpHash: otpHash,

      emailVerificationOtpExpiresAt: otpExpiresAt,

      emailVerificationOtpLastSentAt: new Date(),

      emailVerificationOtpAttempts: 0,

      emailVerificationOtpLockUntil: null,

      failedLoginAttempts: 0,

      loginLockUntil: null,

      tokenVersion: 0,
    });

    // ------------------------------------------------------
    // SEND VERIFICATION EMAIL
    // ------------------------------------------------------

    await sendEmail({
      to: cleanEmail,

      subject: "Verify your email",

      html: `
        <h2>Email Verification</h2>

        <p>Hello ${cleanName},</p>

        <p>Your verification OTP is:</p>

        <h1>${otp}</h1>

        <p>
          This OTP will expire in
          ${OTP_EXPIRES_MINUTES} minutes.
        </p>
      `,
    });

    return res.status(201).json({
      success: true,

      message: "Registration successful. Please verify your email.",
    });
  }),
);

// ============================================================
// VERIFY EMAIL
// POST /api/auth/verify-email
// ============================================================

router.post(
  "/verify-email",
  otpLimiter,
  asyncHandler(async (req, res, next) => {
    const { email, otp } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // ------------------------------------------------------
    // OTP VALIDATION
    // ------------------------------------------------------

    if (!otp || typeof otp !== "string") {
      return res.status(400).json({
        success: false,
        message: "OTP is required",
      });
    }

    // OTP should be exactly 6 digits
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "OTP must be a 6-digit number",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select("+emailVerificationOtpHash " + "+emailVerificationOtpExpiresAt");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // ALREADY VERIFIED
    // ------------------------------------------------------

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    // ------------------------------------------------------
    // CHECK OTP LOCK
    // ------------------------------------------------------

    if (
      user.emailVerificationOtpLockUntil &&
      user.emailVerificationOtpLockUntil > new Date()
    ) {
      return res.status(429).json({
        success: false,
        message: "Too many incorrect OTP attempts. Please try again later.",
      });
    }

    // ------------------------------------------------------
    // RESET EXPIRED LOCK
    // ------------------------------------------------------

    if (
      user.emailVerificationOtpLockUntil &&
      user.emailVerificationOtpLockUntil <= new Date()
    ) {
      user.emailVerificationOtpAttempts = 0;

      user.emailVerificationOtpLockUntil = null;

      await user.save();
    }

    // ------------------------------------------------------
    // CHECK OTP EXPIRY
    // ------------------------------------------------------

    if (
      !user.emailVerificationOtpExpiresAt ||
      user.emailVerificationOtpExpiresAt < new Date()
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // HASH INCOMING OTP
    // ------------------------------------------------------

    const incomingOtpHash = hashToken(otp);

    // ------------------------------------------------------
    // WRONG OTP
    // ------------------------------------------------------

    if (incomingOtpHash !== user.emailVerificationOtpHash) {
      user.emailVerificationOtpAttempts += 1;

      if (user.emailVerificationOtpAttempts >= MAX_OTP_ATTEMPTS) {
        user.emailVerificationOtpLockUntil = new Date(
          Date.now() + OTP_LOCK_TIME,
        );
      }

      await user.save();

      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // CORRECT OTP
    // ------------------------------------------------------

    user.isEmailVerified = true;

    user.emailVerificationOtpHash = null;

    user.emailVerificationOtpExpiresAt = null;

    user.emailVerificationOtpLastSentAt = null;

    user.emailVerificationOtpAttempts = 0;

    user.emailVerificationOtpLockUntil = null;

    await user.save();

    return res.status(200).json({
      success: true,

      message: "Email verified successfully",
    });
  }),
);

// ============================================================
// RESEND EMAIL VERIFICATION OTP
// POST /api/auth/resend-verification-otp
// ============================================================

router.post(
  "/resend-verification-otp",
  otpLimiter,
  asyncHandler(async (req, res, next) => {
    const { email } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select(
      "+emailVerificationOtpHash " +
        "+emailVerificationOtpExpiresAt " +
        "+emailVerificationOtpLastSentAt",
    );

    if (!user) {
      return res.status(200).json({
        success: true,
        message: "If an account exists, a verification OTP has been sent.",
      });
    }

    // ------------------------------------------------------
    // ALREADY VERIFIED
    // ------------------------------------------------------

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: "Email is already verified",
      });
    }

    // ------------------------------------------------------
    // 60-SECOND COOLDOWN
    // ------------------------------------------------------

    if (user.emailVerificationOtpLastSentAt) {
      const secondsSinceLastSent =
        (Date.now() - user.emailVerificationOtpLastSentAt.getTime()) / 1000;

      if (secondsSinceLastSent < OTP_RESEND_COOLDOWN_SECONDS) {
        const remaining = Math.ceil(
          OTP_RESEND_COOLDOWN_SECONDS - secondsSinceLastSent,
        );

        return res.status(429).json({
          success: false,

          message: `Please wait ${remaining} seconds before requesting another OTP.`,
        });
      }
    }

    // ------------------------------------------------------
    // GENERATE NEW OTP
    // ------------------------------------------------------

    const otp = generateOtp();

    const otpHash = hashToken(otp);

    user.emailVerificationOtpHash = otpHash;

    user.emailVerificationOtpExpiresAt = new Date(
      Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000,
    );

    user.emailVerificationOtpLastSentAt = new Date();

    // New OTP gets fresh attempts
    user.emailVerificationOtpAttempts = 0;

    user.emailVerificationOtpLockUntil = null;

    await user.save();

    // ------------------------------------------------------
    // SEND EMAIL
    // ------------------------------------------------------

    await sendEmail({
      to: cleanEmail,

      subject: "New verification OTP",

      html: `
        <h2>Email Verification</h2>

        <p>Your new verification OTP is:</p>

        <h1>${otp}</h1>

        <p>
          This OTP expires in
          ${OTP_EXPIRES_MINUTES} minutes.
        </p>
      `,
    });

    return res.status(200).json({
      success: true,

      message: "Verification OTP sent successfully",
    });
  }),
);

// ============================================================
// LOGIN
// POST /api/auth/login
// ============================================================

router.post(
  "/login",
  loginLimiter,
  asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // ------------------------------------------------------
    // PASSWORD VALIDATION
    // ------------------------------------------------------

    if (password === undefined || password === null) {
      return res.status(400).json({
        success: false,
        message: "Password is required",
      });
    }

    if (typeof password !== "string") {
      return res.status(400).json({
        success: false,
        message: "Password must be a string",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select("+password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // ------------------------------------------------------
    // CHECK ACCOUNT LOCK
    // ------------------------------------------------------

    if (user.loginLockUntil && user.loginLockUntil > new Date()) {
      return res.status(423).json({
        success: false,
        message: "Too many failed login attempts. Please try again later.",
      });
    }

    // ------------------------------------------------------
    // RESET EXPIRED LOCK
    // ------------------------------------------------------

    if (user.loginLockUntil && user.loginLockUntil <= new Date()) {
      user.failedLoginAttempts = 0;

      user.loginLockUntil = null;

      await user.save();
    }

    // ------------------------------------------------------
    // COMPARE PASSWORD
    // ------------------------------------------------------

    const passwordMatch = await bcrypt.compare(password, user.password);

    // ------------------------------------------------------
    // WRONG PASSWORD
    // ------------------------------------------------------

    if (!passwordMatch) {
      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.loginLockUntil = new Date(Date.now() + LOGIN_LOCK_TIME);
      }

      await user.save();

      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // ------------------------------------------------------
    // CORRECT PASSWORD
    // RESET LOGIN ATTEMPTS
    // ------------------------------------------------------

    user.failedLoginAttempts = 0;

    user.loginLockUntil = null;

    await user.save();

    // ------------------------------------------------------
    // EMAIL VERIFICATION
    // ------------------------------------------------------

    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email before logging in.",
      });
    }

    // ------------------------------------------------------
    // CREATE SESSION
    // ------------------------------------------------------

    const session = await Session.create({
      userId: user._id,

      // Temporary value
      refreshTokenHash: "temporary",

      deviceName: req.headers["user-agent"] || "Unknown device",

      userAgent: req.headers["user-agent"] || null,

      ipAddress: req.ip || null,

      expiresAt: new Date(Date.now() + env.REFRESH_TOKEN_MAX_AGE_MS),
    });

    // ------------------------------------------------------
    // GENERATE TOKENS
    // ------------------------------------------------------

    const accessToken = generateAccessToken(user);

    const refreshToken = generateRefreshToken(user, session._id);

    // ------------------------------------------------------
    // HASH REFRESH TOKEN
    // ------------------------------------------------------

    session.refreshTokenHash = hashToken(refreshToken);

    await session.save();

    // ------------------------------------------------------
    // SET REFRESH COOKIE
    // ------------------------------------------------------

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // ------------------------------------------------------
    // RESPONSE
    // ------------------------------------------------------

    return res.status(200).json({
      success: true,

      message: "Login successful",

      accessToken,

      user: {
        id: user._id,

        name: user.name,

        email: user.email,

        role: user.role,
      },
    });
  }),
);

// ============================================================
// REFRESH TOKEN
// POST /api/auth/refresh
// ============================================================

router.post(
  "/refresh",
  asyncHandler(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: "Refresh token missing",
      });
    }

    // ------------------------------------------------------
    // VERIFY JWT
    // ------------------------------------------------------

    let decoded;

    try {
      decoded = jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET, {
        algorithms: ["HS256"],
      });
    } catch (error) {
      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Invalid or expired refresh token",
      });
    }

    // ------------------------------------------------------
    // REQUIRE SESSION ID
    // ------------------------------------------------------

    if (!decoded.sessionId) {
      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    // ------------------------------------------------------
    // FIND SESSION
    // ------------------------------------------------------

    const session = await Session.findById(decoded.sessionId).select(
      "+refreshTokenHash",
    );

    if (!session) {
      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Session not found",
      });
    }

    // ------------------------------------------------------
    // CHECK SESSION USER
    // ------------------------------------------------------

    if (session.userId.toString() !== decoded.userId.toString()) {
      session.revokedAt = new Date();

      await session.save();

      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Invalid session",
      });
    }

    // ------------------------------------------------------
    // CHECK REVOKED
    // ------------------------------------------------------

    if (session.revokedAt) {
      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Session has been revoked",
      });
    }

    // ------------------------------------------------------
    // CHECK EXPIRY
    // ------------------------------------------------------

    if (session.expiresAt <= new Date()) {
      session.revokedAt = new Date();

      await session.save();

      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Session has expired",
      });
    }

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findById(decoded.userId);

    if (!user) {
      session.revokedAt = new Date();

      await session.save();

      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    // ------------------------------------------------------
    // TOKEN VERSION CHECK
    // ------------------------------------------------------

    if (
      decoded.tokenVersion === undefined ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      session.revokedAt = new Date();

      await session.save();

      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Session expired. Please login again.",
      });
    }

    // ------------------------------------------------------
    // HASH INCOMING REFRESH TOKEN
    // ------------------------------------------------------

    const incomingHash = hashToken(refreshToken);

    // ------------------------------------------------------
    // REFRESH TOKEN REUSE DETECTION
    // ------------------------------------------------------

    if (incomingHash !== session.refreshTokenHash) {
      // Possible stolen/reused token
      session.revokedAt = new Date();

      await session.save();

      res.clearCookie("refreshToken");

      return res.status(401).json({
        success: false,
        message: "Refresh token reuse detected. Session revoked.",
      });
    }

    // ------------------------------------------------------
    // GENERATE NEW TOKENS
    // ------------------------------------------------------

    const newAccessToken = generateAccessToken(user);

    const newRefreshToken = generateRefreshToken(user, session._id);

    // ------------------------------------------------------
    // ROTATE REFRESH TOKEN
    // ------------------------------------------------------

    session.refreshTokenHash = hashToken(newRefreshToken);

    session.lastUsedAt = new Date();

    await session.save();

    // ------------------------------------------------------
    // SET NEW COOKIE
    // ------------------------------------------------------

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",

      maxAge: env.REFRESH_TOKEN_MAX_AGE_MS,
    });

    return res.status(200).json({
      success: true,

      accessToken: newAccessToken,
    });
  }),
);

// ============================================================
// LOGOUT CURRENT DEVICE
// POST /api/auth/logout
// ============================================================

router.post(
  "/logout",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET, {
          algorithms: ["HS256"],
        });

        if (decoded.sessionId) {
          const session = await Session.findById(decoded.sessionId);

          if (
            session &&
            session.userId.toString() === req.user._id.toString()
          ) {
            session.revokedAt = new Date();

            await session.save();
          }
        }
      } catch (error) {
        // Token may already be invalid.
        // Logout should still clear cookie.
      }
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",
    });

    return res.status(200).json({
      success: true,

      message: "Logged out successfully",
    });
  }),
);

// ============================================================
// LOGOUT ALL DEVICES
// POST /api/auth/logout-all
// ============================================================

router.post(
  "/logout-all",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ------------------------------------------------------
    // INVALIDATE ALL ACCESS TOKENS
    // ------------------------------------------------------

    user.tokenVersion += 1;

    // ------------------------------------------------------
    // REVOKE ALL SESSIONS
    // ------------------------------------------------------

    await Session.updateMany(
      {
        userId: user._id,

        revokedAt: null,
      },
      {
        $set: {
          revokedAt: new Date(),
        },
      },
    );

    // Compatibility with old
    // User-level refresh fields
    user.refreshTokenHash = null;

    user.refreshTokenExpiresAt = null;

    await user.save();

    // ------------------------------------------------------
    // CLEAR COOKIE
    // ------------------------------------------------------

    res.clearCookie("refreshToken", {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",
    });

    return res.status(200).json({
      success: true,

      message: "Logged out from all devices successfully",
    });
  }),
);

// ============================================================
// GET ACTIVE SESSIONS
// GET /api/auth/sessions
// ============================================================

router.get(
  "/sessions",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const sessions = await Session.find({
      userId: req.user._id,

      revokedAt: null,

      expiresAt: {
        $gt: new Date(),
      },
    })
      .sort({
        lastUsedAt: -1,
      })
      .select(
        "deviceName " +
          "userAgent " +
          "ipAddress " +
          "lastUsedAt " +
          "expiresAt " +
          "createdAt",
      );

    return res.status(200).json({
      success: true,

      count: sessions.length,

      sessions,
    });
  }),
);

// ============================================================
// REVOKE ONE SESSION
// DELETE /api/auth/sessions/:sessionId
// ============================================================

router.delete(
  "/sessions/:sessionId",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const { sessionId } = req.params;

    // ------------------------------------------------------
    // VALIDATE OBJECT ID
    // ------------------------------------------------------

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid session ID",
      });
    }

    const session = await Session.findById(sessionId);

    if (!session) {
      return res.status(404).json({
        success: false,
        message: "Session not found",
      });
    }

    // ------------------------------------------------------
    // OWNERSHIP CHECK
    // ------------------------------------------------------

    if (session.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: "You cannot revoke this session",
      });
    }

    session.revokedAt = new Date();

    await session.save();

    return res.status(200).json({
      success: true,

      message: "Session revoked successfully",
    });
  }),
);

// ============================================================
// FORGOT PASSWORD
// POST /api/auth/forgot-password
// ============================================================

router.post(
  "/forgot-password",
  otpLimiter,
  asyncHandler(async (req, res, next) => {
    const { email } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // GENERIC RESPONSE HELPER
    // ------------------------------------------------------

    const genericResponse = () => {
      return res.status(200).json({
        success: true,
        message:
          "If an account exists, password reset instructions have been sent.",
      });
    };

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select(
      "+passwordResetOtpHash " +
        "+passwordResetOtpExpiresAt " +
        "+passwordResetOtpLastSentAt",
    );

    // Don't reveal whether account exists
    if (!user) {
      return genericResponse();
    }

    // ------------------------------------------------------
    // CHECK OTP LOCK
    // ------------------------------------------------------

    if (
      user.passwordResetOtpLockUntil &&
      user.passwordResetOtpLockUntil > new Date()
    ) {
      return genericResponse();
    }

    // ------------------------------------------------------
    // RESET EXPIRED LOCK
    // ------------------------------------------------------

    if (
      user.passwordResetOtpLockUntil &&
      user.passwordResetOtpLockUntil <= new Date()
    ) {
      user.passwordResetOtpAttempts = 0;

      user.passwordResetOtpLockUntil = null;

      await user.save();
    }

    // ------------------------------------------------------
    // 60-SECOND COOLDOWN
    // ------------------------------------------------------

    if (user.passwordResetOtpLastSentAt) {
      const secondsSinceLastSent =
        (Date.now() - user.passwordResetOtpLastSentAt.getTime()) / 1000;

      if (secondsSinceLastSent < OTP_RESEND_COOLDOWN_SECONDS) {
        return genericResponse();
      }
    }

    // ------------------------------------------------------
    // GENERATE OTP
    // ------------------------------------------------------

    const otp = generateOtp();

    const otpHash = hashToken(otp);

    user.passwordResetOtpHash = otpHash;

    user.passwordResetOtpExpiresAt = new Date(
      Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000,
    );

    user.passwordResetOtpLastSentAt = new Date();

    user.passwordResetOtpAttempts = 0;

    user.passwordResetOtpLockUntil = null;

    await user.save();

    // ------------------------------------------------------
    // SEND EMAIL
    // ------------------------------------------------------

    await sendEmail({
      to: cleanEmail,

      subject: "Password Reset OTP",

      html: `
        <h2>Password Reset</h2>

        <p>Your password reset OTP is:</p>

        <h1>${otp}</h1>

        <p>
          This OTP will expire in
          ${OTP_EXPIRES_MINUTES} minutes.
        </p>
      `,
    });

    return genericResponse();
  }),
);

// ============================================================
// VERIFY PASSWORD RESET OTP
// POST /api/auth/verify-password-reset-otp
// ============================================================

router.post(
  "/verify-password-reset-otp",
  otpLimiter,
  asyncHandler(async (req, res, next) => {
    const { email, otp } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // ------------------------------------------------------
    // OTP VALIDATION
    // ------------------------------------------------------

    if (!otp || typeof otp !== "string") {
      return res.status(400).json({
        success: false,
        message: "OTP is required",
      });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "OTP must be a 6-digit number",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select("+passwordResetOtpHash " + "+passwordResetOtpExpiresAt");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // CHECK LOCK
    // ------------------------------------------------------

    if (
      user.passwordResetOtpLockUntil &&
      user.passwordResetOtpLockUntil > new Date()
    ) {
      return res.status(429).json({
        success: false,
        message: "Too many incorrect OTP attempts. Please try again later.",
      });
    }

    // ------------------------------------------------------
    // RESET EXPIRED LOCK
    // ------------------------------------------------------

    if (
      user.passwordResetOtpLockUntil &&
      user.passwordResetOtpLockUntil <= new Date()
    ) {
      user.passwordResetOtpAttempts = 0;

      user.passwordResetOtpLockUntil = null;

      await user.save();
    }

    // ------------------------------------------------------
    // CHECK EXPIRY
    // ------------------------------------------------------

    if (
      !user.passwordResetOtpExpiresAt ||
      user.passwordResetOtpExpiresAt < new Date()
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // HASH INCOMING OTP
    // ------------------------------------------------------

    const incomingOtpHash = hashToken(otp);

    // ------------------------------------------------------
    // WRONG OTP
    // ------------------------------------------------------

    if (incomingOtpHash !== user.passwordResetOtpHash) {
      user.passwordResetOtpAttempts += 1;

      if (user.passwordResetOtpAttempts >= MAX_OTP_ATTEMPTS) {
        user.passwordResetOtpLockUntil = new Date(Date.now() + OTP_LOCK_TIME);
      }

      await user.save();

      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // ------------------------------------------------------
    // CORRECT OTP
    // ------------------------------------------------------

    const resetToken = crypto.randomBytes(32).toString("hex");

    user.passwordResetTokenHash = hashToken(resetToken);

    user.passwordResetTokenExpiresAt = new Date(
      Date.now() + RESET_TOKEN_EXPIRES_MINUTES * 60 * 1000,
    );

    // OTP is single-use
    user.passwordResetOtpHash = null;

    user.passwordResetOtpExpiresAt = null;

    user.passwordResetOtpLastSentAt = null;

    user.passwordResetOtpAttempts = 0;

    user.passwordResetOtpLockUntil = null;

    await user.save();

    return res.status(200).json({
      success: true,

      message: "OTP verified successfully",

      resetToken,
    });
  }),
);

// ============================================================
// RESET PASSWORD
// POST /api/auth/reset-password
// ============================================================

router.post(
  "/reset-password",
  asyncHandler(async (req, res, next) => {
    const { email, resetToken, newPassword } = req.body;

    // ------------------------------------------------------
    // EMAIL VALIDATION
    // ------------------------------------------------------

    const emailValidation = validateEmail(email);

    if (!emailValidation.valid) {
      return res.status(400).json({
        success: false,
        message: emailValidation.message,
      });
    }

    // ------------------------------------------------------
    // RESET TOKEN VALIDATION
    // ------------------------------------------------------

    if (!resetToken || typeof resetToken !== "string") {
      return res.status(400).json({
        success: false,
        message: "Reset token is required",
      });
    }

    // ------------------------------------------------------
    // PASSWORD VALIDATION
    // ------------------------------------------------------

    const passwordValidation = validatePassword(newPassword);

    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findOne({
      email: cleanEmail,
    }).select(
      "+password " +
        "+passwordResetTokenHash " +
        "+passwordResetTokenExpiresAt",
    );

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    // ------------------------------------------------------
    // CHECK RESET TOKEN EXPIRY
    // ------------------------------------------------------

    if (
      !user.passwordResetTokenExpiresAt ||
      user.passwordResetTokenExpiresAt < new Date()
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    // ------------------------------------------------------
    // HASH RESET TOKEN
    // ------------------------------------------------------

    const incomingTokenHash = hashToken(resetToken);

    // ------------------------------------------------------
    // CHECK RESET TOKEN
    // ------------------------------------------------------

    if (incomingTokenHash !== user.passwordResetTokenHash) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    // ------------------------------------------------------
    // CHECK SAME PASSWORD
    // ------------------------------------------------------

    if (user.password && (await bcrypt.compare(newPassword, user.password))) {
      return res.status(400).json({
        success: false,
        message: "New password must be different from old password",
      });
    }

    // ------------------------------------------------------
    // HASH NEW PASSWORD
    // ------------------------------------------------------

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    user.password = hashedPassword;

    // ------------------------------------------------------
    // INVALIDATE ALL ACCESS TOKENS
    // ------------------------------------------------------

    user.tokenVersion += 1;

    // ------------------------------------------------------
    // REVOKE OLD REFRESH TOKEN
    // ------------------------------------------------------

    user.refreshTokenHash = null;

    user.refreshTokenExpiresAt = null;

    // ------------------------------------------------------
    // CLEAR RESET TOKEN
    // ------------------------------------------------------

    user.passwordResetTokenHash = null;

    user.passwordResetTokenExpiresAt = null;

    user.passwordResetOtpHash = null;

    user.passwordResetOtpExpiresAt = null;

    user.passwordResetOtpLastSentAt = null;

    user.passwordResetOtpAttempts = 0;

    user.passwordResetOtpLockUntil = null;

    await user.save();

    // ------------------------------------------------------
    // REVOKE ALL SESSIONS
    // ------------------------------------------------------

    await Session.updateMany(
      {
        userId: user._id,

        revokedAt: null,
      },
      {
        $set: {
          revokedAt: new Date(),
        },
      },
    );

    // ------------------------------------------------------
    // CLEAR COOKIE
    // ------------------------------------------------------

    res.clearCookie("refreshToken", {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",
    });

    return res.status(200).json({
      success: true,

      message: "Password reset successfully. Please login again.",
    });
  }),
);

// ============================================================
// CHANGE PASSWORD
// PUT /api/auth/change-password
// ============================================================

router.put(
  "/change-password",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const { currentPassword, newPassword } = req.body;

    // ------------------------------------------------------
    // CURRENT PASSWORD VALIDATION
    // ------------------------------------------------------

    if (!currentPassword || typeof currentPassword !== "string") {
      return res.status(400).json({
        success: false,
        message: "Current password is required",
      });
    }

    // ------------------------------------------------------
    // NEW PASSWORD VALIDATION
    // ------------------------------------------------------

    const passwordValidation = validatePassword(newPassword);

    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // ------------------------------------------------------
    // FIND USER
    // ------------------------------------------------------

    const user = await User.findById(req.user._id).select("+password");

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // ------------------------------------------------------
    // CHECK CURRENT PASSWORD
    // ------------------------------------------------------

    const passwordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // ------------------------------------------------------
    // PREVENT SAME PASSWORD
    // ------------------------------------------------------

    const samePassword = await bcrypt.compare(newPassword, user.password);

    if (samePassword) {
      return res.status(400).json({
        success: false,
        message: "New password must be different from current password",
      });
    }

    // ------------------------------------------------------
    // HASH NEW PASSWORD
    // ------------------------------------------------------

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    user.password = hashedPassword;

    // ------------------------------------------------------
    // INVALIDATE ALL ACCESS TOKENS
    // ------------------------------------------------------

    user.tokenVersion += 1;

    // ------------------------------------------------------
    // CLEAR OLD USER REFRESH TOKEN
    // ------------------------------------------------------

    user.refreshTokenHash = null;

    user.refreshTokenExpiresAt = null;

    await user.save();

    // ------------------------------------------------------
    // REVOKE ALL SESSIONS
    // ------------------------------------------------------

    await Session.updateMany(
      {
        userId: user._id,

        revokedAt: null,
      },
      {
        $set: {
          revokedAt: new Date(),
        },
      },
    );

    // ------------------------------------------------------
    // CLEAR COOKIE
    // ------------------------------------------------------

    res.clearCookie("refreshToken", {
      httpOnly: true,

      secure: env.NODE_ENV === "production",

      sameSite: "strict",
    });

    return res.status(200).json({
      success: true,

      message: "Password changed successfully. Please login again.",
    });
  }),
);

// ============================================================
// GET CURRENT USER
// GET /api/auth/me
// ============================================================

router.get(
  "/me",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,

      user: {
        id: user._id,

        name: user.name,

        email: user.email,

        role: user.role,

        isEmailVerified: user.isEmailVerified,
      },
    });
  }),
);

router.get(
  "/:id",
  authMiddleware,
  asyncHandler(async (req, res, next) => {
    const { id } = req.params;

    // Validate MongoDB ID
    if (!validateObjectId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID",
      });
    }

    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    return res.status(200).json({
      success: true,

      user,
    });
  }),
);
// ============================================================
// EXPORT ROUTER
// ============================================================

module.exports = router;
