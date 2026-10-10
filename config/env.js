const dotenv = require("dotenv");

dotenv.config();

// ============================================================
// REQUIRED ENVIRONMENT VARIABLES
// ============================================================

const requiredVariables = [
  "MONGODB_URI",
  "JWT_SECRET",
  "REFRESH_TOKEN_SECRET",
  "EMAIL_USER",
  "EMAIL_APP_PASSWORD",
];

for (const variable of requiredVariables) {
  if (!process.env[variable]) {
    throw new Error(`Missing required environment variable: ${variable}`);
  }
}

// ============================================================
// ENVIRONMENT
// ============================================================

const NODE_ENV = process.env.NODE_ENV || "development";

// ============================================================
// TOKEN EXPIRATION
// ============================================================

const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "15m";

const REFRESH_TOKEN_EXPIRES = process.env.REFRESH_TOKEN_EXPIRES || "7d";

// ============================================================
// CONVERT DURATION TO MILLISECONDS
// ============================================================

const parseDurationToMs = (duration) => {
  const match = /^(\d+)\s*(ms|s|m|h|d)$/.exec(duration);

  if (!match) {
    throw new Error(`Invalid duration format: ${duration}`);
  }

  const value = Number(match[1]);
  const unit = match[2];

  const multipliers = {
    ms: 1,
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[unit];
};

const REFRESH_TOKEN_MAX_AGE_MS = parseDurationToMs(REFRESH_TOKEN_EXPIRES);

// ============================================================
// FINAL ENV CONFIGURATION
// ============================================================

const env = {
  PORT: Number(process.env.PORT) || 5000,

  NODE_ENV,

  MONGODB_URI: process.env.MONGODB_URI,

  JWT_SECRET: process.env.JWT_SECRET,

  REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,

  ACCESS_TOKEN_EXPIRES,

  REFRESH_TOKEN_EXPIRES,

  REFRESH_TOKEN_MAX_AGE_MS,

  FRONTEND_URL: process.env.FRONTEND_URL || "http://localhost:3000",

  EMAIL_USER: process.env.EMAIL_USER,

  EMAIL_APP_PASSWORD: process.env.EMAIL_APP_PASSWORD,
};

module.exports = env;
